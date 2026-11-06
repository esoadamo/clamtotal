#!/bin/bash
set -e

mkdir -p /data/uploads /rules "${DOMAIN_FEED_DIR:-/data/domain-feed}"

# Keep clamd's INSTREAM size cap in sync with the app's STREAM_SCAN_MAX_SIZE, which
# defaults to MAX_UPLOAD_SIZE (512M): every accepted upload then goes via INSTREAM and
# clamd never has to read an app-owned file (avoids "Access denied" when the clamd user
# cannot traverse /data). Set STREAM_SCAN_MAX_SIZE lower to use file-based SCAN instead.
STREAM_SCAN_MAX_SIZE="${STREAM_SCAN_MAX_SIZE:-${MAX_UPLOAD_SIZE:-536870912}}"
sed -i -e "s/^#\\{0,1\\}StreamMaxLength.*/StreamMaxLength ${STREAM_SCAN_MAX_SIZE}/" /etc/clamav/clamd.conf
{ grep -q '^StreamMaxLength' /etc/clamav/clamd.conf || echo "StreamMaxLength ${STREAM_SCAN_MAX_SIZE}" >> /etc/clamav/clamd.conf; }

# App version stamped at image BUILD time (YYMMDD.hhmmss UTC), shown in the footer
export APP_VERSION="${APP_VERSION:-$(cat /app/.build-version 2>/dev/null || echo dev)}"

# Self-heal: older images left fangfrisch's sqlite metadata DB inside clamd's DB dir,
# which makes clamd abort with "Malformed database" — remove it if present.
rm -f /var/lib/clamav/fangfrisch.db

# Signature bootstrap (default mode): download official + unofficial signatures when
# /var/lib/clamav has none — not at image build time. Must run BEFORE clamd starts:
# clamd refuses to start when /var/lib/clamav has no supported database files, and the
# old marker-file check skipped the download forever after one failed attempt.
# Gated on actual DB files, so it retries on every start until signatures exist.
# Skipped entirely when CLAM_AUTOUPDATE=false (e.g. AIRGAPPED=true images that already
# have signatures baked in).
sig_db_files() {
  find /var/lib/clamav -maxdepth 1 -type f \( -name '*.cvd' -o -name '*.cld' -o -name '*.ndb' \
    -o -name '*.hdb' -o -name '*.ldb' -o -name '*.yar' -o -name '*.db' -o -name '*.mdb' \
    -o -name '*.cdb' \) -print -quit | grep -q .
}
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ] && ! sig_db_files; then
  echo "[bootstrap] no signature databases in /var/lib/clamav — downloading (official + unofficial)..."
  update-signatures.sh || true  # individual sources may fail offline; checked below
  if ! sig_db_files; then
    echo "[bootstrap] FATAL: signature download produced no database files in /var/lib/clamav; refusing to start (clamd would fail with 'No supported database files found'). Check network/DNS. Container will retry on restart." >&2
    exit 1
  fi
fi

# Third-party YARA rule sets for the local YARA engine (license-permitted sources
# from /etc/yara-rules-sources.conf -> /rules/third_party). Non-fatal: the bundled
# rules in /rules always work. Skipped when CLAM_AUTOUPDATE=false (airgapped).
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ]; then
  # ALWAYS prune at start: the volume persists rule sets from earlier configs, and a
  # set disabled in the sources conf must stop being compiled or it OOMs the daemon
  update-yara-rules.sh --prune-only || true
  if [ ! -d /rules/third_party ]; then
    echo "[bootstrap] no third-party YARA rules in /rules/third_party - downloading..."
    update-yara-rules.sh || echo "[bootstrap] yara rule download failed (offline?) - bundled rules still active"
  fi
fi

# Domain feed for URL/domain scanning (hagezi, StevenBlack, URLhaus with key, ...).
# Non-fatal: without it file scanning still works and URL checks return 503.
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ]; then
  feed_dir="${DOMAIN_FEED_DIR:-/data/domain-feed}"
  if ! ls "$feed_dir"/*.txt >/dev/null 2>&1; then
    echo "[bootstrap] no domain feed in $feed_dir - downloading..."
    update-domain-feed.sh || echo "[bootstrap] domain feed download failed (offline?) - URL checks will 503 until a feed exists"
  fi
fi

# Periodic background autoupdater (freshclam + unofficial DBs + third-party YARA rules
# + URL blocklists).
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ]; then
  (
    interval="${CLAM_UPDATE_INTERVAL:-21600}"  # 6h
    while true; do
      sleep "$interval"
      update-signatures.sh || echo "[autoupdate] update failed; will retry next cycle"
      update-yara-rules.sh || echo "[autoupdate] yara rules update failed; will retry next cycle"
      update-domain-feed.sh || echo "[autoupdate] domain feed update failed; will retry next cycle"
    done
  ) &
fi

clamd &

# Wait until clamd answers an INSTREAM PING with PONG on TCP 3310 (a bare TCP
# connect is not enough — clamd must have finished loading its databases).
# The web UI (uvicorn below) starts ONLY after this succeeds; on timeout the
# script exits non-zero (set -e) and the container fails to start.
python - <<'EOF'
import socket
import sys
import time

for _ in range(60):
    try:
        with socket.create_connection(("127.0.0.1", 3310), timeout=2) as s:
            s.sendall(b"zPING\0")
            resp = b""
            while b"\n" not in resp:
                part = s.recv(64)
                if not part:
                    break
                resp += part
            if b"PONG" in resp:
                sys.exit(0)
    except OSError:
        pass
    time.sleep(1)
sys.exit("clamd did not answer PING on 127.0.0.1:3310")
EOF

# YARA scan daemon: compiles the rule set ONCE in a single process and serves match
# requests on $YARA_SOCKET; uvicorn workers query it instead of each compiling the
# rules into their own RAM (which OOM-killed workers under --workers N). Started
# before uvicorn; the web UI starts only after the daemon answers PING.
if [ -n "${YARA_RULES_DIR:-}" ]; then
  /app/.venv/bin/python -m app.yara_daemon \
    --rules "$YARA_RULES_DIR" --socket "${YARA_SOCKET:-/tmp/yara.sock}" &
  # Non-fatal: if the daemon dies (e.g. OOM-killed while compiling a huge rule set
  # inside a small memory limit), the service still runs with ClamAV only and
  # /healthz shows the yara engine as not ready.
  if ! python - <<'EOF'
import os, socket, sys, time

sock_path = os.environ.get("YARA_SOCKET", "/tmp/yara.sock")
for _ in range(60):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall(b"zPING\0")
            if b"PONG" in s.recv(64):
                sys.exit(0)
    except OSError:
        pass
    time.sleep(1)
sys.exit(f"yara daemon did not answer PING on {sock_path}")
EOF
  then
    echo "[bootstrap] WARNING: yara daemon did not answer PING on ${YARA_SOCKET:-/tmp/yara.sock} — continuing WITHOUT the YARA engine (/healthz will show it not ready). It was likely OOM-killed while compiling the rule set: raise the container memory limit (compose mem_limit, e.g. 8g) or trim /etc/yara-rules-sources.conf." >&2
  fi
fi

# Domain feed daemon: imports the downloaded feed lists into their OWN database
# ($DOMAIN_FEED_DIR/feed.db, separate from the app DB) ONCE in a single process and
# serves lookups on $DOMAIN_FEED_SOCKET; uvicorn workers query it over the socket
# instead of each importing the lists. Started before uvicorn; non-fatal like the
# yara daemon (without it URL checks return 503, file scanning still works).
if [ -n "${DOMAIN_FEED_DIR:-}" ]; then
  feed_socket="${DOMAIN_FEED_SOCKET:-/tmp/domain-feed.sock}"
  /app/.venv/bin/python -m app.feed_daemon \
    --feed-dir "$DOMAIN_FEED_DIR" --db "$DOMAIN_FEED_DIR/feed.db" --socket "$feed_socket" &
  if ! python - <<EOF
import os, socket, sys, time

sock_path = os.environ.get("DOMAIN_FEED_SOCKET", "/tmp/domain-feed.sock")
for _ in range(60):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall(b"zPING\0")
            if b"PONG" in s.recv(64):
                sys.exit(0)
    except OSError:
        pass
    time.sleep(1)
sys.exit(f"domain feed daemon did not answer PING on {sock_path}")
EOF
  then
    echo "[bootstrap] WARNING: domain feed daemon did not answer PING on $feed_socket - continuing WITHOUT the domain feed (URL checks will 503; /healthz shows the feed engine as not ready)." >&2
  fi
fi

# Apply database migrations (creates the tables in /data/clamtotal.db on first start).
# Use the venv binaries directly — a uv run wrapper would try to SYNC (network) at
# runtime; all packages are already installed in the image at build time.
/app/.venv/bin/alembic upgrade head

# 2 workers by default (override with UVICORN_WORKERS): every worker is a separate
# process that compiles the full YARA rule set into its own RAM on first scan, and
# clamd holds the whole signature DB in RAM — with many workers inside a small
# container memory limit, the kernel OOM-killer SIGKILLs workers on the first
# /healthz or upload ("Child process died" with NO faulthandler traceback).
# Trust proxy headers so it works behind a Cloudflare Tunnel.
# LOG_LEVEL=debug shows worker lifecycle + restart reasons in the container logs.
workers="${UVICORN_WORKERS:-2}"
echo "[entrypoint] starting uvicorn: workers=$workers log_level=${LOG_LEVEL:-info}"
# The parent SIGKILLs any worker that does not answer its healthcheck ping within
# --timeout-worker-healthcheck seconds (default 5) — long scans/rules compiles must
# not get a worker killed mid-work, so raise it (override: UVICORN_WORKER_HEALTHCHECK_TIMEOUT)
hc_timeout="${UVICORN_WORKER_HEALTHCHECK_TIMEOUT:-120}"
# memory visibility: cgroup v2 then v1 limit/current, plus host MemTotal — a worker
# dying with no traceback right after startup is the OOM killer; confirm against these
echo "[entrypoint] memory: cgroup_limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo '?') cgroup_current=$(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo '?') host_MemTotal=$(awk '/^MemTotal/{print $2" kB"}' /proc/meminfo)"
exec /app/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --workers "$workers" --proxy-headers --forwarded-allow-ips='*' \
  --log-level "${LOG_LEVEL:-info}" --timeout-worker-healthcheck "$hc_timeout"
