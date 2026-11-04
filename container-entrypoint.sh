#!/bin/bash
set -e

mkdir -p /data/uploads /rules

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

# Periodic background autoupdater (freshclam + unofficial DBs).
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ]; then
  (
    interval="${CLAM_UPDATE_INTERVAL:-21600}"  # 6h
    while true; do
      sleep "$interval"
      update-signatures.sh || echo "[autoupdate] update failed; will retry next cycle"
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

# Apply database migrations (creates the tables in /data/clamtotal.db on first start)
uv run alembic upgrade head

# 2 workers per CPU core; trust proxy headers so it works behind a Cloudflare Tunnel
workers=$(( $(nproc) * 2 ))
exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --workers "$workers" --proxy-headers --forwarded-allow-ips='*'
