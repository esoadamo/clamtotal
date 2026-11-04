#!/bin/bash
set -e

mkdir -p /data/uploads /rules

# Self-heal: older images left fangfrisch's sqlite metadata DB inside clamd's DB dir,
# which makes clamd abort with "Malformed database" — remove it if present.
rm -f /var/lib/clamav/fangfrisch.db

clamd &

# Wait until clamd accepts INSTREAM connections on TCP 3310.
python - <<'EOF'
import socket
import sys
import time

for _ in range(60):
    try:
        socket.create_connection(("127.0.0.1", 3310), timeout=1).close()
        sys.exit(0)
    except OSError:
        time.sleep(1)
sys.exit("clamd did not start listening on 127.0.0.1:3310")
EOF

# First-launch signature bootstrap (default mode): download official + unofficial
# signatures once, on the first container start — not at image build time.
# Runs AFTER clamd is up so freshclam's NotifyClamd works and the update script's
# `pkill -HUP clamd` reload picks the new databases up.
# Skipped entirely when CLAM_AUTOUPDATE=false (e.g. AIRGAPPED=true images that
# already have signatures baked in).
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ] && [ ! -f /data/.signatures-initialized ]; then
  echo "[bootstrap] downloading ClamAV signatures on first launch..."
  update-signatures.sh || echo "[bootstrap] signature download failed; will retry on next start"
  touch /data/.signatures-initialized
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

# Apply database migrations (creates the tables in /data/clamtotal.db on first start)
uv run alembic upgrade head

# 2 workers per CPU core; trust proxy headers so it works behind a Cloudflare Tunnel
workers=$(( $(nproc) * 2 ))
exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --workers "$workers" --proxy-headers --forwarded-allow-ips='*'
