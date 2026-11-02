#!/bin/bash
set -e

mkdir -p /data/uploads

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

exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
