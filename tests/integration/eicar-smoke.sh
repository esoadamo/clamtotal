#!/bin/bash
# Integration smoke test: boot the ACTUAL built image with a minimal signature set
# (one EICAR hash DB — clamd refuses to start with an empty DB dir, and with
# CLAM_AUTOUPDATE=false nothing is downloaded, so the container starts instantly),
# upload the EICAR test file via the API, and assert it is detected as infected.
# Used by CI between the local image build and the GHCR publish step.
# Usage: eicar-smoke.sh <image-tag>   (CONTAINER_RUNTIME=docker|podman, default docker)
set -euo pipefail

IMAGE="${1:?usage: eicar-smoke.sh <image-tag>}"
RUNTIME="${CONTAINER_RUNTIME:-docker}"
PORT=18000
BASE="http://127.0.0.1:$PORT"
NAME="clamtotal-it"
SIG_DIR="$(cd "$(dirname "$0")" && pwd)/signatures"

cleanup() { "$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[it] starting $IMAGE with minimal sigs (CLAM_AUTOUPDATE=false)..."
"$RUNTIME" run -d --name "$NAME" -p "127.0.0.1:$PORT:8000" \
  -e CLAM_AUTOUPDATE=false \
  -v "$SIG_DIR:/var/lib/clamav:ro" \
  -v "${NAME}-data:/data" \
  "$IMAGE"

echo "[it] waiting for the web UI (entrypoint starts uvicorn only after clamd answers PONG)..."
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ "$ready" = "1" ] || { echo "[it] FATAL: container did not become ready"; "$RUNTIME" logs "$NAME"; exit 1; }
echo "[it] container is up."

EICAR=/tmp/eicar.com
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR"
md5=$(md5sum "$EICAR" | cut -d' ' -f1)
[ "$md5" = "44d88612fea8a8f36de82e1278abb02f" ] || { echo "[it] FATAL: bad EICAR test string (md5=$md5)"; exit 1; }

echo "[it] uploading EICAR via POST /api/v2/files..."
resp=$(curl -fsS -X POST "$BASE/api/v2/files" -F "file=@$EICAR")
sha256=$(printf '%s' "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')
echo "[it] upload accepted, sha256=$sha256 — polling report until done..."

verdict=""; signature=""; status=""
for _ in $(seq 1 30); do
  report=$(curl -fsS "$BASE/api/v2/files/$sha256")
  status=$(printf '%s' "$report" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
  [ "$status" = "done" ] && break
  sleep 2
done
verdict=$(printf '%s' "$report" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])')
signature=$(printf '%s' "$report" | python3 -c 'import json,sys; print(json.load(sys.stdin)["signature"] or "")')
engines=$(printf '%s' "$report" | python3 -c 'import json,sys; print(json.load(sys.stdin)["engines"])')
echo "[it] verdict=$verdict signature=$signature engines=$engines"

if [ "$status" != "done" ] || [ "$verdict" != "infected" ] || ! printf '%s' "$signature" | grep -qi eicar; then
  echo "[it] FATAL: EICAR was not detected (status=$status verdict=$verdict signature=$signature)"
  exit 1
fi
echo "[it] OK: EICAR detected as infected ($signature)."
