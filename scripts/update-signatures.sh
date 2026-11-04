#!/bin/bash
# Refresh ClamAV signatures: official (freshclam) + unofficial DBs (fangfrisch).
# Unofficial DBs (e.g. SaneSecurity) include YARA-format rules that clamd/clamscan load natively.
# For fully airgapped operation set CLAM_AUTOUPDATE=false and bake signatures into the image
# or mount them at /var/lib/clamav.
set -e

CLAM_DB_DIR="${CLAM_DB_DIR:-/var/lib/clamav}"
FANGFRISCH_CONF="${FANGFRISCH_CONF:-/etc/fangfrisch.conf}"

echo "[signatures] running freshclam (official DBs)..."
freshclam --quiet || echo "[signatures] freshclam failed (offline?) — keeping existing official DBs"

# fangfrisch is installed in the app venv inside the container — resolve it there if needed
FANGFRISCH_BIN="$(command -v fangfrisch || true)"
if [ -z "$FANGFRISCH_BIN" ] && [ -x /app/.venv/bin/fangfrisch ]; then
  FANGFRISCH_BIN=/app/.venv/bin/fangfrisch
fi
if [ -n "$FANGFRISCH_BIN" ] && [ -f "$FANGFRISCH_CONF" ]; then
  echo "[signatures] refreshing unofficial DBs via fangfrisch..."
  if ! "$FANGFRISCH_BIN" --conf "$FANGFRISCH_CONF" refresh >/tmp/fangfrisch.log 2>&1; then
    echo "[signatures] fangfrisch refresh failed (offline?) — keeping existing unofficial DBs. Last error:"
    tail -n 1 /tmp/fangfrisch.log
  fi
fi

# extremeshok/clamav-unofficial-sigs (public community signature set)
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ] && command -v git >/dev/null 2>&1; then
  echo "[signatures] refreshing extremeshok unofficial sigs..."
  update-unofficial-sigs.sh || echo "[signatures] extremeshok update failed — keeping existing files"
fi

# make clamd reload the signature database
pkill -HUP -x clamd 2>/dev/null || true
echo "[signatures] done."
