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

if command -v fangfrisch >/dev/null 2>&1 && [ -f "$FANGFRISCH_CONF" ]; then
  echo "[signatures] refreshing unofficial DBs via fangfrisch..."
  fangfrisch --conf "$FANGFRISCH_CONF" refresh || echo "[signatures] fangfrisch refresh failed (offline?) — keeping existing unofficial DBs"
fi

# extremeshok/clamav-unofficial-sigs (public community signature set)
if [ "${CLAM_AUTOUPDATE:-true}" = "true" ] && command -v git >/dev/null 2>&1; then
  echo "[signatures] refreshing extremeshok unofficial sigs..."
  update-unofficial-sigs.sh || echo "[signatures] extremeshok update failed — keeping existing files"
fi

# make clamd reload the signature database
pkill -HUP -x clamd 2>/dev/null || true
echo "[signatures] done."
