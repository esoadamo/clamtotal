#!/bin/bash
# Fetch the extremeshok/clamav-unofficial-sigs signature set (public, community-maintained)
# and install its signature files into the ClamAV database directory.
# Skipped entirely in airgapped builds/runs (CLAM_AUTOUPDATE=false / AIRGAPPED=true).
set -e

CLAM_DB_DIR="${CLAM_DB_DIR:-/var/lib/clamav}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[unofficial-sigs] cloning extremeshok/clamav-unofficial-sigs..."
git clone --depth 1 https://github.com/extremeshok/clamav-unofficial-sigs "$WORK/sigs"

count=0
for f in "$WORK"/sigs/sigs/*; do
  case "$(basename "$f")" in
    *.db|*.ndb|*.hdb|*.hsb|*.ldb|*.cdb|*.mdb|*.mdb|*.fp|*.ign*|*.yar|*.yara) ;;
    *) continue ;;
  esac
  install -m 0644 "$f" "$CLAM_DB_DIR/" && count=$((count + 1))
done
echo "[unofficial-sigs] installed $count signature files into $CLAM_DB_DIR"

# make clamd reload the signature database
pkill -HUP -x clamd 2>/dev/null || true
