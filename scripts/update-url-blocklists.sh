#!/bin/bash
# Refresh the URL/domain blocklists used for URL scanning (app/blocklists.py).
#
# Sources are read from URL_BLOCKLIST_SOURCES (default /etc/url-blocklist-sources.conf),
# one per line:  <name>|<category>|<url>
# Each list is downloaded to $URL_BLOCKLIST_DIR/<name>.txt with a
# '# clamtotal-category: <category>' header line (the app's importer reads it), and
# .blocklists-stamp is touched so the running app re-imports the lists into its DB on
# the next request (hot reload, no restart). '<URLHAUS_AUTH_KEY>' inside a URL is
# replaced with $URLHAUS_AUTH_KEY; that source is skipped while the variable is unset.
#
# Runs at container bootstrap and on the CLAM_UPDATE_INTERVAL loop
# (container-entrypoint.sh); skipped entirely when CLAM_AUTOUPDATE=false (airgapped).
# Failures are non-fatal: existing lists are kept (offline tolerance).
set -e

BLOCKLIST_DIR="${URL_BLOCKLIST_DIR:-/data/blocklists}"
SOURCES_CONF="${URL_BLOCKLIST_SOURCES:-/etc/url-blocklist-sources.conf}"
STAMP="$BLOCKLIST_DIR/.blocklists-stamp"

if [ ! -f "$SOURCES_CONF" ]; then
  echo "[url-blocklists] no sources config at $SOURCES_CONF - nothing to do"
  exit 0
fi
if ! mkdir -p "$BLOCKLIST_DIR" 2>/dev/null || [ ! -w "$BLOCKLIST_DIR" ]; then
  echo "[url-blocklists] $BLOCKLIST_DIR missing or not writable - keeping existing lists"
  exit 0
fi

updated=0
while IFS='|' read -r name category url || [ -n "$name" ]; do
  case "$name" in '' | \#*) continue ;; esac
  [ -n "$url" ] || continue
  case "$url" in
    *'<URLHAUS_AUTH_KEY>'*)
      if [ -z "${URLHAUS_AUTH_KEY:-}" ]; then
        echo "[url-blocklists] $name: URLHAUS_AUTH_KEY not set - skipping (set the env var or bake the key into a mounted sources conf)"
        continue
      fi
      url="${url//<URLHAUS_AUTH_KEY>/$URLHAUS_AUTH_KEY}"
      ;;
  esac
  tmp="$(mktemp)"
  echo "[url-blocklists] fetching $name (category: ${category:-$name})..."
  if curl -fsSL --connect-timeout 15 --max-time 600 "$url" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    { echo "# clamtotal-category: ${category:-$name}"; cat "$tmp"; } > "$tmp.hdr"
    mv "$tmp.hdr" "$BLOCKLIST_DIR/$name.txt"
    rm -f "$tmp"
    echo "[url-blocklists] $name: installed ($(wc -l < "$BLOCKLIST_DIR/$name.txt") lines)"
    updated=1
  else
    rm -f "$tmp"
    echo "[url-blocklists] $name: download failed (offline or HTTP error) - keeping existing list"
  fi
done < "$SOURCES_CONF"

# prune lists whose source is no longer active in the conf (disabled entries must stop
# being imported, the same as third-party YARA rule sets)
active_names="$(grep -vE '^\s*(#|$)' "$SOURCES_CONF" | cut -d'|' -f1 | tr '\n' ' ' || true)"
for f in "$BLOCKLIST_DIR"/*.txt; do
  [ -f "$f" ] || continue
  name="$(basename "$f" .txt)"
  case " $active_names " in
    *" $name "*) ;;
    *)
      rm -f "$f"
      echo "[url-blocklists] pruned inactive list: $name"
      updated=1
      ;;
  esac
done

if [ "$updated" = "1" ]; then
  touch "$STAMP" 2>/dev/null || true  # signals the app to re-import on next request
  echo "[url-blocklists] done."
else
  echo "[url-blocklists] nothing updated - keeping existing lists."
fi
