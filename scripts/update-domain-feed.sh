#!/bin/bash
# Refresh the domain feed used for URL/domain scanning (app/domain_feed.py).
#
# Sources are read from DOMAIN_FEED_SOURCES (default /etc/domain-feed-sources.conf),
# one per line:  <name>|<category>|<url>
# Each list is downloaded to $DOMAIN_FEED_DIR/<name>.txt with a
# '# clamtotal-category: <category>' header line (the importer reads it), and
# .feed-stamp is touched so the feed daemon re-imports the lists on the next lookup
# (hot reload, no restart). '<URLHAUS_AUTH_KEY>' inside a URL is replaced with
# $URLHAUS_AUTH_KEY; that source is skipped while the variable is unset.
#
# Runs at container bootstrap and on the CLAM_UPDATE_INTERVAL loop
# (container-entrypoint.sh); skipped entirely when CLAM_AUTOUPDATE=false (airgapped).
# Failures are non-fatal: existing lists are kept (offline tolerance).
set -e

FEED_DIR="${DOMAIN_FEED_DIR:-/data/domain-feed}"
SOURCES_CONF="${DOMAIN_FEED_SOURCES:-/etc/domain-feed-sources.conf}"
STAMP="$FEED_DIR/.feed-stamp"

if [ ! -f "$SOURCES_CONF" ]; then
  echo "[domain-feed] no sources config at $SOURCES_CONF - nothing to do"
  exit 0
fi
if ! mkdir -p "$FEED_DIR" 2>/dev/null || [ ! -w "$FEED_DIR" ]; then
  echo "[domain-feed] $FEED_DIR missing or not writable - keeping existing lists"
  exit 0
fi

updated=0
while IFS='|' read -r name category url || [ -n "$name" ]; do
  case "$name" in '' | \#*) continue ;; esac
  [ -n "$url" ] || continue
  case "$url" in
    *'<URLHAUS_AUTH_KEY>'*)
      if [ -z "${URLHAUS_AUTH_KEY:-}" ]; then
        echo "[domain-feed] $name: URLHAUS_AUTH_KEY not set - skipping (set the env var or bake the key into a mounted sources conf)"
        continue
      fi
      url="${url//<URLHAUS_AUTH_KEY>/$URLHAUS_AUTH_KEY}"
      ;;
  esac
  tmp="$(mktemp)"
  echo "[domain-feed] fetching $name (category: ${category:-$name})..."
  if curl -fsSL --connect-timeout 15 --max-time 600 "$url" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    { echo "# clamtotal-category: ${category:-$name}"; cat "$tmp"; } > "$tmp.hdr"
    mv "$tmp.hdr" "$FEED_DIR/$name.txt"
    rm -f "$tmp"
    echo "[domain-feed] $name: installed ($(wc -l < "$FEED_DIR/$name.txt") lines)"
    updated=1
  else
    rm -f "$tmp"
    echo "[domain-feed] $name: download failed (offline or HTTP error) - keeping existing list"
  fi
done < "$SOURCES_CONF"

# prune lists whose source is no longer active in the conf (disabled entries must stop
# being imported, the same as third-party YARA rule sets)
active_names="$(grep -vE '^\s*(#|$)' "$SOURCES_CONF" | cut -d'|' -f1 | tr '\n' ' ' || true)"
for f in "$FEED_DIR"/*.txt; do
  [ -f "$f" ] || continue
  name="$(basename "$f" .txt)"
  case " $active_names " in
    *" $name "*) ;;
    *)
      rm -f "$f"
      echo "[domain-feed] pruned inactive list: $name"
      updated=1
      ;;
  esac
done

if [ "$updated" = "1" ]; then
  touch "$STAMP" 2>/dev/null || true  # signals the feed daemon to re-import on next lookup
  echo "[domain-feed] done."
else
  echo "[domain-feed] nothing updated - keeping existing lists."
fi
