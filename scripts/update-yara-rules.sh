#!/bin/bash
# Refresh third-party YARA rule sets for the LOCAL YARA engine (yara-python in
# app/scanner.py). The ClamAV database is handled separately (update-signatures.sh).
#
# Sources are read from YARA_RULES_SOURCES (default /etc/yara-rules-sources.conf), one
# per line:  <name>|<git-url>|<branch>|<subdir-with-.yar-files>
# Only license-permitted rule sets are listed there (see the header of that file);
# each set keeps its upstream LICENSE file next to the downloaded rules.
#
# Rules land in $YARA_RULES_DIR/third_party/<name>/ and a .rules-stamp file is
# touched so the running app recompiles the rules on the next scan (no restart).
# Runs at container bootstrap and on the CLAM_UPDATE_INTERVAL loop
# (container-entrypoint.sh); skipped entirely when CLAM_AUTOUPDATE=false (airgapped).
# Failures are non-fatal: existing rules are kept (offline tolerance).
set -e

RULES_DIR="${YARA_RULES_DIR:-/rules}"
SOURCES_CONF="${YARA_RULES_SOURCES:-/etc/yara-rules-sources.conf}"
STAMP="$RULES_DIR/.rules-stamp"
TARGET="$RULES_DIR/third_party"

if [ ! -f "$SOURCES_CONF" ]; then
  echo "[yara-rules] no sources config at $SOURCES_CONF - nothing to do"
  exit 0
fi
if [ ! -d "$RULES_DIR" ] && ! mkdir -p "$RULES_DIR" 2>/dev/null; then
  echo "[yara-rules] cannot create $RULES_DIR - keeping existing rules"
  exit 0
fi
if [ ! -w "$RULES_DIR" ]; then
  echo "[yara-rules] $RULES_DIR is not writable (mounted read-only?) - keeping existing rules"
  exit 0
fi

mkdir -p "$TARGET"
updated=0
while IFS='|' read -r name url branch subdir || [ -n "$name" ]; do
  case "$name" in '' | \#*) continue ;; esac
  [ -n "$url" ] || continue
  branch="${branch:-main}"
  subdir="${subdir:-.}"
  tmp="$(mktemp -d)"
  echo "[yara-rules] fetching $name ($url, branch $branch)..."
  if ! git clone --depth 1 --branch "$branch" --quiet "$url" "$tmp/repo" 2>/dev/null; then
    # configured branch may not exist (main vs master) - retry with the default branch
    if ! git clone --depth 1 --quiet "$url" "$tmp/repo" 2>/dev/null; then
      echo "[yara-rules] $name: clone failed (offline?) - keeping existing rules"
      rm -rf "$tmp"
      continue
    fi
  fi
  stage="$tmp/stage"
  mkdir -p "$stage"
  if [ -d "$tmp/repo/$subdir" ]; then
    (cd "$tmp/repo/$subdir" && find . -type f \( -name '*.yar' -o -name '*.yara' \) \
      -exec cp --parents {} "$stage/" \;)
  fi
  # keep the upstream license next to the rules (required by DRL/MIT/BSD attribution)
  find "$tmp/repo" -maxdepth 1 -type f -iname 'LICENSE*' -exec cp {} "$stage/" \; 2>/dev/null || true
  count=$(find "$stage" -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "[yara-rules] $name: no .yar/.yara files under '$subdir' - keeping existing rules"
    rm -rf "$tmp"
    continue
  fi
  rm -rf "$TARGET/$name"
  mv "$stage" "$TARGET/$name"
  echo "[yara-rules] $name: installed $count rule file(s)"
  updated=1
  rm -rf "$tmp"
done < "$SOURCES_CONF"

if [ "$updated" = "1" ]; then
  touch "$STAMP" 2>/dev/null || true  # signals YaraScanner to recompile on next scan
  echo "[yara-rules] done."
else
  echo "[yara-rules] nothing updated - keeping existing rules."
fi
