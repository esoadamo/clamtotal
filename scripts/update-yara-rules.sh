#!/bin/bash
# Refresh third-party YARA rule sets for the LOCAL YARA engine (yara-python in
# app/scanner.py). The ClamAV database is handled separately (update-signatures.sh).
#
# Sources are read from YARA_RULES_SOURCES (default /etc/yara-rules-sources.conf), one
# per line:  <name>|<url>|<branch>|<subdir-with-.yar-files>
# <url> is a git repo (cloned shallowly) or, when it ends in .zip, a release asset
# (downloaded with curl, extracted with python3 -m zipfile — e.g. YARA Forge packages,
# which are only published as release zips, not in the git repo).
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
  echo "[yara-rules] fetching $name ($url)..."
  src=""
  case "$url" in
    *.zip)
      # release-asset zip (e.g. YARA Forge packages): download + extract
      if curl -fsSL --connect-timeout 15 "$url" -o "$tmp/rules.zip" 2>/dev/null \
        && python3 -m zipfile -e "$tmp/rules.zip" "$tmp/extract" 2>/dev/null; then
        src="$tmp/extract"
      fi
      ;;
    *)
      if git clone --depth 1 --branch "$branch" --quiet "$url" "$tmp/repo" 2>/dev/null \
        || git clone --depth 1 --quiet "$url" "$tmp/repo" 2>/dev/null; then
        # configured branch may not exist (main vs master) - the fallback clone above
        # already retried with the default branch
        src="$tmp/repo/$subdir"
      fi
      ;;
  esac
  if [ -z "$src" ] || [ ! -d "$src" ]; then
    echo "[yara-rules] $name: no rules downloaded (offline or wrong path) - keeping existing rules"
    rm -rf "$tmp"
    continue
  fi
  stage="$tmp/stage"
  mkdir -p "$stage"
  (cd "$src" && find . -type f \( -name '*.yar' -o -name '*.yara' \) \
    -exec cp --parents {} "$stage/" \;)
  # keep the upstream license next to the rules (required by DRL/MIT/BSD attribution)
  if [ -d "$tmp/repo" ]; then
    find "$tmp/repo" -maxdepth 1 -type f -iname 'LICENSE*' -exec cp {} "$stage/" \; 2>/dev/null || true
  fi
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

# prune third_party sets whose source is no longer active in the conf (e.g. disabled
# for memory reasons): their rules were downloaded into the persistent volume earlier
# and would otherwise keep being compiled, eating the memory budget
active_names="$(grep -vE '^\s*(#|$)' "$SOURCES_CONF" | cut -d'|' -f1 | tr '\n' ' ' || true)"
if [ -d "$TARGET" ]; then
  for dir in "$TARGET"/*/; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"
    case " $active_names " in
      *" $name "*) ;;
      *)
        rm -rf "$dir"
        echo "[yara-rules] pruned inactive rule set: $name"
        updated=1
        ;;
    esac
  done
fi

if [ "$updated" = "1" ]; then
  touch "$STAMP" 2>/dev/null || true  # signals YaraScanner to recompile on next scan
  echo "[yara-rules] done."
else
  echo "[yara-rules] nothing updated - keeping existing rules."
fi
