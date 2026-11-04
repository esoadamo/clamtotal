# clamtotal

> **Disclaimer:** this project was vibe coded with Mistral 4 to test its capabilities. The code was checked by a human at some point and found to contain no obvious vulnerabilities, but due to the nature of vibe coding it is advised to take a look for yourself before relying on it.

A [VirusTotal](https://www.virustotal.com)-style web app that scans uploaded
files with **ClamAV**. Fully airgapped by default: no external API calls, CDNs,
or telemetry at runtime (an optional Plausible analytics script can be enabled
via `PLAUSIBLE_SCRIPT_URL`, off by default).

Features (all fully offline, no login, no community features):

- VirusTotal-like UI: home page with search + upload, report pages with a
  detection widget and tabs — **Detection** (multi-engine verdict table),
  **Details** (hashes, type, entropy), **Behavior** (PE/ELF/PDF/Office analysis,
  suspicious strings, archive contents), **Network** (URLs, domains, IPs,
  emails, registry keys, BTC addresses, punycode/IDN flags), **Embedded**
  (recursively scanned archive members), **Relations** (other local scans connected
  by shared indicators, by archive membership in either direction — so a file uploaded
  separately or packed inside another archive is linked to its containers — and by
  alternative names tracked per hash, shown in Details as "Alternative names")
- Scans via **clamd** (INSTREAM protocol) in the Podman container, or the
  **clamscan** CLI in local development (`CLAM_MODE=auto|daemon|cli`), plus a
  second engine: **local YARA rules** (`yara-python`, `YARA_RULES_DIR`)
- ClamAV signature **autoupdater** in the container: `freshclam` (official) +
  unofficial DBs via fangfrisch (SaneSecurity, which includes YARA rules that
  clamd loads natively) — every 6h by default; disable with
  `CLAM_AUTOUPDATE=false` for airgapped operation and bake signatures in at
  build time (`--build-arg AIRGAPPED=true`)
- SQLite storage via SQLAlchemy + Alembic; scan results are cached by SHA-256
  (re-uploading the same file returns the cached report instantly)
- Hashes: MD5, SHA-1, SHA-256, SHA-512, CRC32, plus PE imphash
- Search by MD5/SHA-1/SHA-256 or file name, sample download, forced rescan
- Indicators are **defanged** in the UI (`hxxp://`, `[.]`) so they are never clickable/loaded; IPs preceded by `version`/`v` are not misdetected; domains require a real IANA TLD and a second-level label of >= 5 chars
- UI is served at both `/` and `/ui/` (home, file reports, search). API: `POST /file/upload`, `/api/v2/...`
- Minimal VT-compatible JSON API: `POST /api/v2/files` (returns `202` + `sha256` and
  scans asynchronously, or `200` with `cached: true` if the hash was already
  analyzed), `GET /api/v2/files/{hash}` (includes `status`: `pending`/`done`)
- VT-style UX flow: the browser hashes the file (SHA-256) and checks
  `GET /api/v2/files/{hash}` first — already-analyzed files go straight to the
  report; new files ask for confirmation, then upload with a progress bar and
  land on `/file/{hash}`, which shows a rotating spinner until the scan finishes

## Local development

Requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), and ClamAV
(`clamscan`, e.g. `apt install clamav`).

```sh
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/ui/ — try uploading the
[EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to see a detection.

## Container image

On every push to `main` where all tests pass, CI builds and publishes the image to GHCR:
`ghcr.io/<owner>/clamtotal:latest` (plus a per-commit SHA tag). Pull with:
`podman pull ghcr.io/<owner>/clamtotal:latest`.

## Podman (container mode with clamd)

```sh
podman build -t clamtotal .
# 2 workers per CPU core, trusts proxy headers (works behind a Cloudflare Tunnel)
podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data -v clamav-db:/var/lib/clamav clamtotal
# or: podman compose up
```

`/var/lib/clamav` (the downloaded ClamAV signature databases) is a named volume in
`compose.yaml`, so container restarts keep the signatures and clamd always starts
with a valid database.

By default, ClamAV signatures are **downloaded on first container launch** (not at build
time) and refreshed every 6 hours at runtime (`update-signatures.sh`: `freshclam` + fangfrisch/SaneSecurity, which
ships YARA rules clamd loads natively). For a fully airgapped deployment:

```sh
podman build --build-arg AIRGAPPED=true -t clamtotal .  # signatures baked in at BUILD time
podman run -e CLAM_AUTOUPDATE=false -v ./my-signatures:/var/lib/clamav:ro \
  -v ./my-public-rules:/rules:ro -p 127.0.0.1:8000:8000 clamtotal
```

Public YARA rules can be mounted at `/rules` (`YARA_RULES_DIR=/rules`); a small
original ruleset is bundled in `app/rules/public.yar`. To customize the unofficial
signature sources (fangfrisch), mount your own config over the baked-in one:
`-v ./fangfrisch.conf:/etc/fangfrisch.conf:ro` (or set `FANGFRISCH_CONF` to another
path) — see `container/fangfrisch.conf` for the available sections.

## Configuration (environment variables)

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clamtotal.db` | SQLAlchemy URL |
| `UPLOAD_DIR` | `./uploads` | where uploaded samples are stored (by SHA-256) |
| `MAX_UPLOAD_SIZE` | `536870912` | max upload size in bytes |
| `CLAM_MODE` | `auto` | `auto`, `daemon` (aliases `clamd`/`tcp`), or `cli` (clamscan); any other value fails startup |
| `CLAMD_HOST` / `CLAMD_PORT` | `127.0.0.1` / `3310` | clamd TCP endpoint |
| `CLAMD_SOCKET` | unset | clamd Unix socket (takes precedence over TCP) |
| `CLAMSCAN_PATH` | `clamscan` | clamscan binary for CLI mode |
| `YARA_RULES_DIR` | unset | directory with local public YARA rules (`.yar`/`.yara`) |
| `MAX_EMBEDDED_FILES` | `10` | max archive members scanned recursively per file |
| `MAX_SCAN_DEPTH` | `2` | recursion depth for embedded-file scanning |
| `SHOW_RECENT_SCANS` | `true` | show the "recently analyzed files" list on the home page (`false` hides it) |
| `UPLOADS_TTL` | `-1` | how long uploaded samples are stored locally, in minutes: `-1` = forever, `0` = delete right after upload+scan, `N` = keep N minutes (pruned every minute) |
| `SCAN_POLL_INTERVAL_MS` | `3000` | how often the pending report page polls for scan progress |
| `RATE_LIMIT_UPLOAD` | `0` | optional per-IP rate limit on uploads (`POST /file/upload`, `POST /api/v2/files`): max requests per window, `0` = disabled |
| `RATE_LIMIT_BROWSE` | `0` | optional per-IP rate limit on browsing result pages (`/ui/`, `/ui/search`, `/ui/file/{hash}`): max requests per window, `0` = disabled |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | rate-limit window length in seconds (429 returned when exceeded) |
| `PLAUSIBLE_SCRIPT_URL` | unset | optional Plausible analytics script URL loaded (deferred) on every page; unset = fully airgapped |

## Development

```sh
uv run bandit -r app/ -ll -q   # SAST scan of the source code
uv run pytest                 # backend tests, enforced at 100% coverage of app/ (--cov-fail-under=100)
node --test tests/js/app.test.mjs   # frontend JS tests
uv run ruff format .          # format
uv run ruff check .           # lint
uv run ty check               # type check
uv run alembic revision --autogenerate -m "description"   # new migration
```

See [AGENT.md](AGENT.md) for project conventions.
