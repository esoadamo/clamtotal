# clamtotal

A [VirusTotal](https://www.virustotal.com)-style web app that scans uploaded
files with **ClamAV**. Fully airgapped: no external API calls, CDNs, or
telemetry at runtime.

Features (all fully offline, no login, no community features):

- VirusTotal-like UI: home page with search + upload, report pages with a
  detection widget and tabs — **Detection** (multi-engine verdict table),
  **Details** (hashes, type, entropy), **Behavior** (PE/ELF/PDF/Office analysis,
  suspicious strings, archive contents), **Network** (URLs, domains, IPs,
  emails, registry keys, BTC addresses, punycode/IDN flags), **Embedded**
  (recursively scanned archive members), **Relations** (other local files
  sharing the same indicators)
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
- UI is served under `/ui/` (home, file reports, search); `/` redirects there. API: `POST /file/upload`, `/api/v2/...`
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

## Podman (container mode with clamd)

```sh
podman build -t clamtotal .
# 2 workers per CPU core, trusts proxy headers (works behind a Cloudflare Tunnel)
podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data clamtotal
# or: podman compose up
```

ClamAV signatures are refreshed at image build time and every 6 hours at
runtime (`update-signatures.sh`: `freshclam` + fangfrisch/SaneSecurity, which
ships YARA rules clamd loads natively). For a fully airgapped deployment:

```sh
podman build --build-arg AIRGAPPED=true -t clamtotal .
podman run -e CLAM_AUTOUPDATE=false -v ./my-signatures:/var/lib/clamav:ro \
  -v ./my-public-rules:/rules:ro -p 127.0.0.1:8000:8000 clamtotal
```

Public YARA rules can be mounted at `/rules` (`YARA_RULES_DIR=/rules`); a small
original ruleset is bundled in `app/rules/public.yar`.

## Configuration (environment variables)

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clamtotal.db` | SQLAlchemy URL |
| `UPLOAD_DIR` | `./uploads` | where uploaded samples are stored (by SHA-256) |
| `MAX_UPLOAD_SIZE` | `536870912` | max upload size in bytes |
| `CLAM_MODE` | `auto` | `auto`, `daemon` (clamd), or `cli` (clamscan) |
| `CLAMD_HOST` / `CLAMD_PORT` | `127.0.0.1` / `3310` | clamd TCP endpoint |
| `CLAMD_SOCKET` | unset | clamd Unix socket (takes precedence over TCP) |
| `CLAMSCAN_PATH` | `clamscan` | clamscan binary for CLI mode |
| `YARA_RULES_DIR` | unset | directory with local public YARA rules (`.yar`/`.yara`) |
| `MAX_EMBEDDED_FILES` | `10` | max archive members scanned recursively per file |
| `MAX_SCAN_DEPTH` | `2` | recursion depth for embedded-file scanning |
| `SHOW_RECENT_SCANS` | `true` | show the "recently analyzed files" list on the home page (`false` hides it) |
| `UPLOADS_TTL` | `-1` | how long uploaded samples are stored locally, in minutes: `-1` = forever, `0` = delete right after upload+scan, `N` = keep N minutes (pruned every minute) |
| `SCAN_POLL_INTERVAL_MS` | `3000` | how often the pending report page polls for scan progress |

## Development

```sh
uv run pytest                 # tests, enforced at 100% coverage of app/ (--cov-fail-under=100)
uv run ruff format .          # format
uv run ruff check .           # lint
uv run ty check               # type check
uv run alembic revision --autogenerate -m "description"   # new migration
```

See [AGENT.md](AGENT.md) for project conventions.
