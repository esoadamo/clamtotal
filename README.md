# clamtotal

A [VirusTotal](https://www.virustotal.com)-style web app that scans uploaded
files with **ClamAV**. Fully airgapped: no external API calls, CDNs, or
telemetry at runtime.

Features:

- VirusTotal-like UI: home page with search + upload, report pages with
  detection widget, hash details, and extracted URLs
- Scans via **clamd** (INSTREAM protocol) in the Podman container, or the
  **clamscan** CLI in local development (`CLAM_MODE=auto|daemon|cli`)
- SQLite storage via SQLAlchemy + Alembic; scan results are cached by SHA-256
  (re-uploading the same file returns the cached report instantly)
- Search by MD5/SHA-1/SHA-256 or file name, sample download, forced rescan
- Minimal VT-compatible JSON API: `POST /api/v2/files`, `GET /api/v2/files/{hash}`

## Local development

Requires Python >= 3.12, [uv](https://docs.astral.sh/uv/), and ClamAV
(`clamscan`, e.g. `apt install clamav`).

```sh
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 — try uploading the
[EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to see a detection.

## Podman (container mode with clamd)

```sh
podman build -t clamtotal .
podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data clamtotal
# or: podman compose up
```

ClamAV signatures are refreshed at image build time (`freshclam`). For a fully
airgapped build, remove that step and bake your own signatures into
`/var/lib/clamav` (e.g. via a mounted volume or a custom base image).

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

## Development

```sh
uv run pytest                 # tests
uv run ruff format .          # format
uv run ruff check .           # lint
uv run ty check               # type check
uv run alembic revision --autogenerate -m "description"   # new migration
```

See [AGENT.md](AGENT.md) for project conventions.
