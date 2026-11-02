# AGENT.md — ClamTotal

ClamTotal is a VirusTotal lookalike web app: users upload a file, it is scanned
with ClamAV, and a VirusTotal-style report page is shown (detections, hashes,
file details, extracted URLs). It must run in **fully airgapped environments** —
no external API calls, CDNs, fonts, or telemetry at runtime.

## Stack

- Python >= 3.12, **FastAPI**, Jinja2 templates (all CSS/JS inline — no CDNs)
- **uv** for dependency management (`uv sync`, `uv run ...`); commit `uv.lock`
- **SQLAlchemy** with **SQLite**, **Alembic** for migrations
- **ruff** for format + lint, **ty** for type checking
- ClamAV: `clamd` (INSTREAM protocol) inside the Podman container, `clamscan`
  CLI in local development; auto-detected, switchable via `CLAM_MODE`

## Layout

- `app/main.py` — FastAPI app, routes (HTML UI + `/api/v2/...` JSON API)
- `app/config.py` — env-based settings (pydantic-settings)
- `app/db.py` — engine, `SessionLocal`, `get_db`, `Base`
- `app/models.py` — `Scan` table (hashes, verdict, signature, URLs, ...)
- `app/scanner.py` — `ClamdScanner` / `ClamscanScanner` behind a `Scanner` protocol
- `app/analysis.py` — hashing, URL extraction, file-type sniffing
- `app/templates/` — VirusTotal-style UI (`base`, `index`, `report`, `search`)
- `alembic/` — migrations (`alembic revision --autogenerate -m "..."`)
- `Containerfile`, `compose.yaml`, `container-entrypoint.sh` — Podman deployment

## Commands

```sh
uv sync                          # install deps
uv run alembic upgrade head      # apply migrations
uv run uvicorn app.main:app --reload          # dev server (needs clamscan installed)
uv run pytest                    # tests
uv run ruff format . && uv run ruff check .
uv run ty check
podman build -t clamtotal . && podman compose up   # container mode (clamd)
```

## Conventions

- Conventional commits (`feat:`, `fix:`, `chore:`, ...).
- Keep code clean and compact: do not create many small functions — inline logic
  that is used only once.
- Every model change goes through an Alembic migration; keep SQLite compatible.
- Runtime must stay airgapped: never add runtime calls to external services.
- Run `ruff format`, `ruff check`, and `ty check` before committing.
