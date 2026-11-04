# AGENTS.md — ClamTotal

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

- `app/main.py` — FastAPI app: HTML UI under `/ui/` + JSON API (`/file/upload`, `/api/v2/...`)
- `app/config.py` — env-based settings (pydantic-settings)
- `app/db.py` — engine, `SessionLocal`, `get_db`, `Base`
- `app/models.py` — `Scan` table (hashes, verdict, signature, URLs, ...)
- `app/scanner.py` — `ClamdScanner` / `ClamscanScanner` (Scanner protocol) + `YaraScanner` (local public rules)
- `app/analysis.py` — hashing (MD5/SHA-1/SHA-256/SHA-512/CRC32), IOC extraction (URLs, domains, IPs, emails, registry keys, BTC), PE/ELF/PDF/Office parsing, suspicious strings, archive extraction
- `app/rules/` — bundled original public YARA rules (mounted at `/rules` in the container)
- `scripts/update-signatures.sh`, `container/fangfrisch.conf` — official (freshclam) + unofficial (SaneSecurity via fangfrisch, which includes YARA rules) signature updates; `CLAM_AUTOUPDATE=false` for airgapped. (extremeshok/clamav-unofficial-sigs was dropped: the repo no longer ships signature files.) Build context is restricted by `.containerignore` so no secrets enter the image
- `scripts/update-yara-rules.sh`, `container/yara-rules-sources.conf` — auto-update of license-permitted third-party YARA rule sets (MIT/BSD-2-Clause/DRL-1.1 only) into `/rules/third_party/` for the local YARA engine; runs at bootstrap + on the `CLAM_UPDATE_INTERVAL` loop, gated on `CLAM_AUTOUPDATE` like the ClamAV updates, touches `.rules-stamp` so `YaraScanner` hot-reloads. `YaraScanner` compiles rule files individually and skips broken ones (duplicate rule names across sets must not break the engine)
- `app/templates/` — UI pages (`base`, `index`, `report`, `search`, `not_found`)
- `app/static/app.js` — all frontend JS (exports pure functions on `window.ClamTotal`); tested by `node --test tests/js/app.test.mjs`
- `tests/test_frontend.py` — asserts the rendered HTML matches the DOM contract app.js expects
- `alembic/` — migrations (`alembic revision --autogenerate -m "..."`)
- `Containerfile`, `compose.yaml`, `container-entrypoint.sh` — Podman deployment

## CI

- GitHub Actions (`.github/workflows/tests.yml`) runs on every push/PR: ruff
  format+check, `ty check`, alembic migrations, `pytest` (100% coverage gate),
  bandit SAST, pip-audit SCA; the container image builds only if all pass.

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
- Runtime must stay airgapped by default: never add runtime calls to external
  services. Signature updates (freshclam/fangfrisch) are opt-out via
  `CLAM_AUTOUPDATE=false`, and no community/login features.
- **100% test coverage is mandatory**: `app/` must be at 100% line coverage
  (`pytest` runs with `--cov=app --cov-fail-under=100` via `addopts`; keep it green).
- Run `ruff format`, `ruff check`, `ty check`, and `uv run bandit -r app/ -ll -q` (SAST) before committing.
