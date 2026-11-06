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
- `app/scanner.py` — `ClamdScanner` / `ClamscanScanner` (Scanner protocol) + `YaraDaemonClient`; `YaraScanner` (in-process, dev) lives there too and is used by the daemon
- `app/yara_daemon.py` — YARA scan daemon: compiles the rule set ONCE in one process and serves match requests over a Unix socket (`YARA_SOCKET`, started by the container entrypoint), so uvicorn workers don't each load the rules into their own RAM; in local dev (`YARA_SOCKET` unset) `get_yara_scanner()` falls back to the in-process `YaraScanner` from `YARA_RULES_DIR`
- `app/analysis.py` — hashing (MD5/SHA-1/SHA-256/SHA-512/CRC32), IOC extraction (URLs, domains, IPs, emails, registry keys, BTC), PE/ELF/PDF/Office parsing, suspicious strings, archive extraction
- `app/blocklists.py` — URL/domain scanning: parses downloaded blocklist formats (plain domains, hagezi wildcard `*.x`, hosts `0.0.0.0 x`, adblock `||x^`), imports `URL_BLOCKLIST_DIR/*.txt` into the `blocklist_entries` table (shared SQLite, so workers don't each hold the list in RAM), hot-reloads in a background thread when `.blocklists-stamp` changes, and answers host lookups with exact + parent-domain (wildcard) matching; `url_scans` rows cache per-URL verdicts keyed by a VT-style base64url id
- `app/rules/` — bundled original public YARA rules (mounted at `/rules` in the container)
- `scripts/update-signatures.sh`, `container/fangfrisch.conf` — official (freshclam) + unofficial (SaneSecurity via fangfrisch, which includes YARA rules) signature updates; `CLAM_AUTOUPDATE=false` for airgapped. (extremeshok/clamav-unofficial-sigs was dropped: the repo no longer ships signature files.) Build context is restricted by `.containerignore` so no secrets enter the image
- `scripts/update-url-blocklists.sh`, `container/url-blocklist-sources.conf` — periodic download of categorized URL/domain blocklists (`name|category|url`) into `/data/blocklists` at bootstrap + on the `CLAM_UPDATE_INTERVAL` loop, gated on `CLAM_AUTOUPDATE`; URLhaus entry ships commented out and is enabled via `URLHAUS_AUTH_KEY` (placeholder substitution) or a mounted conf. The app shows the category (malware, gambling, ...) per match
- `scripts/update-yara-rules.sh`, `container/yara-rules-sources.conf` — auto-update of license-permitted third-party YARA rule sets (MIT/BSD-2-Clause/DRL-1.1 only) into `/rules/third_party/` for the local YARA engine; runs at bootstrap + on the `CLAM_UPDATE_INTERVAL` loop, gated on `CLAM_AUTOUPDATE` like the ClamAV updates, touches `.rules-stamp` so `YaraScanner` hot-reloads. `YaraScanner` compiles all rule files into one combined `yara.Rules` object (per-file namespaces keep duplicate rule names across sets legal; on a broken file it falls back to per-file compiles and skips the broken ones) and recompiles in a background thread when the stamp changes, so the scan after an update is not blocked. Scans match by filepath (mmap) when the sample is on disk, and per-file fallback matches run on a small thread pool (yara-python releases the GIL during `match()`)
- `app/templates/` — UI pages (`base`, `index`, `report`, `search`, `not_found`)
- `app/static/app.js` — all frontend JS (exports pure functions on `window.ClamTotal`); tested by `node --test tests/js/app.test.mjs`
- `tests/test_frontend.py` — asserts the rendered HTML matches the DOM contract app.js expects
- `alembic/` — migrations (`alembic revision --autogenerate -m "..."`)
- `Containerfile`, `compose.yaml`, `container-entrypoint.sh` — Podman deployment

## CI

- GitHub Actions (`.github/workflows/tests.yml`) runs on every push/PR: ruff
  format+check, `ty check`, alembic migrations, `pytest` (100% coverage gate),
  bandit SAST, pip-audit SCA; the container image builds only if all pass.
  On `main`, after the local image build and BEFORE the GHCR publish step, an
  integration smoke test (`tests/integration/eicar-smoke.sh`) boots the actual
  image with a one-signature DB (`tests/integration/signatures/eicar.hdb`,
  `CLAM_AUTOUPDATE=false` — no downloads, instant start) and asserts an EICAR
  upload via `POST /api/v2/files` is detected as infected.

## Commands

```sh
uv sync                          # install deps
uv run alembic upgrade head      # apply migrations
uv run uvicorn app.main:app --reload --reload-dir app   # dev server (needs clamscan installed); watch only app/ so runtime data (uploads, sqlite db) never restarts the server mid-request
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
