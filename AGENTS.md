# AGENTS.md — ClamTotal

ClamTotal is a web app that looks like VirusTotal. A user uploads a file. The
app scans the file with ClamAV. The app then shows a report page. The report
page shows detections, hashes, file details, and extracted URLs. The app must
run in fully airgapped environments. At runtime, the app makes no calls to
external services, CDNs, fonts, or telemetry.

## Stack

- Python >= 3.12, **FastAPI**, Jinja2 templates. All CSS and JS are inline.
  The app loads no CDNs.
- **uv** manages the dependencies (`uv sync`, `uv run ...`). Commit `uv.lock`.
- **SQLAlchemy** with **SQLite**. **Alembic** does the migrations.
- **ruff** formats and lints the code. **ty** type checks the code.
- ClamAV: the Podman container uses `clamd` with the INSTREAM protocol.
  Local development uses the `clamscan` CLI. The app finds the correct mode
  automatically. Set `CLAM_MODE` to select a mode.

## Layout

- `app/main.py` — the FastAPI app. It serves the HTML UI under `/ui/` and the
  JSON API (`/file/upload`, `/api/v2/...`). Every upload path accepts an
  `engines` parameter (comma-separated `clamav`, `yara`, `domain-feed`;
  default `all`) that selects which engines run.
- `app/config.py` — settings that come from environment variables
  (pydantic-settings).
- `app/db.py` — the engine, `SessionLocal`, `get_db`, and `Base`.
- `app/models.py` — the `Scan` table (hashes, verdict, signature, URLs, ...).
- `app/scanner.py` — `ClamdScanner` and `ClamscanScanner`. Both obey the
  Scanner protocol. Also `YaraDaemonClient`. `YaraScanner` runs in-process for
  local development. The YARA daemon also uses it.
- `app/yara_daemon.py` — the YARA scan daemon. It compiles the rule set one
  time in one process. It then serves match requests over a Unix socket
  (`YARA_SOCKET`). The container entrypoint starts it. This design prevents
  each uvicorn worker from loading the rules into its own RAM. In local
  development (`YARA_SOCKET` unset), `get_yara_scanner()` uses the in-process
  `YaraScanner` from `YARA_RULES_DIR`.
- `app/analysis.py` — hashing (MD5/SHA-1/SHA-256/SHA-512/CRC32), IOC
  extraction (URLs, domains, IPs, emails, registry keys, BTC), PE/ELF/PDF/Office
  parsing, suspicious strings, and archive extraction.
- `app/domain_feed.py` — URL and domain scanning. It parses the downloaded
  feed formats: plain domains, hagezi wildcards `*.x`, hosts `0.0.0.0 x`, and
  adblock `||x^`. It imports `DOMAIN_FEED_DIR/*.txt` into a separate SQLite DB
  (`feed.db` in the feed dir, not the app DB). It hot-reloads in a background
  thread when `.feed-stamp` changes. It answers host lookups with exact and
  parent-domain (wildcard) matching. `DomainFeedClient` queries the feed daemon
  over `DOMAIN_FEED_SOCKET` in the container. `url_scans` rows cache the
  per-URL verdicts. The key is a VT-style base64url id.
- `app/feed_daemon.py` — the domain feed daemon. It imports the feed into
  `feed.db` one time in one process. It then serves zLOOKUP, zSTATS, and zPING
  over a Unix socket (clamd-style). The container entrypoint starts it like
  the YARA daemon.
- `app/rules/` — bundled original public YARA rules. The container mounts them
  at `/rules`.
- `scripts/update-signatures.sh`, `container/fangfrisch.conf` — signature
  updates. `freshclam` downloads the official DBs. `fangfrisch` downloads the
  unofficial SaneSecurity DBs, which include YARA rules. Set
  `CLAM_AUTOUPDATE=false` for airgapped operation. The project does not ship
  signature files. `.containerignore` restricts the build context, so no
  secrets enter the image.
- `scripts/update-domain-feed.sh`, `container/domain-feed-sources.conf` —
  periodic download of categorized domain feed lists (`name|category|url`)
  into `/data/domain-feed`. The script runs at bootstrap and on the
  `CLAM_UPDATE_INTERVAL` loop. `CLAM_AUTOUPDATE` gates it. The URLhaus entry
  ships commented out. Enable it with `URLHAUS_AUTH_KEY` (placeholder
  substitution) or with a mounted conf. Each match shows its category, for
  example malware or gambling.
- `scripts/update-yara-rules.sh`, `container/yara-rules-sources.conf` —
  auto-update of third-party YARA rule sets. Only sets with permissive licenses
  (MIT, BSD-2-Clause, DRL-1.1) are permitted. The rules go into
  `/rules/third_party/` for the local YARA engine. The script runs at bootstrap
  and on the `CLAM_UPDATE_INTERVAL` loop. `CLAM_AUTOUPDATE` gates it, the same
  as the ClamAV updates. The script touches `.rules-stamp` so `YaraScanner`
  hot-reloads. `YaraScanner` compiles all rule files into one combined
  `yara.Rules` object. Per-file namespaces keep duplicate rule names across
  sets legal. If a file is broken, the scanner falls back to per-file compiles
  and skips the broken files. It recompiles in a background thread when the
  stamp changes, so a scan after an update is not blocked. Scans match by
  filepath (mmap) when the sample is on disk. Per-file fallback matches run on
  a small thread pool, because yara-python releases the GIL during `match()`.
- `app/templates/` — the UI pages (`base` warm teal theme, `index` home with
  FILE/URL/SEARCH tabs plus ToS notice, `report`, `url_report`, `search`,
  `terms`, `privacy`, `not_found`).
- `app/static/app.js` — all frontend JS. It exports pure functions on
  `window.ClamTotal`. `node --test tests/js/app.test.mjs` tests it.
- `tests/test_frontend.py` — asserts that the rendered HTML agrees with the
  DOM contract that app.js expects.
- `alembic/` — migrations (`alembic revision --autogenerate -m "..."`).
- `Containerfile`, `compose.yaml`, `container-entrypoint.sh` — the Podman
  deployment.
- `clamtotal-client/` — a standalone uv tool subproject
  (`uv tool install ./clamtotal-client`). It is a stdlib-only CLI (`scan`,
  `describe`, `url`) against the JSON API. Every option falls back to an env
  var (`CLAMTOTAL_URL`, default `https://clamtotal.com`,
  `CLAMTOTAL_TIMEOUT`, `CLAMTOTAL_API_KEY`). It has its own pyproject and
  pytest config with 100% coverage of `clamtotal_client/`. Run its tests with
  `cd clamtotal-client && uv run pytest`.

## CI

- GitHub Actions (`.github/workflows/tests.yml`) runs on every push and every
  PR. It runs ruff format and check, `ty check`, the alembic migrations,
  `pytest` with the 100% coverage gate, bandit SAST, and pip-audit SCA. The
  container image builds only if all steps pass.
- On `main`, after the local image build and before the GHCR publish step, an
  integration smoke test (`tests/integration/eicar-smoke.sh`) boots the actual
  image. The test uses a one-signature DB
  (`tests/integration/signatures/eicar.hdb`) and sets
  `CLAM_AUTOUPDATE=false`, so the start is instant and downloads nothing. The
  test uploads EICAR via `POST /api/v2/files` and checks that the verdict is
  infected.

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

- Use conventional commits (`feat:`, `fix:`, `chore:`, ...).
- Keep the code clean and compact. Do not create many small functions. Inline
  logic that is used only once.
- Every model change goes through an Alembic migration. Keep SQLite
  compatible.
- The runtime must stay airgapped by default. Do not add runtime calls to
  external services. Signature updates (freshclam/fangfrisch) are opt-out via
  `CLAM_AUTOUPDATE=false`. Do not add community or login features.
- **100% test coverage is mandatory.** `app/` must be at 100% line coverage.
  `pytest` runs with `--cov=app --cov-fail-under=100` via `addopts`. Keep it
  green. The same rule applies to `clamtotal_client/` in the subproject.
- **When the JSON API changes, update `clamtotal-client/` in the same
  commit.** Adjust `api.py` and `cli.py`, adjust its tests, and increase
  `version` in `clamtotal-client/pyproject.toml`. Commit its `uv.lock` too,
  because the SCA job pip-audits both lockfiles.
- Before you commit, run `ruff format`, `ruff check`, `ty check`, and
  `uv run bandit -r app/ -ll -q` (SAST).
