# clamtotal

> **Disclaimer:** Mistral 4 wrote most of this code with AI assistance. A
> human checked the code and found no obvious vulnerabilities. Before you
> rely on this software, read the code yourself.

ClamTotal is a web app that looks like
[VirusTotal](https://www.virustotal.com). The app scans uploaded files with
**ClamAV**. The app is fully airgapped by default. At runtime, the app makes
no external API calls, loads no CDNs, and sends no telemetry. You can enable
an optional Plausible analytics script with `PLAUSIBLE_SCRIPT_URL`. It is off
by default.

All features work fully offline. The app has no login and no community
features.

- The UI looks like VirusTotal and uses the warm teal theme. The home page
  shows a centered logo, a tagline, and a tabbed widget with **FILE / URL /
  SEARCH** tabs. Under it, the page shows a Terms-of-Service and privacy
  notice (`/ui/terms`, `/ui/privacy`) and an API bar. The report pages show a
  detection widget and these tabs:
  - **Detection** — a verdict table with one row per engine.
  - **Details** — hashes, file type, entropy.
  - **Behavior** — PE/ELF/PDF/Office analysis, suspicious strings,
    archive contents.
  - **Network** — URLs, domains, IPs, emails, registry keys, BTC addresses,
    punycode/IDN flags.
  - **Embedded** — archive members, scanned recursively.
  - **Relations** — other local scans that share indicators. A scan links to
    its containers in both directions, so a file that was uploaded separately
    or packed inside an archive links to that archive. Alternative names are
    tracked per hash and shown in Details as "Alternative names".
- The container scans with **clamd** over the INSTREAM protocol. Local
  development scans with the **clamscan** CLI. Set `CLAM_MODE` to
  `auto`, `daemon`, or `cli`. A second engine scans with **local YARA rules**
  (`yara-python`, `YARA_RULES_DIR`).
- The container updates the ClamAV signatures by itself. `freshclam` updates
  the official DBs. fangfrisch updates the unofficial SaneSecurity DBs, which
  include YARA rules that clamd loads natively. The update runs every 6 hours
  by default. For airgapped operation, bake the signatures into the image at
  build time (`--build-arg AIRGAPPED=true`). The image then sets
  `CLAM_AUTOUPDATE=false` by default. You do not need the `-e` flag.
- The app stores data in SQLite via SQLAlchemy and Alembic. Scan results are
  cached by SHA-256. If you upload a file again, the app shows the cached
  report immediately.
- The app computes these hashes: MD5, SHA-1, SHA-256, SHA-512, CRC32, and the
  PE imphash.
- The app scans URLs and domains against a periodically downloaded,
  categorized **domain feed**. Use `POST /api/v2/urls` (form field `url`) and
  `GET /api/v2/urls/{id}` (VT-style base64url id). A report page is at
  `/ui/url/{id}`. It uses the same tabbed UI as the file reports
  (Detection/Details/Relations). The home page has a URL tab. If a search
  query is a domain or URL, the page shows a live verdict card. URLs and
  domains extracted from files are clickable links to their URL scan. URL
  reports list the files that contain them (Relations). Each match shows the
  **category** (malware, gambling, ads, ...) and the source list. The default
  sources are HaGeZi TIF (malware/phishing/scam), HaGeZi gambling, and
  StevenBlack hosts. The URLhaus hostfile (malware distribution) is commented
  out. To enable it, get a free `URLHAUS_AUTH_KEY`. A dedicated daemon imports
  the feed into its own database (`feed.db`). The daemon is
  `app/feed_daemon.py` on `DOMAIN_FEED_SOCKET`. It serves the workers over a
  Unix socket, like the YARA daemon.
- Search by MD5/SHA-1/SHA-256, file name, or URL/domain. Download a sample.
  Force a rescan.
- The UI shows all indicators **defanged** (`hxxp://`, `[.]`). Indicators are
  never clickable or loadable. IPs preceded by `version` or `v` are not
  misdetected. A domain must have a real IANA TLD. Its second-level label
  must have 5 or more characters.
- The UI is served at `/` and at `/ui/`. The API is `POST /file/upload` and
  `/api/v2/...`.
- The JSON API is VT-compatible at a minimum level. `POST /api/v2/files`
  returns `202` plus a `sha256` and scans asynchronously. If the hash was
  already analyzed, it returns `200` with `cached: true`. `GET
  /api/v2/files/{hash}` includes a `status` of `pending` or `done`. `POST
  /api/v2/urls` and `GET /api/v2/urls/{id}` check URLs and domains against the
  local domain feed. This lookup is synchronous and returns a verdict plus
  categories. `/healthz` lists the feed as a `domain-feed` engine entry with
  the entry count and the last update.
- The user flow copies VirusTotal. The browser hashes the file (SHA-256) and
  checks `GET /api/v2/files/{hash}` first. If the file was analyzed before,
  the browser goes directly to the report. For a new file, the browser asks
  for confirmation, then uploads it with a progress bar. The progress bar
  shows live speed and ETA for whole-file and chunked uploads. The browser
  then lands on `/file/{hash}`, the full results page. The page fills in
  progressively: the Detection tab shows one spinning circle per engine
  (ClamAV, YARA). When an engine finishes, the circle changes to the verdict
  (signature or "Undetected"). The Details/Behavior/Network tabs fill in as
  the offline analysis is committed.
- Files larger than `CHUNK_UPLOAD_SIZE` (default 25 MB) upload in chunks. By
  default the browser sends the chunks over a persistent WebSocket
  (`/file/upload/ws`, small frames, resumable on reconnect). Per-request proxy
  body caps and timeouts, like Cloudflare's, do not stop this path. If the
  socket fails, the browser falls back to HTTP chunks via `POST
  /file/upload/chunk`. Both paths reassemble the file on the server and
  verify the SHA-256.

## Local development

You need Python >= 3.12, [uv](https://docs.astral.sh/uv/), and ClamAV
(`clamscan`, for example `apt install clamav`).

```sh
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --reload-dir app   # watch only app/ so uploads/db writes never restart the server mid-request
```

Open http://127.0.0.1:8000/ui/ . Upload the
[EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to see a
detection.

## CLI client (`clamtotal-client`)

A standalone CLI lives in [`clamtotal-client/`](clamtotal-client/README.md).
It uses only the Python standard library. Install it as a
[uv tool](https://docs.astral.sh/uv/concepts/tools/):

```sh
uv tool install ./clamtotal-client
clamtotal-client scan suspicious.exe --wait 120   # upload, poll, exit 2 if infected
clamtotal-client describe 44d88612fea8a86fde9d2f7d4e5f4c6a --json
clamtotal-client url example.com
```

Every option falls back to an env var: `--url` → `CLAMTOTAL_URL`
(default `https://clamtotal.com`), `--timeout` → `CLAMTOTAL_TIMEOUT`,
`--token` → `CLAMTOTAL_API_KEY`.

## Container image

On every push to `main` where all tests pass, CI builds and publishes the
image to GHCR: `ghcr.io/<owner>/clamtotal:latest`, plus a tag per commit SHA.
Pull it with:

```sh
podman pull ghcr.io/<owner>/clamtotal:latest
```

### Airgapped image

Do this to build a fully airgapped image with all signatures baked in at
build time. The build downloads the official ClamAV DBs via freshclam, the
unofficial DBs via fangfrisch, third-party YARA rules, and the domain feed.
Pass `--build-arg AIRGAPPED=true`. The build **fails if it cannot download
any signature database**. A broken image is therefore never published. The
image sets `CLAM_AUTOUPDATE=false` by default. You do not need the `-e` flag
at run time.

Run the image on an **internal Podman network**. An `--internal` network has
no route to the internet or to the host, so the container stays fully
offline. Rootless Podman still forwards published ports. `--net=none` does
not do this: it discards `-p` ("Port mappings have been discarded...") and
the web UI is unreachable.

```sh
podman network create --internal clamtotal-airgap   # once
podman build --build-arg AIRGAPPED=true -t clamtotal:airgapped .
podman run --rm --network=clamtotal-airgap -p 127.0.0.1:8000:8000 -v clamtotal-data:/data clamtotal:airgapped
```

CI builds and publishes this variant by itself on every push to `main` and
every 3 days, as `ghcr.io/esoadamo/clamtotal:airgapped-latest`:

```sh
podman network create --internal clamtotal-airgap   # once
podman run --rm --network=clamtotal-airgap -p 127.0.0.1:8000:8000 -v clamtotal-data:/data ghcr.io/esoadamo/clamtotal:airgapped-latest
```

> **Note:** port forwarding on `--internal` networks works with **rootless**
> Podman, the default on personal machines. Rootful Podman does not forward
> published ports on internal networks. If you run rootful Podman, publish
> the port on a non-internal network, or put a reverse proxy in front.

#### Move the airgapped image to another machine (offline transfer)

Do this to copy the image to a machine with no registry and no internet.

1. On the source machine, save the image to a tar archive:

```sh
podman save -o clamtotal-airgapped.tar ghcr.io/esoadamo/clamtotal:airgapped-latest
```

2. If you want a smaller file, compress the archive first. The image is
   several GB, because the signatures are baked in:

```sh
xz -T0 clamtotal-airgapped.tar
```

3. Copy `clamtotal-airgapped.tar` to the target machine (USB drive, `scp`,
   ...).

4. On the target machine, load the image:

```sh
podman load -i clamtotal-airgapped.tar
```

5. If you compressed the archive, decompress it first
   (`xz -d clamtotal-airgapped.tar.xz`), or run `podman load -i` on the
   `.tar` inside.

6. Run the image:

```sh
podman network create --internal clamtotal-airgap   # once, if not already created
podman run --rm --network=clamtotal-airgap -p 127.0.0.1:8000:8000 -v clamtotal-data:/data ghcr.io/esoadamo/clamtotal:airgapped-latest
```

`podman load` restores the original image reference. The `podman run`
command is therefore the same as on the source machine.

## Podman (container mode with clamd)

```sh
podman build -t clamtotal .
# 2 workers per CPU core, trusts proxy headers (works behind a Cloudflare Tunnel)
podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data -v clamav-db:/var/lib/clamav clamtotal
# or: podman compose up
```

`/var/lib/clamav` holds the downloaded ClamAV signature databases. It is a
named volume in `compose.yaml`. Container restarts keep the signatures, so
clamd always starts with a valid database.

By default, the container downloads the ClamAV signatures on first launch,
not at build time. It refreshes them every 6 hours at runtime
(`update-signatures.sh`: `freshclam` + fangfrisch/SaneSecurity, which ships
YARA rules that clamd loads natively). The **local YARA engine** also pulls
third-party rule sets with permissive licenses (ReversingLabs MIT,
signature-base DRL-1.1, ditekshen BSD-2 — see
`container/yara-rules-sources.conf`) into `/rules/third_party/`. This happens
on first launch and on the same 6-hour loop
(`scripts/update-yara-rules.sh`). The app hot-reloads the rules without a
restart. For a fully airgapped deployment:

```sh
podman build --build-arg AIRGAPPED=true -t clamtotal .  # signatures baked in at BUILD time
podman run -e CLAM_AUTOUPDATE=false -v ./my-signatures:/var/lib/clamav:ro \
  -v ./my-public-rules:/rules:ro -p 127.0.0.1:8000:8000 clamtotal
```

You can mount public YARA rules at `/rules` (`YARA_RULES_DIR=/rules`). A small
original ruleset is bundled in `app/rules/public.yar`. Set
`CLAM_AUTOUPDATE=false` to turn off the third-party YARA rule updates together
with the ClamAV updates, or bake them into the image with `--build-arg
AIRGAPPED=true`. To customize the unofficial signature sources (fangfrisch),
mount your own config over the baked-in one:
`-v ./fangfrisch.conf:/etc/fangfrisch.conf:ro`, or set `FANGFRISCH_CONF` to
another path. See `container/fangfrisch.conf` for the available sections. In
the same way, you can override the YARA source list with
`-v ./yara-rules-sources.conf:/etc/yara-rules-sources.conf:ro`, or set
`YARA_RULES_SOURCES`. See `container/yara-rules-sources.conf` for the format.
It ships with a commented YARA Forge opt-in. YARA Forge mixes licenses. You
must accept them before you enable it.

`scripts/update-domain-feed.sh` downloads the domain feed into
`/data/domain-feed` (a named volume via `/data`). This happens on first
launch and on the same 6-hour loop. The sources are listed, with categories,
in `container/domain-feed-sources.conf` (one `<name>|<category>|<url>` per
line). The feed daemon imports the lists into its own SQLite database
(`/data/domain-feed/feed.db`, separate from the app DB) and hot-reloads
without a restart when `.feed-stamp` changes. Customize the sources with
`-v ./domain-feed-sources.conf:/etc/domain-feed-sources.conf:ro`, or set
`DOMAIN_FEED_SOURCES`. You can also put your own `*.txt` files into
`/data/domain-feed` with a `# clamtotal-category: <category>` header. The
URLhaus source needs a free API key (https://urlhaus.abuse.ch/api/): set
`URLHAUS_AUTH_KEY` (the updater substitutes it into the `<URLHAUS_AUTH_KEY>`
placeholder), or bake the key into a mounted conf. `CLAM_AUTOUPDATE=false`
turns off the feed updates together with the ClamAV updates.

## Configuration (environment variables)

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clamtotal.db` | SQLAlchemy URL |
| `UVICORN_WORKERS` | `2` in the container | uvicorn worker count. Each worker is a separate process that compiles the full YARA rule set into its own RAM on first scan. The ClamAV DB is loaded once by clamd, not per worker. If the memory limit is small and you set too many workers, the kernel OOM-kills them on the first `/healthz` or upload. The workers die with no traceback. Check `[entrypoint] memory:`, per-worker `rss=`, and `podman inspect --format '{{.State.OOMKilled}}'`. |
| `UVICORN_WORKER_HEALTHCHECK_TIMEOUT` | `120` | Seconds the uvicorn parent waits for a worker healthcheck ping before it sends SIGKILL. The uvicorn default is 5. That is too low for long scans. |
| `UPLOAD_DIR` | `./uploads` | Where uploaded samples are stored (by SHA-256) |
| `MAX_UPLOAD_SIZE` | `536870912` | Max upload size in bytes. The home page shows this value. |
| `STREAM_SCAN_MAX_SIZE` | `536870912` (= `MAX_UPLOAD_SIZE`) | INSTREAM size cap for clamd. The container syncs clamd's `StreamMaxLength` to this value, so all uploads scan via INSTREAM and clamd never reads app-owned files. This avoids `Access denied` on the upload volume. Set it lower to scan larger files via clamd's file-based SCAN. |
| `WS_UPLOAD_ENABLED` | `true` | Enables the WebSocket chunked-upload endpoint (`/file/upload/ws`). The browser uses it by default and falls back to HTTP chunks on failure. |
| `WS_CHUNK_SIZE` | `1048576` (1 MB) | Client-side WebSocket frame size in bytes. `0` disables the WS endpoint. |
| `CHUNK_UPLOAD_SIZE` | `26214400` (25 MB) | Files larger than this upload in chunks (`POST /file/upload/chunk`). `0` disables chunked upload. If a proxy (e.g. Cloudflare) returns 413, the client retries with 25 MB chunks by itself. |
| `APP_VERSION` | build stamp | Version shown in the page footer. The container image sets it at build time to `YYMMDD.hhmmss` UTC (`/app/.build-version`). |
| `CLAM_MODE` | `auto` | `auto`, `daemon` (aliases `clamd`/`tcp`), or `cli` (clamscan). Any other value makes startup fail. |
| `CLAMD_HOST` / `CLAMD_PORT` | `127.0.0.1` / `3310` | clamd TCP endpoint |
| `CLAMD_TIMEOUT` | `600` | Per-recv socket timeout for clamd answers. clamd can take minutes on a large sample before it replies. On timeout, the app shows the clear error `clamd did not answer within CLAMD_TIMEOUT=...s` instead of a raw `TimeoutError`, and marks the ClamAV engine `timed out` in the report. |
| `CLAMD_SOCKET` | `/tmp/clamd.sock` in the container | Unix socket for clamd. When set, stored samples scan via `FILDES` (fd passed with `SCM_RIGHTS`). There is no `StreamMaxLength` cap and no file-permission problem. Multi-GB files work when you raise `MAX_UPLOAD_SIZE`. |
| `CLAMD_SOCKET` | unset | clamd Unix socket. It takes precedence over TCP. |
| `CLAMSCAN_PATH` | `clamscan` | clamscan binary for CLI mode |
| `CLAMSCAN_TIMEOUT` | `600` | Subprocess timeout for one clamscan run. If the run exceeds it, the report marks the ClamAV engine `timed out`. |
| `ENABLED_SCANNERS` | `clamav,yara` | Comma-separated list of enabled scan engines: `clamav` (clamd/clamscan) and/or `yara` (local rules). Any other value makes the app fail with an error. |
| `CLAMAV_DB_DIR` | unset (container: `/var/lib/clamav`) | ClamAV signature database directory. `/healthz` reports the signature count and the last update time from it. |
| `LOG_LEVEL` | `info` | Log level for the app logger and, in the container via the entrypoint, uvicorn. `debug` shows worker lifecycle and restart reasons, scan start/done/failure logs, and native tracebacks on hard crashes (faulthandler). |
| `YARA_RULES_DIR` | unset | Directory with local public YARA rules (`.yar`/`.yara`). In the container it is `/rules`. |
| `YARA_SOCKET` | unset (container: `/tmp/yara.sock`) | Unix socket of the YARA scan daemon (`app/yara_daemon.py`, started by the container entrypoint). Workers query it over the socket instead of each compiling the rule set into their own RAM. Unset = in-process engine from `YARA_RULES_DIR` (local dev). |
| `YARA_RSS_BUDGET_MB` | `0` (auto) | RSS budget in MB for the compiled YARA rule set. `0` = cgroup memory limit − current usage − 512 MB reserve. Negative = unlimited. Positive = explicit MB. Rule sets that would exceed the budget are skipped (with a log line), so the daemon is not OOM-killed mid-compile. |
| `YARA_MATCH_TIMEOUT` | `60` | Per-match timeout in seconds for the in-process YARA engine. A sample that triggers catastrophic regex backtracking does not hang forever. If the timeout is exceeded, the report marks the YARA engine `timed out`. |
| `YARA_DAEMON_TIMEOUT` | `600` | Per-roundtrip socket timeout for the YARA daemon (`YARA_SOCKET`). If the daemon cannot finish a scan in time, the report marks the YARA engine `timed out`. |
| `YARA_RULES_SOURCES` | `/etc/yara-rules-sources.conf` | Third-party YARA rule sources (`name|git-url|branch|subdir`) for the local YARA engine. Only sets with permissive licenses. |
| `DOMAIN_FEED_DIR` | unset (container: `/data/domain-feed`) | Directory with downloaded domain feed files (`<name>.txt` + `.feed-stamp` + `feed.db`). If empty, URL scanning is disabled. |
| `DOMAIN_FEED_SOURCES` | `/etc/domain-feed-sources.conf` | Domain feed sources (`name|category|url`) for `scripts/update-domain-feed.sh`. |
| `DOMAIN_FEED_SOCKET` | unset (container: `/tmp/domain-feed.sock`) | Unix socket of the domain feed daemon. When set, workers query it instead of importing the feed in-process. |
| `DOMAIN_FEED_TIMEOUT` | `30` | Per-lookup socket timeout for the domain feed daemon (`DOMAIN_FEED_SOCKET`). If a lookup exceeds it, the report marks the domain feed engine `timed out`. |
| `URLHAUS_AUTH_KEY` | unset | Free URLhaus API key. The updater substitutes it into the `<URLHAUS_AUTH_KEY>` placeholder of the commented-out urlhaus source. |
| `MAX_EMBEDDED_FILES` | `10` | Max archive members scanned recursively per file. |
| `MAX_SCAN_DEPTH` | `2` | Recursion depth for embedded-file scanning. |
| `SHOW_RECENT_SCANS` | `true` | Shows the "recently analyzed files" list on the home page. `false` hides it. |
| `ALLOW_EPHEMERAL_UPLOAD` | `false` | When `true`, the upload confirmation dialog shows an "ephemeral upload" checkbox. When checked, the app deletes the stored sample and its scan result after the scan finishes and the report page has been viewed once. This works for full, chunked, and WebSocket uploads. |
| `UPLOADS_TTL` | `-1` | How long uploaded samples stay in local storage, in minutes. `-1` = forever. `0` = delete right after upload and scan. `N` = keep N minutes. A background job prunes every minute. |
| `SCANS_TTL` | `-1` | How long scan results (report rows in the SQLite database) stay, in minutes. The semantics are the same as `UPLOADS_TTL`: `-1` = forever (default), `0` = delete after the scan finishes, `N` = keep N minutes. A background job prunes every minute. The stored sample is deleted together with its scan result. |
| `SCAN_POLL_INTERVAL_MS` | `3000` | How often the pending report page polls for scan progress. |
| `RATE_LIMIT_UPLOAD` | `0` | Optional per-IP rate limit on uploads (`POST /file/upload`, `POST /api/v2/files`). Max requests per window. `0` = disabled. |
| `RATE_LIMIT_BROWSE` | `0` | Optional per-IP rate limit on browsing result pages (`/ui/`, `/ui/search`, `/ui/file/{hash}`). Max requests per window. `0` = disabled. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window length in seconds. The app returns 429 when the limit is exceeded. |
| `PLAUSIBLE_SCRIPT_URL` | unset | Optional Plausible analytics script URL, loaded (deferred) on every page. Unset = fully airgapped. |

Memory note: clamd holds the ClamAV signature DB in RAM. The YARA daemon
compiles the rule set once. With all default third-party YARA sources, this
needs several GB. If the kernel OOM-kills the daemon or the workers
(`Killed`/`Child process died` with no traceback), raise the container memory
limit (compose `mem_limit: 8g`), or trim
`container/yara-rules-sources.conf` (signature-base is disabled by default
for this reason).

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

See [AGENTS.md](AGENTS.md) for the project conventions.
