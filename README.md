# clamtotal

> **Disclaimer:** AI wrote most of this code. A human checked the code and
> found no obvious vulnerabilities. Before you rely on this software, read the
> code yourself.

A [VirusTotal](https://www.virustotal.com)-style web app that scans uploaded
files with **ClamAV** and YARA rules. Fully airgapped by default: no external
API calls, CDNs, or telemetry at runtime.

Every scan runs all enabled detection engines by default (ClamAV, YARA, the
domain feed). Any submission — the web upload dialog, the chunked and
WebSocket upload paths, `POST /api/v2/files`, and a rescan — can select which
engines run with an `engines` parameter: a comma-separated list of engine ids
(`clamav`, `yara`, `domain-feed`, or `all`).

## Run with one command

```sh
podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data -v clamav-db:/var/lib/clamav ghcr.io/esoadamo/clamtotal:latest
```

Open http://127.0.0.1:8000/ui/ . The container downloads the ClamAV
signatures on first launch and refreshes them every 6 hours. The named
volumes keep the signatures and the data across restarts. CI publishes the
image to GHCR on every push to `main` where all tests pass.

## Run airgapped

Build the image with all signatures baked in at build time. The build fails
if it cannot download any signature database. The image then makes no
network calls at runtime.

```sh
podman build --build-arg AIRGAPPED=true -t clamtotal:airgapped .
podman network create --internal clamtotal-airgap   # once
podman run --rm --network=clamtotal-airgap -p 127.0.0.1:8000:8000 -v clamtotal-data:/data clamtotal:airgapped
```

A prebuilt variant is published as
`ghcr.io/esoadamo/clamtotal:airgapped-latest`. An `--internal` network has no
route to the internet, so the container stays offline. Rootless Podman still
forwards published ports; rootful Podman does not. To move the image to
another machine, use `podman save -o file.tar` and `podman load -i file.tar`.

## Health check and self-healing

The image ships a `HEALTHCHECK` that curls `http://127.0.0.1:8000/healthz` every
30 s and only reports healthy while the JSON status is `"ok"` (at least one scan
engine ready — a dead clamd makes it `"degraded"`, which counts as unhealthy).
`compose.yaml` repeats the probe in its `healthcheck:` key (a `podman build`
with the default OCI format drops the image `HEALTHCHECK`, so the compose key is
what applies for locally built images) and sets the `io.containers.autoheal`
label, so Podman restarts the container when it turns unhealthy. With a plain
`podman run`, pass the on-failure action explicitly:

```sh
podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data -v clamav-db:/var/lib/clamav \
  --health-on-failure restart ghcr.io/esoadamo/clamtotal:latest
```

Inspect the state with `podman ps` (shows `(healthy)` / `(unhealthy)`) or
`podman inspect --format '{{.State.Health.Status}}' clamtotal`.

## CLI client

A standalone CLI lives in [`clamtotal-client/`](clamtotal-client/README.md).
It uses only the Python standard library. Install it as a
[uv tool](https://docs.astral.sh/uv/concepts/tools/) directly from git — no
clone needed:

```sh
uv tool install "git+https://github.com/esoadamo/clamtotal.git#subdirectory=clamtotal-client"
clamtotal-client scan suspicious.exe --wait 120   # upload, poll, exit 2 if infected
clamtotal-client scan suspicious.exe --engines clamav,yara   # run only the selected engines
clamtotal-client describe 44d88612fea8a86fde9d2f7d4e5f4c6a --json
clamtotal-client url example.com
```

Every option falls back to an env var: `--url` → `CLAMTOTAL_URL`
(default `https://clamtotal.com`), `--timeout` → `CLAMTOTAL_TIMEOUT`,
`--token` → `CLAMTOTAL_API_KEY`, `--engines` → `CLAMTOTAL_ENGINES`.

## Configuration (environment variables)

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./clamtotal.db` | SQLAlchemy URL |
| `UVICORN_WORKERS` | `2` in the container | uvicorn worker count. Each worker loads the full YARA rule set into its own RAM. Too many workers on a small memory limit get OOM-killed. |
| `UVICORN_WORKER_HEALTHCHECK_TIMEOUT` | `120` | Seconds the uvicorn parent waits for a worker healthcheck ping before SIGKILL. The uvicorn default (5) is too low for long scans. |
| `UPLOAD_DIR` | `./uploads` | Where uploaded samples are stored (by SHA-256) |
| `MAX_UPLOAD_SIZE` | `536870912` | Max upload size in bytes. The home page shows this value. |
| `STREAM_SCAN_MAX_SIZE` | `536870912` (= `MAX_UPLOAD_SIZE`) | INSTREAM size cap for clamd. The container syncs clamd's `StreamMaxLength` to this value. |
| `WS_UPLOAD_ENABLED` | `true` | Enables the WebSocket chunked-upload endpoint (`/file/upload/ws`). |
| `WS_CHUNK_SIZE` | `1048576` (1 MB) | Client-side WebSocket frame size in bytes. `0` disables the WS endpoint. |
| `CHUNK_UPLOAD_SIZE` | `26214400` (25 MB) | Files larger than this upload in chunks. `0` disables chunked upload. |
| `APP_VERSION` | build stamp | Version shown in the page footer. The container sets it at build time (`YYMMDD.hhmmss` UTC). |
| `CLAM_MODE` | `auto` | `auto`, `daemon` (aliases `clamd`/`tcp`), or `cli` (clamscan). Any other value makes startup fail. |
| `CLAMD_HOST` / `CLAMD_PORT` | `127.0.0.1` / `3310` | clamd TCP endpoint |
| `CLAMD_TIMEOUT` | `600` | Per-recv socket timeout for clamd answers. On timeout, the report marks the ClamAV engine `timed out`. |
| `CLAMD_SOCKET` | `/tmp/clamd.sock` in the container | clamd Unix socket. When set, samples scan via `FILDES`, so there is no `StreamMaxLength` cap and no file-permission problem. Takes precedence over TCP. |
| `CLAMSCAN_PATH` | `clamscan` | clamscan binary for CLI mode |
| `CLAMSCAN_TIMEOUT` | `600` | Subprocess timeout for one clamscan run. On timeout, the report marks the ClamAV engine `timed out`. |
| `ENABLED_SCANNERS` | `clamav,yara` | Comma-separated list of enabled engines: `clamav` and/or `yara`. Any other value makes the app fail with an error. |
| `CLAMAV_DB_DIR` | unset (container: `/var/lib/clamav`) | ClamAV signature database directory. `/healthz` reports the signature count and the last update time from it. |
| `LOG_LEVEL` | `info` | Log level for the app and uvicorn. `debug` shows worker lifecycle, scan logs, and tracebacks on hard crashes. |
| `YARA_RULES_DIR` | unset | Directory with local public YARA rules (`.yar`/`.yara`). In the container it is `/rules`. |
| `YARA_SOCKET` | unset (container: `/tmp/yara.sock`) | Unix socket of the YARA scan daemon. Unset = in-process engine from `YARA_RULES_DIR` (local dev). |
| `YARA_RSS_BUDGET_MB` | `0` (auto) | RSS budget in MB for the compiled YARA rule set. Rule sets that would exceed the budget are skipped, so the daemon is not OOM-killed mid-compile. |
| `YARA_MATCH_TIMEOUT` | `60` | Per-match timeout in seconds for the in-process YARA engine. On timeout, the report marks the YARA engine `timed out`. |
| `YARA_DAEMON_TIMEOUT` | `600` | Per-roundtrip socket timeout for the YARA daemon. On timeout, the report marks the YARA engine `timed out`. |
| `YARA_RULES_SOURCES` | `/etc/yara-rules-sources.conf` | Third-party YARA rule sources (`name|git-url|branch|subdir`). Only sets with permissive licenses. |
| `DOMAIN_FEED_DIR` | unset (container: `/data/domain-feed`) | Directory with downloaded domain feed files. If empty, URL scanning is disabled. |
| `DOMAIN_FEED_SOURCES` | `/etc/domain-feed-sources.conf` | Domain feed sources (`name|category|url`). |
| `DOMAIN_FEED_SOCKET` | unset (container: `/tmp/domain-feed.sock`) | Unix socket of the domain feed daemon. When set, workers query it instead of importing the feed in-process. |
| `DOMAIN_FEED_TIMEOUT` | `30` | Per-lookup socket timeout for the domain feed daemon. On timeout, the report marks the domain feed engine `timed out`. |
| `URLHAUS_AUTH_KEY` | unset | Free URLhaus API key, substituted into the `<URLHAUS_AUTH_KEY>` placeholder of the commented-out urlhaus source. |
| `MAX_EMBEDDED_FILES` | `10` | Max archive members scanned recursively per file. |
| `MAX_SCAN_DEPTH` | `2` | Recursion depth for embedded-file scanning. |
| `SHOW_RECENT_SCANS` | `true` | Shows the "recently analyzed files" list on the home page. `false` hides it. |
| `ALLOW_EPHEMERAL_UPLOAD` | `false` | When `true`, the upload dialog shows an "ephemeral upload" checkbox. When checked, the app deletes the sample and its result after the scan and one report view. |
| `UPLOADS_TTL` | `-1` | How long uploaded samples stay, in minutes. `-1` = forever. `0` = delete after upload+scan. `N` = keep N minutes. |
| `SCANS_TTL` | `-1` | How long scan results stay, in minutes. Same semantics as `UPLOADS_TTL`. The sample is deleted together with its result. |
| `SCAN_POLL_INTERVAL_MS` | `3000` | How often the pending report page polls for scan progress. |
| `RATE_LIMIT_UPLOAD` | `0` | Per-IP rate limit on uploads. Max requests per window. `0` = disabled. |
| `RATE_LIMIT_BROWSE` | `0` | Per-IP rate limit on browsing result pages. Max requests per window. `0` = disabled. |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window length in seconds. The app returns 429 when the limit is exceeded. |
| `PLAUSIBLE_SCRIPT_URL` | unset | Optional Plausible analytics script URL. Unset = fully airgapped. |

See [AGENTS.md](AGENTS.md) for the project conventions and the local
development setup.
