# clamtotal-client

CLI client for a [ClamTotal](../README.md) server, installable as a
[uv tool](https://docs.astral.sh/uv/concepts/tools/) straight from git — no clone
needed:

```sh
uv tool install "git+https://github.com/esoadamo/clamtotal.git#subdirectory=clamtotal-client"
```

Zero runtime dependencies (stdlib only), so it installs and runs fully airgapped.
A local clone can also be installed with `uv tool install ./clamtotal-client`.

The client picks the best upload transport the server supports (it probes
`GET /api/v2/upload/capabilities`): one direct `POST /api/v2/files` for small
files, HTTP chunked upload behind body-size-limiting proxies, or a single
persistent WebSocket with resumable chunks for large ones. If the WebSocket
fails mid-upload it degrades to HTTP chunks (the server shares the chunk
storage, so the retry resumes).

While a file is being uploaded, a live progress line (`uploading sample.zip: 42%
(4.2 MB of 10 MB, 1.8 MB/s, eta 3s)`) is redrawn in place on **stderr**; stdout
stays clean for `--json` and piping. Use `--no-progress` to hide it.

Files whose SHA-256 the server already knows (queued or analyzed) are not
uploaded again unless `--rescan` is passed. After the upload the client waits
for the analysis to finish and prints the verdict (exit `2` when any enabled
engine detects something, `1` when one never delivered a verdict, `0` only
when they all finished clean). `--no-wait-result` skips the waiting and
prints the upload response only.

## Usage

```sh
# scan one or more files (uploads to POST /api/v2/files)
clamtotal-client scan suspicious.exe                  # upload, wait, print the verdict
clamtotal-client scan sample.zip --rescan --wait 120   # cap the wait at 120s
clamtotal-client scan huge.iso --no-wait-result        # fire-and-forget (upload response only)
clamtotal-client scan suspicious.exe --engines clamav,yara   # run only the selected engines (default: all)
clamtotal-client scan big.iso --no-progress    # hide the upload progress indicator

# show the report for a local file or a known sample (GET /api/v2/files/{hash})
clamtotal-client describe suspicious.exe                 # local file: hash lookup (uploads when unknown)
clamtotal-client describe suspicious.exe --rescan       # re-analyze it
clamtotal-client describe --hash 44d88612fea8a86fde9d2f7d4e5f4c6a --json  # hash only, never uploads

# check a URL/domain against the domain feed (POST /api/v2/urls)
clamtotal-client url example.com
```

Exit codes: `0` success (for `scan`: every enabled engine finished and found no
detection), `1` request/read error or an inconclusive verdict (an engine timed
out, or the wait expired before the scan finished), `2` the analyzed sample (or
URL) is malicious.

## Options

Global options (apply to every command):

| Option      | Description                              |
| ----------- | ---------------------------------------- |
| `--url`     | ClamTotal backend base URL               |
| `--timeout` | Request timeout in seconds               |
| `--token`   | API key sent as `X-Api-Key`              |
| `--version` | Print the client version and exit        |

`scan` options:

| Option       | Description                                                                        |
| ------------ | ---------------------------------------------------------------------------------- |
| `--rescan`   | Force a re-analysis of an already-known sample (always uploads)                    |
| `--ephemeral`| Do not persist the sample (deleted after the scan and one report view)              |
| `--engines`  | Comma-separated engines to run: `clamav`, `yara`, `domain-feed` (default: all)    |
| `--no-progress` | Hide the upload progress indicator on stderr (shown by default)           |
| `--no-wait-result` | Print only the upload response; do not wait for the scan result        |
| `--wait`     | Max seconds to wait for the analysis (default: 300)                                 |
| `--json`     | Print the raw JSON response(s) instead of the human-readable summary              |

`describe` accepts a local file path or `--hash`; a file is uploaded only when
the server does not know its hash (or with `--rescan`). `--rescan --hash`
cannot work - the daemon can only rescan what you upload - and fails fast.
`describe` and `url` accept `--json` for raw output; `--json` combined with the
result wait prints the final report as JSON.

## Configuration

Every CLI option falls back to an environment variable:

| Option      | Env var             | Default                  |
| ----------- | ------------------- | ------------------------ |
| `--url`     | `CLAMTOTAL_URL`     | `https://clamtotal.com`  |
| `--timeout` | `CLAMTOTAL_TIMEOUT` | `60`                     |
| `--token`   | `CLAMTOTAL_API_KEY` | none (sent as `X-Api-Key` when set) |
| `--engines` | `CLAMTOTAL_ENGINES` | all engines (when unset, no selection is sent) |

An explicit flag always overrides its env var.

## Development

```sh
uv run --project clamtotal-client pytest   # 100% coverage enforced
uv run ruff format clamtotal-client && uv run ruff check clamtotal-client
```
