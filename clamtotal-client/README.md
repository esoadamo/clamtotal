# clamtotal-client

CLI client for a [ClamTotal](../README.md) server, installable as a
[uv tool](https://docs.astral.sh/uv/concepts/tools/) straight from git — no clone
needed:

```sh
uv tool install "git+https://github.com/esoadamo/clamtotal.git#subdirectory=clamtotal-client"
```

Zero runtime dependencies (stdlib only), so it installs and runs fully airgapped.
A local clone can also be installed with `uv tool install ./clamtotal-client`.

While a file is being uploaded, a live progress line (`uploading sample.zip: 42%
(4.2 MB of 10 MB)`) is redrawn in place on **stderr**; stdout stays clean for
`--json` and piping. Use `--no-progress` to hide it.

## Usage

```sh
# scan one or more files (uploads to POST /api/v2/files)
clamtotal-client scan suspicious.exe
clamtotal-client scan sample.zip --rescan --wait 120   # poll until done, exit 2 if infected
clamtotal-client scan suspicious.exe --engines clamav,yara   # run only the selected engines (default: all)
clamtotal-client scan big.iso --no-progress    # hide the upload progress indicator

# show the report for a known sample (GET /api/v2/files/{hash})
clamtotal-client describe 44d88612fea8a86fde9d2f7d4e5f4c6a --json

# check a URL/domain against the domain feed (POST /api/v2/urls)
clamtotal-client url example.com
```

Exit codes: `0` success, `1` request/read error, `2` analyzed sample (or URL) is malicious.

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
| `--rescan`   | Force a re-analysis of an already-known sample                                     |
| `--ephemeral`| Do not persist the sample (deleted after the scan and one report view)              |
| `--engines`  | Comma-separated engines to run: `clamav`, `yara`, `domain-feed` (default: all)    |
| `--no-progress` | Hide the upload progress indicator on stderr (shown by default)           |
| `--wait`     | Poll until the analysis finishes (max seconds), then print the verdict             |
| `--json`     | Print the raw JSON response(s) instead of the human-readable summary              |

`describe` and `url` accept `--json` for raw output. `--wait` also works with
`--json` (prints the final report as JSON).

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
