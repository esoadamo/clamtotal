# clamtotal-client

CLI client for a [ClamTotal](../README.md) server, installable as a [uv tool](https://docs.astral.sh/uv/concepts/tools/):

```sh
uv tool install ./clamtotal-client
```

Zero runtime dependencies (stdlib only), so it installs and runs fully airgapped.

## Usage

```sh
# scan one or more files (uploads to POST /api/v2/files)
clamtotal-client scan suspicious.exe
clamtotal-client scan sample.zip --rescan --wait 120   # poll until done, exit 2 if infected

# show the report for a known sample (GET /api/v2/files/{hash})
clamtotal-client describe 44d88612fea8a86fde9d2f7d4e5f4c6a --json

# check a URL/domain against the domain feed (POST /api/v2/urls)
clamtotal-client url example.com
```

Exit codes: `0` success, `1` request/read error, `2` analyzed sample (or URL) is malicious.

## Configuration

Every CLI option falls back to an environment variable:

| Option      | Env var             | Default                |
| ----------- | ------------------- | ---------------------- |
| `--url`     | `CLAMTOTAL_URL`     | `https://clamtotal.com` |
| `--timeout` | `CLAMTOTAL_TIMEOUT` | `60`                   |
| `--token`   | `CLAMTOTAL_API_KEY` | none (sent as `X-Api-Key` when set) |

## Development

```sh
uv run --project clamtotal-client pytest   # 100% coverage enforced
uv run ruff format clamtotal-client && uv run ruff check clamtotal-client
```
