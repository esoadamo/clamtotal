from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./clamtotal.db"
    upload_dir: str = "./uploads"
    max_upload_size: int = 512 * 1024 * 1024  # bytes
    # INSTREAM size cap: files up to this size are streamed to clamd over the socket;
    # clamd's own StreamMaxLength is synced to this value by the container entrypoint.
    # Defaults to MAX_UPLOAD_SIZE so every accepted upload can use INSTREAM and clamd
    # never needs to read an app-owned file from disk (which fails with "Access denied"
    # when the clamd user cannot traverse the upload volume). Lower it to fall back to
    # clamd's file-based SCAN for large files.
    stream_scan_max_size: int = 512 * 1024 * 1024  # bytes
    # files larger than this are uploaded by the browser in chunks (POST /file/upload/chunk);
    # 0 disables chunked upload. Default 25M stays well under Cloudflare's 100M request-body
    # cap (free plan) even with multipart overhead and proxy buffers
    chunk_upload_size: int = 25 * 1024 * 1024  # bytes
    # WebSocket upload: one persistent connection with small binary frames, so no
    # per-request proxy body cap / ~100s timeout (Cloudflare's limits that bite HTTP
    # chunks). The client falls back to POST /file/upload/chunk when WS fails.
    # ws_upload_enabled=false (or ws_chunk_size=0) disables the WS endpoint.
    ws_upload_enabled: bool = True
    ws_chunk_size: int = 1024 * 1024  # client-side WS frame size, bytes

    # shown in the page footer; the container sets it at BUILD time (UTC YYMMDD.hhmmss)
    app_version: str = ""

    # log level for the app logger and (in the container, via the entrypoint) uvicorn
    log_level: str = "info"

    # auto | daemon | cli — which ClamAV backend to use ("clamd"/"tcp" accepted as alias of
    # "daemon"); any other value fails startup with an error instead of silently guessing
    clam_mode: str = "auto"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str | None = None
    clamd_timeout: float = 120.0
    clamd_chunk_size: int = 64 * 1024
    clamscan_path: str = "clamscan"
    clamscan_timeout: int = 600
    # ClamAV signature database directory (clamd's DatabaseDirectory); used by /healthz
    # to report signature count and last update time. Empty = unknown. The container
    # sets it to /var/lib/clamav.
    clamav_db_dir: str = ""

    # comma-separated list of enabled scan engines ("clamav,yara" = both, the default);
    # unknown or empty values fail with an error instead of silently guessing
    enabled_scanners: str = "clamav,yara"

    # local YARA rules directory (public rules only); empty disables the YARA engine
    yara_rules_dir: str = ""
    # recursive scan of archive members: max members per archive, max depth
    max_embedded_files: int = 10
    max_scan_depth: int = 2

    # show the "recently analyzed files" list on the home page
    show_recent_scans: bool = True

    # how long uploaded samples are kept locally, in minutes:
    # -1 = indefinitely, 0 = delete right after upload+scan, N = keep N minutes
    uploads_ttl: int = -1
    # how often the report page polls for scan progress while pending
    scan_poll_interval_ms: int = 3000

    # optional per-IP rate limits, max requests per window (0 = disabled):
    # uploads -> POST /file/upload and POST /api/v2/files
    # browse  -> GET /ui/, /ui/search, /ui/file/{hash}
    rate_limit_upload: int = 0
    rate_limit_browse: int = 0
    rate_limit_window_seconds: int = 60

    # optional Plausible analytics script URL loaded on every page; empty = off
    # (e.g. "https://plausible.io/js/script.js"); default keeps runtime airgapped
    plausible_script_url: str = ""


settings = Settings()
