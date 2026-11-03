from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./clamtotal.db"
    upload_dir: str = "./uploads"
    max_upload_size: int = 512 * 1024 * 1024  # bytes

    # auto | daemon | cli — which ClamAV backend to use
    clam_mode: str = "auto"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str | None = None
    clamd_timeout: float = 120.0
    clamd_chunk_size: int = 64 * 1024
    clamscan_path: str = "clamscan"
    clamscan_timeout: int = 600

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


settings = Settings()
