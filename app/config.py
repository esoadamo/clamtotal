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
    # per-recv socket timeout; clamd may legitimately take minutes on a large sample
    # before it sends anything, so keep this well above the expected scan time
    clamd_timeout: float = 600.0
    clamd_chunk_size: int = 64 * 1024
    clamscan_path: str = "clamscan"
    # subprocess timeout for one clamscan run; a sample that exceeds it marks the
    # ClamAV engine "timed out" in the report instead of hanging the scan
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
    # domain feed: directory with downloaded feed files (<name>.txt plus a
    # .feed-stamp, written by scripts/update-domain-feed.sh); the feed is imported into
    # its OWN database (feed.db in this dir, separate from the app DB) and hot-reloaded
    # when the stamp changes. Empty (and no socket) disables URL/domain scanning.
    # The container sets it to /data/domain-feed.
    domain_feed_dir: str = ""
    # Unix socket of the domain feed daemon (container: /tmp/domain-feed.sock): when
    # set, workers query the daemon over the socket instead of importing the feed
    # in-process. Empty = in-process feed from DOMAIN_FEED_DIR (local development).
    domain_feed_socket: str = ""
    # per-lookup socket timeout for the domain feed daemon (DOMAIN_FEED_SOCKET); a
    # lookup that exceeds it marks the domain feed engine "timed out" in the report
    domain_feed_timeout: float = 30.0
    # Unix socket of the YARA scan daemon (container sets /tmp/yara.sock): when set,
    # workers query the daemon instead of compiling the rule set into their own RAM.
    # Empty = in-process YaraScanner from YARA_RULES_DIR (local development).
    yara_socket: str = ""
    # per-roundtrip socket timeout for the YARA daemon (YARA_SOCKET); a scan the
    # daemon cannot finish in time marks the YARA engine "timed out" in the report
    yara_daemon_timeout: float = 600.0
    # RSS budget in MB for the compiled YARA rule set: 0 = auto (cgroup memory limit
    # minus current usage minus a 512 MB reserve), negative = unlimited, positive =
    # explicit MB. Rule groups that would exceed it are skipped instead of letting the
    # daemon get OOM-killed mid-compile.
    yara_rss_budget_mb: int = 0
    # per-match timeout in seconds: a pathological sample (catastrophic regex
    # backtracking) must not hang a yara daemon thread forever; exceeding it marks
    # the YARA engine "timed out" in the report
    yara_match_timeout: int = 60
    # recursive scan of archive members: max members per archive, max depth
    max_embedded_files: int = 10
    max_scan_depth: int = 2

    # show the "recently analyzed files" list on the home page
    show_recent_scans: bool = True

    # how long uploaded samples are kept locally, in minutes:
    # -1 = indefinitely, 0 = delete right after upload+scan, N = keep N minutes
    uploads_ttl: int = -1
    # how long scan results (report rows in the database) are kept, in minutes —
    # same semantics as uploads_ttl: -1 = indefinitely (default), 0 = delete right
    # after the scan finishes, N = keep N minutes. The stored sample file is
    # deleted together with its scan result.
    scans_ttl: int = -1
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
