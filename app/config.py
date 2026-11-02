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


settings = Settings()
