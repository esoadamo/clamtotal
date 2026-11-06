from typing import Any

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    """POST /file/upload — 202 when a new scan was queued, 200 when cached."""

    sha256: str = Field(description="SHA-256 of the uploaded file")
    status: str = Field(description="scan status: 'pending' (202) or 'done' (200, cached)")
    cached: bool = Field(description="true when the result came from the cache")


class ApiScanResponse(BaseModel):
    """POST /api/v2/files — VT-compatible upload response."""

    sha256: str
    md5: str
    sha1: str
    status: str = Field(description="'pending' (202) or 'done' (200, cached)")
    permalink: str = Field(description="UI report page path")


class EngineVerdict(BaseModel):
    name: str = Field(description="engine name, e.g. 'ClamAV (clamd)'")
    status: str = Field(
        default="done",
        description="'scanning' while the engine runs, 'done' once the verdict is in",
    )
    verdict: str = Field(
        default="", description="'clean' | 'infected' (empty while still scanning)"
    )
    signature: str | None = Field(description="detection signature, if infected")


class FileReport(BaseModel):
    """GET /api/v2/files/{hash} — full analysis report for a file."""

    sha256: str
    md5: str
    sha1: str
    sha512: str | None
    crc32: str | None
    file_name: str
    names: list[str] = Field(description="all known file names for this hash")
    size: int = Field(description="file size in bytes")
    file_type: str
    verdict: str = Field(description="'clean' | 'infected' | 'pending'")
    status: str = Field(description="'pending' | 'done'")
    signature: str | None
    engines: list[EngineVerdict]
    urls: list[str]
    iocs: dict[str, Any] = Field(description="domains, ips, emails, registry keys, BTC addresses")
    behavior: dict[str, Any] = Field(
        description="PE/ELF/PDF/Office analysis, suspicious strings, archive members"
    )
    embedded: list[dict[str, Any]] = Field(description="recursively scanned archive members")
    scanned_at: str = Field(description="ISO-8601 UTC timestamp of the last completed scan")


class UrlMatch(BaseModel):
    domain: str = Field(description="blocked domain/host that matched")
    source: str = Field(description="blocklist source name, e.g. 'hagezi-tif'")
    category: str = Field(description="blocklist category, e.g. 'malware' or 'gambling'")


class UrlScanResponse(BaseModel):
    """POST /api/v2/urls — URL/domain check result (synchronous local blocklist lookup)."""

    id: str = Field(description="base64url id of the normalized URL, for GET /api/v2/urls/{id}")
    url: str = Field(description="normalized URL that was checked")
    verdict: str = Field(description="'malicious' when any blocklist matched, else 'harmless'")
    categories: list[str] = Field(description="categories of the matched blocklists")
    sources: list[str] = Field(description="blocklist sources that matched")
    permalink: str = Field(description="UI report page path")


class UrlReport(BaseModel):
    """GET /api/v2/urls/{id} — full report for a checked URL/domain."""

    id: str
    url: str
    host: str = Field(description="extracted host (domain or IP) that was looked up")
    verdict: str = Field(description="'malicious' | 'harmless'")
    matches: list[UrlMatch]
    categories: list[str]
    stats: dict[str, int] = Field(
        description="VT-style counters: {'malicious': 1|0, 'harmless': 1|0}"
    )
    permalink: str
    last_analysis: str = Field(description="ISO-8601 UTC timestamp of the last check")


class EngineHealth(BaseModel):
    name: str = Field(description="engine display name, e.g. 'ClamAV (clamd)'")
    type: str = Field(description="'clamav', 'yara' or 'blocklists' (URL blocklist feed)")
    enabled: bool = Field(description="whether ENABLED_SCANNERS selects this engine")
    ready: bool = Field(description="whether the engine is currently reachable/loaded")
    version: str | None = Field(default=None, description="engine version string, if known")
    rules: int | None = Field(default=None, description="signature/rule count, null when unknown")
    rules_updated_at: str | None = Field(
        default=None, description="ISO 8601 UTC timestamp of the last rules update, if known"
    )


class HealthResponse(BaseModel):
    status: str = Field(
        description="'ok' when at least one enabled engine is ready, else 'degraded'"
    )
    engines: list[EngineHealth] = Field(
        description="scan engines plus the URL blocklist feed (type 'blocklists')"
    )


class ChunkUploadResponse(BaseModel):
    """POST /file/upload/chunk — 202 while more chunks are expected."""

    status: str = Field(description="'chunk_stored' until the last chunk arrives")
    sha256: str = Field(description="SHA-256 of the whole file, as sent by the client")
    received: int = Field(description="chunks stored so far (including this one)")
    total: int = Field(description="total chunk count")


class ErrorResponse(BaseModel):
    detail: str
