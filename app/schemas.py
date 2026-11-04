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
    verdict: str = Field(description="'clean' | 'infected'")
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


class HealthResponse(BaseModel):
    status: str = Field(description="'ok' when the service is up")


class ChunkUploadResponse(BaseModel):
    """POST /file/upload/chunk — 202 while more chunks are expected."""

    status: str = Field(description="'chunk_stored' until the last chunk arrives")
    sha256: str = Field(description="SHA-256 of the whole file, as sent by the client")
    received: int = Field(description="chunks stored so far (including this one)")
    total: int = Field(description="total chunk count")


class ErrorResponse(BaseModel):
    detail: str
