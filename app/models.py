from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Scan(Base):
    """One row per scanned file, keyed by SHA-256. Doubles as the results cache."""

    __tablename__ = "scans"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    md5: Mapped[str] = mapped_column(String(32), index=True)
    sha1: Mapped[str] = mapped_column(String(40), index=True)
    sha512: Mapped[str | None] = mapped_column(String(128), nullable=True)
    crc32: Mapped[str | None] = mapped_column(String(8), nullable=True)
    file_name: Mapped[str] = mapped_column(String(512))
    names: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=True
    )  # alternative names seen for this hash
    size: Mapped[int] = mapped_column(Integer)
    entropy: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )  # Shannon entropy of the sample, computed once at scan time
    file_type: Mapped[str] = mapped_column(String(128))
    magic_hex: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(
        String(16)
    )  # "clean" | "infected" (any engine); "pending" while scanning
    status: Mapped[str] = mapped_column(String(16), default="done")  # "pending" | "done"
    # ephemeral upload: delete the sample + this row once the finished report
    # has been viewed once (only set when ALLOW_EPHEMERAL_UPLOAD=true)
    ephemeral: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    signature: Mapped[str | None] = mapped_column(String(256), nullable=True)
    engine: Mapped[str] = mapped_column(String(128))  # primary engine (ClamAV)
    urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    # extended offline analysis, all JSON for flexibility
    engines: Mapped[list[dict] | None] = mapped_column(
        JSON, nullable=True
    )  # [{name, verdict, signature}]
    iocs: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )  # domains/ips/emails/registry/btc
    behavior: Mapped[dict | None] = mapped_column(
        JSON, nullable=True
    )  # pe/elf/pdf/office/strings/archive
    embedded: Mapped[list[dict] | None] = mapped_column(
        JSON, nullable=True
    )  # recursive child scans
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class UrlScan(Base):
    """One checked URL/domain, keyed by its VT-style base64url id. Doubles as cache:
    re-checking the same URL refreshes the row instead of re-scanning."""

    __tablename__ = "url_scans"

    url_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    url: Mapped[str] = mapped_column(Text)  # normalized URL as checked
    host: Mapped[str] = mapped_column(String(255), index=True)
    verdict: Mapped[str] = mapped_column(String(16))  # "malicious" | "harmless"
    matches: Mapped[list[dict] | None] = mapped_column(
        JSON, nullable=True
    )  # [{domain, source, category}]
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
