from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
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
    file_name: Mapped[str] = mapped_column(String(512))
    size: Mapped[int] = mapped_column(Integer)
    file_type: Mapped[str] = mapped_column(String(128))
    magic_hex: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))  # "clean" | "infected"
    signature: Mapped[str | None] = mapped_column(String(256), nullable=True)
    engine: Mapped[str] = mapped_column(String(128))
    urls: Mapped[list[str]] = mapped_column(JSON, default=list)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
