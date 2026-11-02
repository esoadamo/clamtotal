from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

_URL_RE = re.compile(rb"(?:https?|ftp)://[^\s\"'<>()\[\]{}|\\^`]+", re.IGNORECASE)

_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "PE32 executable (EXE/DLL)"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (DOCX/XLSX/JAR/APK)"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"RIFF", "RIFF container (WAV/AVI/WEBP)"),
    (b"\x1f\x8b", "gzip compressed data"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"ustar", "POSIX tar archive"),
]


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_urls(data: bytes, limit: int = 200) -> list[str]:
    urls: list[str] = []
    for match in _URL_RE.finditer(data):
        url = match.group(0).decode("utf-8", errors="ignore").rstrip(".,;:!")
        if url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break
    return urls


def sniff_file_type(data: bytes) -> tuple[str, str]:
    """Return (human-readable file type, first bytes as hex)."""
    for magic, description in _MAGIC_SIGNATURES:
        if data.startswith(magic):
            return description, data[:16].hex()
    if (
        data
        and sum(1 for b in data[:4096] if b in b"\t\n\r" or 32 <= b < 127) / min(len(data), 4096)
        > 0.95
    ):
        return "ASCII text", data[:16].hex()
    return "data", data[:16].hex()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
