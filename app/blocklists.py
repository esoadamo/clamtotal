"""URL/domain scanning against downloaded DNS blocklists.

scripts/update-url-blocklists.sh periodically downloads categorized blocklists
(hagezi, URLhaus, StevenBlack, ...) listed in /etc/url-blocklist-sources.conf into
URL_BLOCKLIST_DIR as <name>.txt files and touches .blocklists-stamp. The app imports
those files into the blocklist_entries table (one shared SQLite table, so uvicorn
workers don't each hold a multi-hundred-MB set in RAM) and hot-reloads in a background
thread when the stamp changes — same pattern as the YARA rules stamp.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from app.analysis import _TLDS as _KNOWN_TLDS
from app.config import settings
from app.db import SessionLocal
from app.models import BlocklistEntry, UrlScan

logger = logging.getLogger(__name__)

STAMP_NAME = ".blocklists-stamp"
_CATEGORY_HEADER_RE = re.compile(r"^#\s*clamtotal-category:\s*(\S+)", re.IGNORECASE)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_URL_INPUT = 2048


def _valid_host(host: str) -> bool:
    """A syntactically valid IP or dotted domain (label rules per RFC 1123)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if "." not in host:
        return False
    return all(_HOST_LABEL_RE.match(label) for label in host.split("."))


def parse_blocklist_line(line: str) -> str | None:
    """Normalize one blocklist line to a bare domain/host, or None to skip it.

    Handles the common formats: plain domains, hagezi wildcard ('*.example.com'),
    hosts files ('0.0.0.0 example.com', '127.0.0.1 example.com') and adblock syntax
    ('||example.com^'). Comments and empty lines are skipped.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("||"):
        line = line[2:].split("^")[0]
    else:
        parts = line.split()
        if len(parts) > 1:
            try:
                ipaddress.ip_address(parts[0])  # hosts format: "<ip> <host>"
            except ValueError:
                return None
            line = parts[1]
    if line.startswith("*."):
        line = line[2:]
    domain = line.strip(".").lower()
    if domain in ("localhost", "0.0.0.0", ""):
        return None
    if not _valid_host(domain):
        return None
    return domain


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_url_input(value: str, require_tld: bool = False) -> tuple[str, str, str] | None:
    """Normalize a user-supplied URL/domain to (url_id, normalized_url, host).

    Accepts full http/https/ftp URLs and bare hosts with optional path. With
    require_tld=True the host's TLD must be a real IANA TLD (used for search-box
    auto-detection, so file names like 'notes.txt' are not treated as domains).
    Returns None for anything that is not a plausible URL/domain.
    """
    value = value.strip()
    if not value or len(value) > MAX_URL_INPUT or "@" in value or any(c.isspace() for c in value):
        return None
    if "://" not in value:
        value = "http://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https", "ftp") or not parsed.hostname:
        return None
    host = parsed.hostname.rstrip(".")
    if not _valid_host(host):
        return None
    if require_tld and not _is_ip(host) and host.split(".")[-1] not in _KNOWN_TLDS:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    default_port = {"http": 80, "https": 443, "ftp": 21}.get(parsed.scheme)
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    normalized = urlunparse((parsed.scheme, netloc, parsed.path or "/", "", parsed.query, ""))
    url_id = base64.urlsafe_b64encode(normalized.encode()).decode().rstrip("=")
    return url_id, normalized, host


def lookup_host(db: Session, host: str) -> list[dict]:
    """Blocklist matches for a host: exact match plus parent-domain walk (wildcard
    semantics — a listed 'example.com' also blocks 'sub.example.com')."""
    host = host.lower().rstrip(".")
    candidates = [host]
    if not _is_ip(host):
        parts = host.split(".")
        candidates += [".".join(parts[i:]) for i in range(1, len(parts) - 1)]
    matches: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        for row in db.execute(
            select(BlocklistEntry).where(BlocklistEntry.domain == candidate)
        ).scalars():
            if (row.domain, row.source) not in seen:
                seen.add((row.domain, row.source))
                matches.append(
                    {"domain": row.domain, "source": row.source, "category": row.category}
                )
    return matches


def _stamp_value() -> int | None:
    """mtime_ns of .blocklists-stamp, or of the newest blocklist file when there is no
    stamp (e.g. user-dropped files); None when the dir is missing/empty."""
    if not settings.url_blocklist_dir:  # empty = feature disabled (Path("") would be cwd)
        return None
    blocklist_dir = Path(settings.url_blocklist_dir)
    try:
        return (blocklist_dir / STAMP_NAME).stat().st_mtime_ns
    except OSError:
        pass
    if blocklist_dir.is_dir():
        files = list(blocklist_dir.glob("*.txt"))
        if files:
            return max(f.stat().st_mtime_ns for f in files)
    return None


_import_lock = threading.Lock()
_import_thread: threading.Thread | None = None
_loaded_stamp: int | None = None


def import_blocklists(db: Session) -> int:
    """(Re)load every *.txt in URL_BLOCKLIST_DIR into blocklist_entries, replacing the
    previous set. The category comes from a '# clamtotal-category: <cat>' header line
    (written by the update script) or falls back to the file name. Returns entry count."""
    global _loaded_stamp
    rows: list[dict] = []
    blocklist_dir = Path(settings.url_blocklist_dir) if settings.url_blocklist_dir else None
    if blocklist_dir is not None and blocklist_dir.is_dir():
        for path in sorted(blocklist_dir.glob("*.txt")):
            source = path.stem
            try:
                lines = path.read_text(errors="replace").splitlines()
            except OSError:
                continue
            category = next(
                (m.group(1) for line in lines if (m := _CATEGORY_HEADER_RE.match(line))),
                source,
            )
            for line in lines:
                domain = parse_blocklist_line(line)
                if domain:
                    rows.append({"domain": domain, "source": source, "category": category})
    with _import_lock:
        db.execute(delete(BlocklistEntry))
        if rows:
            db.execute(insert(BlocklistEntry), rows)
        db.commit()
        _loaded_stamp = _stamp_value()
    logger.info("url blocklists loaded: %d entries from %s", len(rows), settings.url_blocklist_dir)
    return len(rows)


def ensure_blocklists_loaded() -> None:
    """Kick off a background import when the stamp changed since the last import.
    Non-blocking: a scan right after an update runs against the previous set, the next
    one sees the new entries (same hot-reload pattern as the YARA rules stamp)."""
    global _import_thread
    if not settings.url_blocklist_dir:
        return
    stamp = _stamp_value()
    with _import_lock:
        if stamp == _loaded_stamp:
            return
        if _import_thread is not None and _import_thread.is_alive():
            return

        def run() -> None:
            with SessionLocal() as db:
                import_blocklists(db)

        _import_thread = threading.Thread(target=run, daemon=True)
        _import_thread.start()


def blocklist_stats(db: Session) -> tuple[int, float | None]:
    """(entry count, last-update epoch seconds) — read-only, never triggers an import."""
    count = db.execute(select(func.count()).select_from(BlocklistEntry)).scalar() or 0
    stamp = _stamp_value()
    return count, (stamp / 1e9 if stamp is not None else None)


def scan_url(db: Session, value: str, require_tld: bool = False) -> UrlScan | None:
    """Check a URL/domain against the blocklists and upsert the cached row.
    Returns None when the input is not a plausible URL/domain."""
    normalized = normalize_url_input(value, require_tld=require_tld)
    if normalized is None:
        return None
    url_id, url, host = normalized
    ensure_blocklists_loaded()
    matches = lookup_host(db, host) if settings.url_blocklist_dir else []
    scan = db.get(UrlScan, url_id)
    if scan is None:
        scan = UrlScan(url_id=url_id, url=url, host=host, verdict="harmless", matches=[])
        db.add(scan)
    scan.url = url
    scan.host = host
    scan.verdict = "malicious" if matches else "harmless"
    scan.matches = matches
    scan.scanned_at = datetime.now(UTC)
    db.commit()
    return scan
