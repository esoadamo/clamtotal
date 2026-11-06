"""Domain feed: URL/domain scanning against periodically downloaded categorized feeds.

scripts/update-domain-feed.sh downloads the feeds listed in /etc/domain-feed-sources.conf
into DOMAIN_FEED_DIR as <name>.txt files and touches .feed-stamp. The feed is imported
into its OWN SQLite database (feed.db inside the feed dir — deliberately separate from
the app database), either by the feed daemon (app/feed_daemon.py, container mode: one
process imports the lists and serves lookups over a Unix socket, so uvicorn workers
don't each load them) or in-process from DOMAIN_FEED_DIR (local development). The feed
hot-reloads in a background thread when .feed-stamp changes — same pattern as the YARA
rules stamp.
"""

from __future__ import annotations

import base64
import fcntl
import ipaddress
import json
import logging
import re
import socket
import threading
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from sqlalchemy import create_engine, delete, func, insert, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.analysis import _TLDS as _KNOWN_TLDS
from app.config import settings
from app.models import UrlScan

logger = logging.getLogger(__name__)

STAMP_NAME = ".feed-stamp"
FEED_DB_NAME = "feed.db"
_CATEGORY_HEADER_RE = re.compile(r"^#\s*clamtotal-category:\s*(\S+)", re.IGNORECASE)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_URL_INPUT = 2048


class FeedBase(DeclarativeBase):
    pass


class FeedEntry(FeedBase):
    """One blocked domain/host from a downloaded feed, in the SEPARATE feed database.
    Composite key on (domain, source): the same domain can be listed by several feeds."""

    __tablename__ = "feed_entries"

    domain: Mapped[str] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(primary_key=True)  # feed name (file stem)
    category: Mapped[str] = mapped_column()  # e.g. malware, gambling, ads


def feed_db_path(feed_dir: str) -> str:
    return str(Path(feed_dir) / FEED_DB_NAME)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _valid_host(host: str) -> bool:
    """A syntactically valid IP or dotted domain (label rules per RFC 1123)."""
    if _is_ip(host):
        return True
    if "." not in host:
        return False
    return all(_HOST_LABEL_RE.match(label) for label in host.split("."))


def parse_feed_line(line: str) -> str | None:
    """Normalize one feed line to a bare domain/host, or None to skip it.

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
    if domain in ("localhost", ""):
        return None
    if not _valid_host(domain):
        return None
    if _is_ip(domain) and ipaddress.ip_address(domain).is_unspecified:
        return None  # hosts-file wildcard address (e.g. the "0.0.0.0 0.0.0.0" line)
    return domain


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
    """Feed matches for a host: exact match plus parent-domain walk (wildcard
    semantics — a listed 'example.com' also blocks 'sub.example.com')."""
    host = host.lower().rstrip(".")
    candidates = [host]
    if not _is_ip(host):
        parts = host.split(".")
        candidates += [".".join(parts[i:]) for i in range(1, len(parts) - 1)]
    matches: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        for row in db.execute(select(FeedEntry).where(FeedEntry.domain == candidate)).scalars():
            if (row.domain, row.source) not in seen:
                seen.add((row.domain, row.source))
                matches.append(
                    {"domain": row.domain, "source": row.source, "category": row.category}
                )
    return matches


def stamp_value(feed_dir: str) -> int | None:
    """mtime_ns of .feed-stamp, or of the newest feed file when there is no stamp
    (e.g. user-dropped files); None when the dir is missing/empty/disabled."""
    if not feed_dir:  # empty = feature disabled (Path("") would be cwd)
        return None
    feed_path = Path(feed_dir)
    try:
        return (feed_path / STAMP_NAME).stat().st_mtime_ns
    except OSError:
        pass
    if feed_path.is_dir():
        files = list(feed_path.glob("*.txt"))
        if files:
            return max(f.stat().st_mtime_ns for f in files)
    return None


def import_feed(db: Session, feed_dir: str) -> int:
    """(Re)load every *.txt in the feed dir into feed_entries, replacing the previous
    set. The category comes from a '# clamtotal-category: <cat>' header line (written
    by the update script) or falls back to the file name. Returns entry count."""
    rows: list[dict] = []
    feed_path = Path(feed_dir) if feed_dir else None
    if feed_path is not None and feed_path.is_dir():
        for path in sorted(feed_path.glob("*.txt")):
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
                domain = parse_feed_line(line)
                if domain:
                    rows.append({"domain": domain, "source": source, "category": category})
    # cross-process lock (same pattern as the YARA compile lock): with uvicorn
    # --workers N or the feed daemon, concurrent multi-MB inserts would otherwise
    # hit SQLite "database is locked"
    lock = None
    if feed_path is not None:
        try:
            lock = open(feed_path / ".import.lock", "w")
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError:
            if lock is not None:
                lock.close()
            lock = None  # read-only dir: import anyway, without the lock
    try:
        db.execute(delete(FeedEntry))
        if rows:
            db.execute(insert(FeedEntry), rows)
        db.commit()
    finally:
        if lock is not None:
            lock.close()
    logger.info("domain feed loaded: %d entries from %s", len(rows), feed_dir)
    return len(rows)


class DomainFeed:
    """In-process domain feed backed by its OWN SQLite database (feed.db in the feed
    dir, separate from the app DB). Used by the feed daemon process and, in local
    development (DOMAIN_FEED_SOCKET unset), directly by the app."""

    engine = "Domain feed"

    def __init__(self, feed_dir: str, db_path: str | None = None) -> None:
        self._feed_dir = feed_dir
        Path(feed_dir).mkdir(parents=True, exist_ok=True)  # feed.db lives here
        self._engine = create_engine(
            f"sqlite:///{db_path or feed_db_path(feed_dir)}",
            connect_args={"check_same_thread": False},
        )
        FeedBase.metadata.create_all(self._engine)
        self._session = sessionmaker(bind=self._engine, autoflush=False, expire_on_commit=False)
        self._lock = threading.Lock()
        self._stamp: int | None = None
        self._reloading: threading.Thread | None = None
        self.load()

    def load(self) -> int:
        with self._session() as db:
            count = import_feed(db, self._feed_dir)
        with self._lock:
            self._stamp = stamp_value(self._feed_dir)
        return count

    def reload_if_stamped(self) -> None:
        """Kick off a background reload when the stamp changed since the last import.
        Non-blocking: a lookup right after an update runs against the previous set."""
        stamp = stamp_value(self._feed_dir)
        with self._lock:
            if stamp == self._stamp:
                return
            if self._reloading is not None and self._reloading.is_alive():
                return
            self._reloading = threading.Thread(target=self._reload_thread, daemon=True)
            self._reloading.start()

    def _reload_thread(self) -> None:
        try:
            self.load()
        except Exception:
            logger.exception("domain feed reload failed; keeping previous entries")

    def available(self) -> bool:
        with self._session() as db:
            return (db.execute(select(func.count()).select_from(FeedEntry)).scalar() or 0) > 0

    def version(self) -> str:
        with self._session() as db:
            count = db.execute(select(func.count()).select_from(FeedEntry)).scalar() or 0
        return f"domain-feed ({count} entries)"

    def lookup(self, host: str) -> list[dict]:
        self.reload_if_stamped()
        with self._session() as db:
            return lookup_host(db, host)

    def stats(self) -> tuple[int, float | None]:
        """(entry count, last-update epoch seconds) — read-only, never triggers a reload."""
        with self._session() as db:
            count = db.execute(select(func.count()).select_from(FeedEntry)).scalar() or 0
        stamp = stamp_value(self._feed_dir)
        return count, (stamp / 1e9 if stamp is not None else None)


class DomainFeedClient:
    """Client for the feed daemon (app/feed_daemon.py): the daemon imports the feed
    into its own DB once and serves lookups over a Unix socket. Same z-command
    protocol as clamd and the YARA daemon."""

    engine = "Domain feed (daemon)"

    def __init__(self, socket_path: str) -> None:
        self._socket_path = socket_path

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)
        sock.settimeout(30)
        return sock

    def _recv_response(self, sock: socket.socket) -> bytes:
        response = b""
        while b"\x00" not in response:
            part = sock.recv(65536)
            if not part:
                break
            response += part
        return response.replace(b"\x00", b"")

    def _roundtrip(self, payload: bytes) -> bytes:
        with self._connect() as sock:
            sock.sendall(payload)
            return self._recv_response(sock)

    def available(self) -> bool:
        try:
            return self._roundtrip(b"zPING\0") == b"PONG"
        except OSError:
            return False

    def version(self) -> str | None:
        try:
            text = self._roundtrip(b"zVERSION\0").decode(errors="replace").strip()
        except OSError:
            return None
        return text or None

    def stats(self) -> tuple[int, float | None]:
        try:
            data = json.loads(self._roundtrip(b"zSTATS\0"))
        except (OSError, json.JSONDecodeError):
            return 0, None
        return int(data.get("entries", 0)), data.get("updated_at")

    def lookup(self, host: str) -> list[dict]:
        resp = self._roundtrip(b"zLOOKUP " + host.encode() + b"\0")
        if resp.startswith(b"ERROR"):
            raise RuntimeError(resp.decode(errors="replace"))
        return json.loads(resp)


@lru_cache(maxsize=1)
def get_domain_feed() -> DomainFeed | DomainFeedClient | None:
    """Resolve the domain feed once per process: the daemon over DOMAIN_FEED_SOCKET in
    the container, else the in-process feed from DOMAIN_FEED_DIR (local dev), else None
    (URL scanning disabled)."""
    if settings.domain_feed_socket:
        client = DomainFeedClient(settings.domain_feed_socket)
        return client if client.available() else None
    if not settings.domain_feed_dir:
        return None
    try:
        return DomainFeed(settings.domain_feed_dir)
    except Exception:
        logger.exception("domain feed init failed; URL scanning will 503")
        return None


def scan_url(
    db: Session, value: str, feed: DomainFeed | DomainFeedClient, require_tld: bool = False
) -> UrlScan | None:
    """Check a URL/domain against the feed and upsert the cached row in the app DB.
    Returns None when the input is not a plausible URL/domain."""
    normalized = normalize_url_input(value, require_tld=require_tld)
    if normalized is None:
        return None
    url_id, url, host = normalized
    matches = feed.lookup(host)
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
