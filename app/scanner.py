from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import yara  # ty: ignore[unresolved-import]  # compiled extension, no stubs

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    verdict: str  # "clean" | "infected"
    signature: str | None  # e.g. "Win.Test.EICAR_HDB-1"
    engine: str  # e.g. "ClamAV (clamd)"
    raw: str  # raw scanner output


class ScannerUnavailableError(RuntimeError):
    pass


class Scanner(Protocol):
    engine: str

    def scan(self, data: bytes, path: Path | None = None) -> ScanResult: ...

    def available(self) -> bool: ...

    def version(self) -> str | None: ...


class ClamdScanner:
    """Scans via clamd using the INSTREAM command over TCP or a Unix socket (container mode)."""

    engine = "ClamAV (clamd)"

    def _connect(self) -> socket.socket:
        if settings.clamd_socket:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(settings.clamd_socket)
        else:
            sock = socket.create_connection(
                (settings.clamd_host, settings.clamd_port), timeout=settings.clamd_timeout
            )
        sock.settimeout(settings.clamd_timeout)
        return sock

    def available(self) -> bool:
        """Real readiness check: clamd must answer the INSTREAM PING with PONG
        (a bare TCP connect can succeed before clamd finished loading databases)."""
        try:
            with self._connect() as sock:
                sock.sendall(b"zPING\0")
                response = b""
                while b"\n" not in response and b"\x00" not in response:
                    part = sock.recv(64)
                    if not part:
                        break
                    response += part
                return b"PONG" in response
        except OSError:
            return False

    def version(self) -> str | None:
        """clamd VERSION reply (engine + signature DB version), None when unreachable."""
        try:
            with self._connect() as sock:
                sock.sendall(b"zVERSION\0")
                response = b""
                while b"\n" not in response and b"\x00" not in response:
                    part = sock.recv(256)
                    if not part:
                        break
                    response += part
        except OSError:
            return None
        return response.decode(errors="replace").replace("\x00", "").strip() or None

    def scan(self, data: bytes, path: Path | None = None) -> ScanResult:
        if path is not None and settings.clamd_socket:
            return self._scan_fd(path)
        if len(data) > settings.stream_scan_max_size:
            return self._scan_file(data)
        return self._scan_stream(data)

    def _scan_fd(self, path: Path) -> ScanResult:
        """Scan via FILDES over the Unix socket: after the zFILDES command a second
        packet (one dummy byte) carries the fd in SCM_RIGHTS ancillary data, and clamd
        reads the file itself — no StreamMaxLength cap, no app-file permission issues,
        works for multi-GB samples."""
        fd = os.open(path, os.O_RDONLY)
        try:
            with self._connect() as sock:
                sock.sendmsg([b"zFILDES\0"], [])
                sock.sendmsg(
                    [b"\0"],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))],
                )
                response = b""
                while b"\n" not in response and b"\x00" not in response:
                    part = sock.recv(4096)
                    if not part:
                        break
                    response += part
        finally:
            os.close(fd)
        text = response.decode(errors="replace").replace("\x00", "").strip()
        if text.endswith("OK"):
            return ScanResult("clean", None, self.engine, text)
        match = re.search(r"(.+?)\s+FOUND$", text)
        if match:
            return ScanResult("infected", match.group(1), self.engine, text)
        raise ScannerUnavailableError(f"unexpected clamd response: {text!r}")

    def _scan_file(self, data: bytes) -> ScanResult:
        """Scan a large sample via clamd's file-based SCAN command (INSTREAM is
        capped by clamd's StreamMaxLength). clamd usually runs as a different user
        (e.g. "clamav" in the container), so the temp file must live in a directory
        it can traverse and be world-readable — a 0600 file in /tmp makes clamd
        answer "Access denied. ERROR". The temp file is removed afterwards."""
        scan_dir = Path(settings.upload_dir) / ".clamd-scan"
        scan_dir.mkdir(parents=True, exist_ok=True)
        # clamd usually runs as a different user than the app: it must be able to
        # traverse UPLOAD_DIR and .clamd-scan and read the temp file. chmod (unlike
        # mkdir's mode=) is not masked by the process umask and also fixes dirs that
        # already exist with restrictive permissions.
        os.chmod(settings.upload_dir, 0o755)  # nosec B103
        os.chmod(scan_dir, 0o755)  # nosec B103
        fd, path = tempfile.mkstemp(prefix="clamtotal-scan-", dir=scan_dir)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(path, 0o644)  # mkstemp creates 0600; clamd must be able to read it
            with self._connect() as sock:
                sock.sendall(f"zSCAN {path}\0".encode())
                response = b""
                while b"\n" not in response and b"\x00" not in response:
                    part = sock.recv(4096)
                    if not part:
                        break
                    response += part
        finally:
            Path(path).unlink(missing_ok=True)
        text = response.decode(errors="replace").replace("\x00", "").strip()
        # clamd SCAN replies "<path>: OK" or "<path>: <signature> FOUND"
        if text.endswith(": OK"):
            return ScanResult("clean", None, self.engine, text)
        match = re.search(r":\s+(.+?)\s+FOUND$", text)
        if match:
            return ScanResult("infected", match.group(1), self.engine, text)
        if "size limit" in text:
            raise ScannerUnavailableError(
                f"file exceeds clamd StreamMaxLength ({text!r}) — raise STREAM_SCAN_MAX_SIZE and "
                "clamd's StreamMaxLength together"
            )
        if "Access denied" in text:
            raise ScannerUnavailableError(
                f"clamd cannot read the temp scan file ({text!r}) — the clamd user must be able "
                f"to traverse and read {scan_dir}"
            )
        raise ScannerUnavailableError(f"unexpected clamd response: {text!r}")

    def _scan_stream(self, data: bytes) -> ScanResult:
        with self._connect() as sock:
            sock.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), settings.clamd_chunk_size):
                chunk = data[offset : offset + settings.clamd_chunk_size]
                sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(struct.pack(">I", 0))
            response = b""
            # z-commands NUL-terminate responses ("stream: OK\0"), plain ones use \n
            while b"\n" not in response and b"\x00" not in response:
                part = sock.recv(4096)
                if not part:
                    break
                response += part
        # strip NUL terminators from z-command responses before parsing
        text = response.decode(errors="replace").replace("\x00", "").strip()
        if text.endswith("OK"):
            return ScanResult("clean", None, self.engine, text)
        match = re.match(r"stream:\s+(.+?)\s+FOUND", text)
        if match:
            return ScanResult("infected", match.group(1), self.engine, text)
        if "size limit" in text:
            raise ScannerUnavailableError(
                f"file exceeds clamd StreamMaxLength ({text!r}) — raise STREAM_SCAN_MAX_SIZE and "
                "clamd's StreamMaxLength together"
            )
        raise ScannerUnavailableError(f"unexpected clamd response: {text!r}")


class ClamscanScanner:
    """Runs the clamscan CLI on stdin (local development mode)."""

    def __init__(self) -> None:
        self._path = settings.clamscan_path
        try:
            version = subprocess.run(
                [self._path, "--version"], capture_output=True, text=True, check=False
            )
            suffix = version.stdout.strip() if version.returncode == 0 else ""
        except OSError:
            suffix = ""
        self._version = suffix or None
        self.engine = f"ClamAV (clamscan) {suffix}".strip()

    def available(self) -> bool:
        return shutil.which(self._path) is not None

    def version(self) -> str | None:
        return self._version

    def scan(self, data: bytes, path: Path | None = None) -> ScanResult:
        # with a stored file, let clamscan read it directly instead of via stdin
        cmd = (
            [self._path, "--stdout", str(path)]
            if path is not None
            else [self._path, "--stdout", "-"]
        )
        proc = subprocess.run(
            cmd,
            input=None if path is not None else data,
            capture_output=True,
            timeout=settings.clamscan_timeout,
        )
        out = proc.stdout.decode(errors="replace")
        err = proc.stderr.decode(errors="replace")
        if proc.returncode == 2:
            raise ScannerUnavailableError(f"clamscan failed: {err.strip()}")
        # clamscan prints "stdin: <sig> FOUND" for stdin and "<path>: <sig> FOUND" for files
        match = re.search(r"^.*:\s+(.+?)\s+FOUND$", out, re.MULTILINE)
        if proc.returncode == 1 and match:
            return ScanResult("infected", match.group(1), self.engine, out.strip())
        return ScanResult("clean", None, self.engine, out.strip())


def rss_mb() -> float | None:
    """Process RSS in MB from /proc/self/status (Linux), None elsewhere."""
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def yara_rss_budget_mb() -> float | None:
    """RSS budget (MB) for the compiled YARA rule set. YARA_RULES_BUDGET_MB: 0 = auto
    (cgroup memory limit minus current usage minus a 512 MB reserve for clamd and
    in-flight scans), negative = unlimited, positive = explicit MB. None (unlimited)
    when no cgroup v2 limit is set. Lets the daemon skip rule sets it cannot afford
    instead of being OOM-killed mid-compile."""
    if settings.yara_rss_budget_mb > 0:
        return float(settings.yara_rss_budget_mb)
    if settings.yara_rss_budget_mb < 0:
        return None
    try:
        limit = int(Path("/sys/fs/cgroup/memory.max").read_text().strip())
        current = int(Path("/sys/fs/cgroup/memory.current").read_text().strip())
    except (OSError, ValueError):
        return None  # "max" or no cgroup v2 -> unlimited
    return max((limit - current) / 1e6 - 512.0, 0.0)


# rule groups with less source than this compile into ONE combined object (bounded
# spike); bigger groups compile per-file with an RSS budget check before each file
_COMBINED_MAX_SRC_BYTES = 2 * 1024 * 1024

_RULE_DECL = re.compile(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]\w*")


def _count_rules(path: Path) -> int:
    """Number of YARA rule declarations in a source file (for /healthz)."""
    try:
        return len(_RULE_DECL.findall(path.read_text(errors="replace")))
    except OSError:
        return 0


class YaraScanner:
    """Second engine: local YARA rules (yara-python). Fully offline, public rules only.

    All rule files are compiled into a single combined yara.Rules object (one matcher
    pass over the sample instead of one match() call per file); each file gets its own
    namespace, so duplicate rule names across third-party rule sets stay legal. If the
    combined compile fails (e.g. one broken file), fall back to per-file compiles and
    skip broken files so they cannot break the whole engine. When
    scripts/update-yara-rules.sh refreshes rules it touches a .rules-stamp file in the
    rules dir; the next scan then recompiles in a background thread, so scans keep
    running on the current rules and pick up the new set once it is ready (no
    multi-second pause on the scan after an update, no app restart needed).
    """

    engine = "YARA (local rules)"

    def __init__(self, rules_dir: str) -> None:
        self._rules_dir = rules_dir
        self._stamp_path = Path(rules_dir) / ".rules-stamp"
        self._lock = threading.Lock()
        self._rules: list = []  # one compiled yara.Rules per source group
        self._stamp: int | None = None
        self._rules_count = 0
        self._rules_updated: float | None = None
        self._reloading: threading.Thread | None = None
        self._load()

    def _load(self) -> None:
        files = sorted(
            p
            for p in Path(self._rules_dir).glob("**/*")
            if p.suffix in (".yar", ".yara") and p.is_file()
        )
        # compile per top-level source group (bundled rules = ".", each third_party/<name>
        # its own group) so the RSS budget check can skip a whole set BEFORE compiling
        # it — a combined compile of everything would spike past the limit in one go
        groups: dict[str, list[Path]] = {}
        for f in files:
            groups.setdefault(str(f.parent.relative_to(self._rules_dir)), []).append(f)
        budget = yara_rss_budget_mb()
        rules: list = []
        rules_count = 0
        for key in sorted(groups):
            group_files = groups[key]
            src_bytes = sum(f.stat().st_size for f in group_files)
            if src_bytes < _COMBINED_MAX_SRC_BYTES:
                # small group: one combined compile is a bounded spike (~tens of MB)
                rss = rss_mb()
                if budget is not None and rss is not None and rss > budget:
                    logger.warning(
                        "yara: skipping rule group %r (%d files): RSS %.0f MB already over "
                        "budget %.0f MB (raise the container memory limit or YARA_RSS_BUDGET_MB)",
                        key,
                        len(group_files),
                        rss,
                        budget,
                    )
                    continue
                try:
                    rules.append(
                        yara.compile(
                            filepaths={f"ns{i}": str(f) for i, f in enumerate(group_files)}
                        )
                    )
                    rules_count += sum(_count_rules(f) for f in group_files)
                    continue
                except yara.Error:
                    pass  # one broken file must not kill the group: per-file fallback
            # big group (or failed combined compile): compile file by file, checking the
            # RSS budget before each file, so a huge set is cut off at the budget instead
            # of spiking past the cgroup limit in a single combined compile
            for f in group_files:
                rss = rss_mb()
                if budget is not None and rss is not None and rss > budget:
                    logger.warning(
                        "yara: skipping rest of rule group %r (from %s): RSS %.0f MB over "
                        "budget %.0f MB (raise the container memory limit or YARA_RSS_BUDGET_MB)",
                        key,
                        f.name,
                        rss,
                        budget,
                    )
                    break
                try:
                    rules.append(yara.compile(filepath=str(f)))
                    rules_count += _count_rules(f)
                except yara.Error:
                    continue
        try:
            stamp = self._stamp_path.stat().st_mtime_ns
        except OSError:
            stamp = None
        if stamp is not None:
            updated: float | None = stamp / 1e9
        else:
            updated = max((f.stat().st_mtime for f in files), default=None)
        with self._lock:
            self._rules = rules
            self._stamp = stamp
            self._rules_count = rules_count
            self._rules_updated = updated
        logger.info(
            "yara rules loaded: %d rules in %d object(s) from %s",
            rules_count,
            len(rules),
            self._rules_dir,
        )

    def available(self) -> bool:
        with self._lock:
            return bool(self._rules)

    @property
    def rules_count(self) -> int:
        with self._lock:
            return self._rules_count

    @property
    def rules_updated_at(self) -> float | None:
        with self._lock:
            return self._rules_updated

    def _reload_if_stamped(self) -> None:
        try:
            stamp = self._stamp_path.stat().st_mtime_ns
        except OSError:
            stamp = None
        with self._lock:
            if stamp == self._stamp:
                return
            if self._reloading is not None and self._reloading.is_alive():
                return
            self._reloading = threading.Thread(target=self._load, daemon=True)
            self._reloading.start()

    def scan(self, data: bytes, path: Path | None = None) -> list[str]:
        self._reload_if_stamped()
        with self._lock:
            rules_list = list(self._rules)
        if not rules_list:
            return []
        # match by filepath (mmap) when the sample is on disk, else in-memory bytes
        use_path = path is not None and path.exists()
        if len(rules_list) == 1:
            rules = rules_list[0]
            matches = rules.match(filepath=str(path)) if use_path else rules.match(data=data)
            return sorted({m.rule for m in matches})
        # yara-python releases the GIL during match(), so per-file matches overlap
        with ThreadPoolExecutor(max_workers=min(8, len(rules_list))) as pool:
            if use_path:
                results = pool.map(lambda r: r.match(filepath=str(path)), rules_list)
            else:
                results = pool.map(lambda r: r.match(data=data), rules_list)
            return sorted({m.rule for matches in results for m in matches})


_CVD_SUFFIXES = {".cvd", ".cld"}
_TEXT_DB_SUFFIXES = {
    ".hdb",
    ".hsb",
    ".mdb",
    ".msb",
    ".ndb",
    ".ldb",
    ".idb",
    ".fp",
    ".sfp",
    ".pdb",
    ".wdb",
    ".cbc",
    ".crb",
}


def clamav_db_stats(db_dir: str) -> tuple[int | None, float | None]:
    """(signature count, last-updated epoch seconds) from a ClamAV database directory.
    CVD/CLD containers carry the signature count in their 512-byte header (4th colon
    field); plain-text databases count one signature per non-empty, non-comment line.
    Last-updated is the newest mtime among the database files (freshclam/fangfrisch
    rewrite them on update). Returns (None, None) when the dir is unset, missing, or
    has no database files."""
    if not db_dir or not Path(db_dir).is_dir():
        return None, None
    total = 0
    newest: float | None = None
    found = False
    for f in sorted(Path(db_dir).iterdir()):
        if not f.is_file():
            continue
        suffix = f.suffix.lower()
        if suffix not in _CVD_SUFFIXES and suffix not in _TEXT_DB_SUFFIXES:
            continue
        try:
            mtime = f.stat().st_mtime
            if suffix in _CVD_SUFFIXES:
                with f.open("rb") as fh:
                    header = fh.read(512).split(b":")
                if len(header) < 4 or header[0] != b"ClamAV-VDB":
                    continue
                total += int(header[3])
            else:
                lines = f.read_text(errors="replace").splitlines()
                total += sum(1 for line in lines if line.strip() and not line.startswith("#"))
        except (OSError, ValueError):
            continue
        found = True
        newest = mtime if newest is None else max(newest, mtime)
    return (total, newest) if found else (None, None)


_KNOWN_SCANNERS = {"clamav", "yara"}


@lru_cache(maxsize=1)
def enabled_scanners() -> set[str]:
    """Parse ENABLED_SCANNERS into the set of enabled engine names. Unknown or empty
    values fail fast instead of silently guessing (same contract as CLAM_MODE)."""
    tokens = {t.strip().lower() for t in settings.enabled_scanners.split(",") if t.strip()}
    if not tokens or tokens - _KNOWN_SCANNERS:
        raise ScannerUnavailableError(
            f"unknown ENABLED_SCANNERS={settings.enabled_scanners!r}: expected a comma-separated "
            "list of clamav, yara (at least one)"
        )
    return tokens


class YaraDaemonClient:
    """Client for the YARA scan daemon (app/yara_daemon.py): the rule set is compiled
    once in the daemon process; workers just send the sample over a Unix socket and
    get the matches back. Same protocol as clamd's z-commands."""

    engine = "YARA (daemon)"

    def __init__(self, socket_path: str) -> None:
        self._socket_path = socket_path

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)
        sock.settimeout(settings.clamd_timeout)
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

    def scan(self, data: bytes, path: Path | None = None) -> list[str]:
        if path is not None and path.exists():
            resp = self._roundtrip(b"zSCANPATH " + str(path).encode() + b"\0")
        else:
            with self._connect() as sock:
                sock.sendall(b"zINSTREAM\0")
                for offset in range(0, len(data), 64 * 1024):
                    chunk = data[offset : offset + 64 * 1024]
                    sock.sendall(struct.pack(">I", len(chunk)) + chunk)
                sock.sendall(struct.pack(">I", 0))
                resp = self._recv_response(sock)
        if resp.startswith(b"ERROR"):
            raise ScannerUnavailableError(resp.decode(errors="replace"))
        return json.loads(resp)


def yara_rules_stats(rules_dir: str) -> tuple[int | None, float | None]:
    """(rule count, last-updated epoch seconds) from the rules dir WITHOUT compiling
    anything — /healthz must not trigger a multi-hundred-MB yara.compile per worker.
    Counts rule declarations in the source files; last-updated is the .rules-stamp
    mtime (touched by update-yara-rules.sh) or the newest rule file."""
    if not rules_dir or not Path(rules_dir).is_dir():
        return None, None
    files = [
        p for p in Path(rules_dir).glob("**/*") if p.suffix in (".yar", ".yara") and p.is_file()
    ]
    if not files:
        return None, None
    count = sum(_count_rules(f) for f in files)
    try:
        updated = (Path(rules_dir) / ".rules-stamp").stat().st_mtime
    except OSError:
        updated = max((f.stat().st_mtime for f in files), default=None)
    return count, updated


@lru_cache(maxsize=1)
def get_yara_scanner() -> YaraScanner | YaraDaemonClient | None:
    if "yara" not in enabled_scanners():
        return None
    if settings.yara_socket:  # container: shared daemon holds the compiled rule set
        client = YaraDaemonClient(settings.yara_socket)
        return client if client.available() else None
    if not settings.yara_rules_dir:  # dev: in-process engine
        return None
    # Serialize the (memory-hungry, multi-second) compile across uvicorn workers via a
    # cross-process lock, so N workers don't compile the whole rule set simultaneously
    # and spike past the container memory limit. If the lock file is not writable
    # (read-only /rules mount), compile anyway without the lock.
    try:
        with open(Path(settings.yara_rules_dir) / ".compile.lock", "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            scanner = YaraScanner(settings.yara_rules_dir)
    except OSError:
        scanner = YaraScanner(settings.yara_rules_dir)
    return scanner if scanner.available() else None


_MODE_ALIASES = {
    "clamd": "daemon",
    "daemon": "daemon",
    "tcp": "daemon",
    "cli": "cli",
    "auto": "auto",
}


def _probe_scanner(wait: bool) -> Scanner:
    """Probe the ClamAV backend. With wait=True (first-ever probe, e.g. at startup)
    clamd gets up to ~60s to finish loading its databases; with wait=False a single
    attempt is made, so requests fail fast when the backend is down."""
    raw_mode = settings.clam_mode.lower()
    if raw_mode not in _MODE_ALIASES:
        raise ScannerUnavailableError(
            f"unknown CLAM_MODE={raw_mode!r}: expected one of auto, daemon (or clamd/tcp), cli"
        )
    mode = _MODE_ALIASES[raw_mode]
    if mode in ("auto", "daemon"):
        clamd = ClamdScanner()
        # clamd may still be loading its databases at startup — wait up to ~60s for PONG.
        # (The container entrypoint also blocks uvicorn on PONG, this covers races/restarts.)
        for _ in range(30 if wait else 1):
            if clamd.available():
                return clamd
            if wait:
                time.sleep(2)
        if mode == "daemon":
            target = settings.clamd_socket or f"{settings.clamd_host}:{settings.clamd_port}"
            raise ScannerUnavailableError(
                f"clamd not reachable at {target} (CLAM_MODE={raw_mode}): "
                "is clamd running and listening on TCP 3310?"
            )
    if mode in ("auto", "cli"):
        if shutil.which(settings.clamscan_path):
            return ClamscanScanner()
        if mode == "cli":
            raise ScannerUnavailableError(f"clamscan binary not found: {settings.clamscan_path}")
    target = settings.clamd_socket or f"{settings.clamd_host}:{settings.clamd_port}"
    raise ScannerUnavailableError(
        f"no ClamAV backend available (CLAM_MODE={raw_mode!r}): clamd did not answer PING at "
        f"{target} and clamscan binary not found ({settings.clamscan_path}) — "
        "run clamd (CLAM_MODE=daemon) or install clamscan (CLAM_MODE=cli)"
    )


_scanner_lock = threading.Lock()
_scanner_cache: Scanner | None = None
_scanner_probed = False


def get_scanner() -> Scanner | None:
    """Resolve and memoize the ClamAV backend; None when ClamAV is disabled via
    ENABLED_SCANNERS. The first-ever probe waits up to ~60s for clamd to load; after a
    failed probe, later calls re-probe single-shot, so a down backend fails fast (503)
    on every request instead of blocking each one, and recovers once clamd is up."""
    global _scanner_cache, _scanner_probed
    if "clamav" not in enabled_scanners():
        return None
    with _scanner_lock:
        if _scanner_cache is not None:
            return _scanner_cache
        wait = not _scanner_probed
        _scanner_probed = True
    scanner = _probe_scanner(wait=wait)
    with _scanner_lock:
        _scanner_cache = scanner
    return scanner


def reset_scanner_cache() -> None:
    global _scanner_cache, _scanner_probed
    with _scanner_lock:
        _scanner_cache = None
        _scanner_probed = False
