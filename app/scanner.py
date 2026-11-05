from __future__ import annotations

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
        self.engine = f"ClamAV (clamscan) {suffix}".strip()

    def available(self) -> bool:
        return shutil.which(self._path) is not None

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
        self._combined = None  # single yara.Rules compiled from all files, when possible
        self._per_file: list = []  # per-file compiled rules (fallback)
        self._stamp: int | None = None
        self._reloading: threading.Thread | None = None
        self._load()

    def _load(self) -> None:
        files = sorted(
            p
            for p in Path(self._rules_dir).glob("**/*")
            if p.suffix in (".yar", ".yara") and p.is_file()
        )
        combined = None
        per_file: list = []
        if files:
            try:
                combined = yara.compile(filepaths={f"ns{i}": str(f) for i, f in enumerate(files)})
            except yara.Error:
                for f in files:
                    try:
                        per_file.append(yara.compile(filepath=str(f)))
                    except yara.Error:
                        continue
        try:
            stamp = self._stamp_path.stat().st_mtime_ns
        except OSError:
            stamp = None
        with self._lock:
            self._combined = combined
            self._per_file = per_file
            self._stamp = stamp

    def available(self) -> bool:
        with self._lock:
            return self._combined is not None or bool(self._per_file)

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
            rules_list = ([self._combined] if self._combined is not None else []) + list(
                self._per_file
            )
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


@lru_cache(maxsize=1)
def get_yara_scanner() -> YaraScanner | None:
    if "yara" not in enabled_scanners() or not settings.yara_rules_dir:
        return None
    scanner = YaraScanner(settings.yara_rules_dir)
    return scanner if scanner.available() else None


_MODE_ALIASES = {
    "clamd": "daemon",
    "daemon": "daemon",
    "tcp": "daemon",
    "cli": "cli",
    "auto": "auto",
}


@lru_cache(maxsize=1)
def get_scanner() -> Scanner | None:
    if "clamav" not in enabled_scanners():
        return None  # ClamAV disabled via ENABLED_SCANNERS; scans run with the other engines
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
        for _ in range(30):
            if clamd.available():
                return clamd
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
