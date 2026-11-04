from __future__ import annotations

import re
import shutil
import socket
import struct
import subprocess
import time
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

    def scan(self, data: bytes) -> ScanResult: ...


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
                while b"\n" not in response:
                    part = sock.recv(64)
                    if not part:
                        break
                    response += part
                return b"PONG" in response
        except OSError:
            return False

    def scan(self, data: bytes) -> ScanResult:
        with self._connect() as sock:
            sock.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), settings.clamd_chunk_size):
                chunk = data[offset : offset + settings.clamd_chunk_size]
                sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(struct.pack(">I", 0))
            response = b""
            while b"\n" not in response:
                part = sock.recv(4096)
                if not part:
                    break
                response += part
        text = response.decode(errors="replace").strip()
        if text.endswith("OK"):
            return ScanResult("clean", None, self.engine, text)
        match = re.match(r"stream:\s+(.+?)\s+FOUND", text)
        if match:
            return ScanResult("infected", match.group(1), self.engine, text)
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

    def scan(self, data: bytes) -> ScanResult:
        proc = subprocess.run(
            [self._path, "--stdout", "-"],
            input=data,
            capture_output=True,
            timeout=settings.clamscan_timeout,
        )
        out = proc.stdout.decode(errors="replace")
        err = proc.stderr.decode(errors="replace")
        if proc.returncode == 2:
            raise ScannerUnavailableError(f"clamscan failed: {err.strip()}")
        match = re.search(r"^stdin:\s+(.+?)\s+FOUND$", out, re.MULTILINE)
        if proc.returncode == 1 and match:
            return ScanResult("infected", match.group(1), self.engine, out.strip())
        return ScanResult("clean", None, self.engine, out.strip())


class YaraScanner:
    """Second engine: local YARA rules (yara-python). Fully offline, public rules only."""

    engine = "YARA (local rules)"

    def __init__(self, rules_dir: str) -> None:
        self._rules = None
        files = sorted(
            p for p in Path(rules_dir).glob("**/*") if p.suffix in (".yar", ".yara") and p.is_file()
        )
        if files:
            sources = {f"rule_{i}": f.read_text(encoding="utf-8") for i, f in enumerate(files)}
            self._rules = yara.compile(sources=sources)

    def available(self) -> bool:
        return self._rules is not None

    def scan(self, data: bytes) -> list[str]:
        if self._rules is None:
            return []
        return sorted({m.rule for m in self._rules.match(data=data)})


@lru_cache(maxsize=1)
def get_yara_scanner() -> YaraScanner | None:
    if not settings.yara_rules_dir:
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
def get_scanner() -> Scanner:
    raw_mode = settings.clam_mode.lower()
    mode = _MODE_ALIASES.get(raw_mode, "auto")  # unknown values fall back to auto, never skip clamd
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
