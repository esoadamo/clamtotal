from __future__ import annotations

import re
import shutil
import socket
import struct
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol

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
        try:
            with self._connect():
                return True
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
        version = subprocess.run(
            [self._path, "--version"], capture_output=True, text=True, check=False
        )
        suffix = version.stdout.strip() if version.returncode == 0 else ""
        self.engine = f"ClamAV (clamscan) {suffix}".strip()

    def available(self) -> bool:
        return shutil.which(self._path) is not None

    def scan(self, data: bytes) -> ScanResult:
        proc = subprocess.run(
            [self._path, "--stdout", "-"],
            input=data,
            capture_output=True,
            text=True,
            timeout=settings.clamscan_timeout,
        )
        if proc.returncode == 2:
            raise ScannerUnavailableError(f"clamscan failed: {proc.stderr.strip()}")
        match = re.search(r"^stdin:\s+(.+?)\s+FOUND$", proc.stdout, re.MULTILINE)
        if proc.returncode == 1 and match:
            return ScanResult("infected", match.group(1), self.engine, proc.stdout.strip())
        return ScanResult("clean", None, self.engine, proc.stdout.strip())


@lru_cache(maxsize=1)
def get_scanner() -> Scanner:
    mode = settings.clam_mode.lower()
    if mode in ("auto", "daemon"):
        clamd = ClamdScanner()
        if clamd.available():
            return clamd
        if mode == "daemon":
            target = settings.clamd_socket or f"{settings.clamd_host}:{settings.clamd_port}"
            raise ScannerUnavailableError(f"clamd not reachable at {target}")
    if mode in ("auto", "cli"):
        if shutil.which(settings.clamscan_path):
            return ClamscanScanner()
        if mode == "cli":
            raise ScannerUnavailableError(f"clamscan binary not found: {settings.clamscan_path}")
    raise ScannerUnavailableError(
        "no ClamAV backend available: run clamd (CLAM_MODE=daemon) "
        "or install clamscan (CLAM_MODE=cli)"
    )
