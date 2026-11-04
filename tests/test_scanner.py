import shutil
import socket
import struct

import pytest

import app.scanner as scanner_module
from app.config import settings
from app.scanner import (
    ClamdScanner,
    ClamscanScanner,
    ScannerUnavailableError,
    YaraScanner,
    get_scanner,
    get_yara_scanner,
)


class FakeSocket:
    def __init__(self, response: bytes, fail: bool = False):
        self.response = response
        self.fail = fail
        self.sent = b""

    def connect(self, addr):
        if self.fail:
            raise OSError("refused")

    def settimeout(self, t):
        pass

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        chunk, self.response = self.response[:n], self.response[n:]
        return chunk

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture(autouse=True)
def clear_caches(monkeypatch):
    get_scanner.cache_clear()
    get_yara_scanner.cache_clear()
    monkeypatch.setattr(scanner_module.time, "sleep", lambda s: None)  # keep retry loop fast
    yield
    get_scanner.cache_clear()
    get_yara_scanner.cache_clear()


def test_clamd_tcp_clean(monkeypatch):
    fake = FakeSocket(b"stream: OK\n")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    result = ClamdScanner().scan(b"data")
    assert result.verdict == "clean" and result.signature is None
    assert fake.sent.startswith(b"zINSTREAM\0")


def test_clamd_tcp_infected(monkeypatch):
    fake = FakeSocket(b"stream: Win.Test.EICAR_HDB-1 FOUND\n")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    result = ClamdScanner().scan(b"data")
    assert result.verdict == "infected" and result.signature == "Win.Test.EICAR_HDB-1"


def test_clamd_unexpected_response(monkeypatch):
    fake = FakeSocket(b"INSTREAM size limit exceeded\n")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    with pytest.raises(ScannerUnavailableError):
        ClamdScanner().scan(b"data")


def test_clamd_available_and_unavailable(monkeypatch):
    # available() does a real INSTREAM PING and requires PONG
    monkeypatch.setattr(
        socket, "create_connection", lambda addr, timeout=None: FakeSocket(b"PONG\n")
    )
    assert ClamdScanner().available() is True
    monkeypatch.setattr(
        socket, "create_connection", lambda addr, timeout=None: FakeSocket(b"stream: OK\n")
    )
    assert ClamdScanner().available() is False  # no PONG -> not ready
    # connection closed before any response (empty recv) -> break path
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: FakeSocket(b""))
    assert ClamdScanner().available() is False
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda addr, timeout=None: (_ for _ in ()).throw(OSError("down")),
    )
    assert ClamdScanner().available() is False


def test_clamd_unix_socket(monkeypatch):
    monkeypatch.setattr(settings, "clamd_socket", "/tmp/fake.clamd.sock")
    fake = FakeSocket(b"stream: OK\n")
    monkeypatch.setattr(socket, "socket", lambda family, type_: fake)
    assert ClamdScanner().scan(b"x").verdict == "clean"
    monkeypatch.setattr(settings, "clamd_socket", None)


def _write_fake_clamscan(tmp_path, body: str):
    path = tmp_path / "clamscan"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


def test_clamscan_clean_and_version(tmp_path, monkeypatch):
    monkeypatch.setattr(
        settings,
        "clamscan_path",
        _write_fake_clamscan(
            tmp_path,
            'if [ "$1" = "--version" ]; then echo "ClamAV 1.0/123"; exit 0; fi; '
            'cat >/dev/null; echo "stdin: OK"; exit 0',
        ),
    )
    scanner = ClamscanScanner()
    assert "ClamAV 1.0/123" in scanner.engine
    result = scanner.scan(b"hello")
    assert result.verdict == "clean" and result.raw == "stdin: OK"


def test_clamscan_infected(tmp_path, monkeypatch):
    monkeypatch.setattr(
        settings,
        "clamscan_path",
        _write_fake_clamscan(
            tmp_path,
            'if [ "$1" = "--version" ]; then echo "ClamAV 1.0/123"; exit 0; fi; '
            'cat >/dev/null; echo "stdin: Eicar-Test-Signature FOUND"; exit 1',
        ),
    )
    result = ClamscanScanner().scan(b"eicar")
    assert result.verdict == "infected" and result.signature == "Eicar-Test-Signature"


def test_clamscan_error_and_version_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(
        settings,
        "clamscan_path",
        _write_fake_clamscan(
            tmp_path, 'if [ "$1" = "--version" ]; then exit 1; fi; echo "boom" >&2; exit 2'
        ),
    )
    scanner = ClamscanScanner()
    assert scanner.engine == "ClamAV (clamscan)"
    with pytest.raises(ScannerUnavailableError):
        scanner.scan(b"x")


def test_clamscan_available(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "clamscan_path", str(tmp_path / "clamscan"))
    assert ClamscanScanner().available() is False
    monkeypatch.setattr(settings, "clamscan_path", "clamscan")
    assert ClamscanScanner().available() == bool(shutil.which("clamscan"))


def test_get_scanner_modes(monkeypatch):
    monkeypatch.setattr(settings, "clam_mode", "daemon")
    monkeypatch.setattr(ClamdScanner, "available", lambda self: True)
    assert isinstance(get_scanner(), ClamdScanner)

    get_scanner.cache_clear()
    monkeypatch.setattr(settings, "clam_mode", "daemon")
    monkeypatch.setattr(ClamdScanner, "available", lambda self: False)
    with pytest.raises(ScannerUnavailableError):
        get_scanner()

    get_scanner.cache_clear()
    monkeypatch.setattr(settings, "clam_mode", "cli")
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/clamscan")
    assert isinstance(get_scanner(), ClamscanScanner)

    get_scanner.cache_clear()
    monkeypatch.setattr(settings, "clam_mode", "cli")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(ScannerUnavailableError):
        get_scanner()

    get_scanner.cache_clear()
    monkeypatch.setattr(settings, "clam_mode", "auto")
    monkeypatch.setattr(ClamdScanner, "available", lambda self: False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(ScannerUnavailableError):
        get_scanner()

    get_scanner.cache_clear()
    monkeypatch.setattr(settings, "clam_mode", "auto")
    monkeypatch.setattr(ClamdScanner, "available", lambda self: False)
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/bin/clamscan" if name == "clamscan" else None
    )
    assert isinstance(get_scanner(), ClamscanScanner)


def test_get_scanner_clamd_alias_and_unknown_mode_fallback(monkeypatch):
    # "clamd" is a common value users set — must behave like "daemon", not skip clamd
    monkeypatch.setattr(settings, "clam_mode", "clamd")
    monkeypatch.setattr(ClamdScanner, "available", lambda self: True)
    assert isinstance(get_scanner(), ClamdScanner)

    get_scanner.cache_clear()
    monkeypatch.setattr(settings, "clam_mode", "clamd")
    monkeypatch.setattr(ClamdScanner, "available", lambda self: False)
    with pytest.raises(ScannerUnavailableError, match=r"CLAM_MODE=clamd"):
        get_scanner()

    get_scanner.cache_clear()
    # unknown mode values fail fast instead of silently guessing a backend
    monkeypatch.setattr(settings, "clam_mode", "bogus")
    with pytest.raises(ScannerUnavailableError, match=r"unknown CLAM_MODE='bogus'"):
        get_scanner()


def test_yara_scanner_empty_and_populated(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "yara_rules_dir", str(tmp_path))
    assert YaraScanner(str(tmp_path)).available() is False
    assert get_yara_scanner() is None

    (tmp_path / "r.yar").write_text("rule R1 { condition: true }")
    scanner = YaraScanner(str(tmp_path))
    assert scanner.available() is True
    assert scanner.scan(b"anything") == ["R1"]
    assert YaraScanner(str(tmp_path / "nonexistent")).scan(b"x") == []
    monkeypatch.setattr(settings, "yara_rules_dir", str(tmp_path))
    get_yara_scanner.cache_clear()
    assert get_yara_scanner() is not None
    monkeypatch.setattr(settings, "yara_rules_dir", "")
    get_yara_scanner.cache_clear()
    assert get_yara_scanner() is None


def test_struct_import_used():
    assert struct.pack(">I", 1) == b"\x00\x00\x00\x01"
    assert scanner_module.struct is struct
