import os
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import threading
from pathlib import Path

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


class FdPassSocket(FakeSocket):
    """Fake AF_UNIX socket that records sendmsg() ancillary data (SCM_RIGHTS fd)."""

    def __init__(self, response: bytes):
        super().__init__(response)
        self.msgs: list[bytes] = []
        self.cmsgs: list[tuple] = []

    def sendmsg(self, data, cmsgs):
        self.msgs.append(b"".join(data))
        self.cmsgs.extend(cmsgs)


def test_clamd_fdpass_over_unix_socket(monkeypatch, tmp_path):
    # with CLAMD_SOCKET set and a stored path, scan() uses FILDES (fd via SCM_RIGHTS),
    # bypassing both StreamMaxLength and app-file permission issues
    monkeypatch.setattr(settings, "clamd_socket", "/tmp/clamd.sock")
    monkeypatch.setattr(settings, "stream_scan_max_size", 8)  # data alone would exceed it
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * 100)
    fake = FdPassSocket(b"OK\x00")
    monkeypatch.setattr(socket, "socket", lambda family, type_: fake)
    result = ClamdScanner().scan(b"x" * 100, path=p)
    assert result.verdict == "clean"
    # zFILDES command first, then a dummy-byte packet carrying the fd via SCM_RIGHTS
    assert fake.msgs == [b"zFILDES\x00", b"\x00"]
    assert any(c[0] == socket.SOL_SOCKET and c[1] == socket.SCM_RIGHTS for c in fake.cmsgs)


def test_clamd_fdpass_infected_and_error(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "clamd_socket", "/tmp/clamd.sock")
    p = tmp_path / "e.bin"
    p.write_bytes(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    fake = FdPassSocket(b"Win.Test.EICAR_HDB-1 FOUND\x00")
    monkeypatch.setattr(socket, "socket", lambda family, type_: fake)
    result = ClamdScanner().scan(b"x", path=p)
    assert result.verdict == "infected" and result.signature == "Win.Test.EICAR_HDB-1"
    fake2 = FdPassSocket(b"Access denied. ERROR\x00")
    monkeypatch.setattr(socket, "socket", lambda family, type_: fake2)
    with pytest.raises(ScannerUnavailableError, match="unexpected clamd response"):
        ClamdScanner().scan(b"x", path=p)
    # clamd closes the connection without answering -> empty response, same error
    fake3 = FdPassSocket(b"")
    monkeypatch.setattr(socket, "socket", lambda family, type_: fake3)
    with pytest.raises(ScannerUnavailableError, match="unexpected clamd response"):
        ClamdScanner().scan(b"x", path=p)


def test_clamd_scan_routes_without_socket_or_path(monkeypatch):
    # no CLAMD_SOCKET / no path -> INSTREAM for small, file-based SCAN for large
    monkeypatch.setattr(settings, "clamd_socket", None)
    monkeypatch.setattr(settings, "stream_scan_max_size", 8)
    fake = FakeSocket(b"stream: OK\x00")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    assert ClamdScanner().scan(b"12345").verdict == "clean"
    assert fake.sent.startswith(b"zINSTREAM\x00")


def test_clamscan_scans_stored_path_directly(monkeypatch, tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    calls = []

    def fake_run(cmd, input=None, **kwargs):
        calls.append((cmd, input))
        if "--version" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "ClamAV 1.0", "")
        return subprocess.CompletedProcess(cmd, 1, b"path: Win.Test.EICAR_HDB-1 FOUND\n", b"")

    monkeypatch.setattr(shutil, "which", lambda p: "/usr/bin/clamscan")
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = ClamscanScanner().scan(b"ignored", path=p)
    assert result.verdict == "infected"
    assert calls[-1][0][-1] == str(p) and calls[-1][1] is None  # path arg, no stdin


def test_yara_scanner_matches_filepath(monkeypatch, tmp_path):
    (tmp_path / "r.yar").write_text("rule r1 { condition: true }")
    monkeypatch.setattr(settings, "yara_rules_dir", str(tmp_path))
    p = tmp_path / "f.bin"
    p.write_bytes(b"whatever")
    assert YaraScanner(str(tmp_path)).scan(b"whatever", path=p) == ["r1"]
    assert YaraScanner(str(tmp_path)).scan(b"whatever") == ["r1"]


@pytest.fixture(autouse=True)
def clear_caches(monkeypatch):
    get_scanner.cache_clear()
    get_yara_scanner.cache_clear()
    monkeypatch.setattr(scanner_module.time, "sleep", lambda s: None)  # keep retry loop fast
    yield
    get_scanner.cache_clear()
    get_yara_scanner.cache_clear()


def test_clamd_tcp_clean(monkeypatch):
    # real clamd z-command responses are NUL-terminated ("stream: OK\x00")
    fake = FakeSocket(b"stream: OK\x00")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    result = ClamdScanner().scan(b"data")
    assert result.verdict == "clean" and result.signature is None
    assert fake.sent.startswith(b"zINSTREAM\0")


def test_clamd_tcp_infected(monkeypatch):
    fake = FakeSocket(b"stream: Win.Test.EICAR_HDB-1 FOUND\x00")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    result = ClamdScanner().scan(b"data")
    assert result.verdict == "infected" and result.signature == "Win.Test.EICAR_HDB-1"


def test_clamd_newline_terminated_response_also_accepted(monkeypatch):
    monkeypatch.setattr(
        socket, "create_connection", lambda addr, timeout=None: FakeSocket(b"stream: OK\n")
    )
    result = ClamdScanner().scan(b"data")
    assert result.verdict == "clean"


def test_clamd_unexpected_response(monkeypatch):
    fake = FakeSocket(b"INSTREAM size limit exceeded\x00")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    with pytest.raises(ScannerUnavailableError, match="StreamMaxLength"):
        ClamdScanner().scan(b"data")


def test_clamd_large_file_scanned_via_temp_file(monkeypatch, tmp_path):
    # above STREAM_SCAN_MAX_SIZE the sample goes through zSCAN <path>, not INSTREAM
    monkeypatch.setattr(settings, "stream_scan_max_size", 8)
    scan_dir = Path(settings.upload_dir) / ".clamd-scan"
    mkstemp_calls: list[dict] = []

    def fake_mkstemp(prefix="", dir=None):
        mkstemp_calls.append({"prefix": prefix, "dir": dir})
        return (
            os.open(str(tmp_path / "s.bin"), os.O_CREAT | os.O_WRONLY),
            str(tmp_path / "s.bin"),
        )

    monkeypatch.setattr(tempfile, "mkstemp", fake_mkstemp)

    class RecordingSocket(FakeSocket):
        def __init__(self):
            super().__init__(b"/tmp/x: Win.Test.EICAR_HDB-1 FOUND\x00")
            self.cmds: list[bytes] = []

        def sendall(self, data: bytes) -> None:
            self.cmds.append(data)
            # by the time clamd is asked to SCAN, the temp file must be world-readable
            # (clamd usually runs as a different user than the app)
            assert stat.S_IMODE(os.stat(tmp_path / "s.bin").st_mode) == 0o644
            super().sendall(data)

    fake = RecordingSocket()
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    result = ClamdScanner().scan(b"this is definitely larger than 8 bytes")
    assert result.verdict == "infected" and result.signature == "Win.Test.EICAR_HDB-1"
    assert fake.cmds[0].startswith(b"zSCAN ")  # file-based command, not zINSTREAM
    assert not (tmp_path / "s.bin").exists()  # temp file removed after scan
    # temp file lives in UPLOAD_DIR/.clamd-scan (traversable by the clamd user), not /tmp
    assert mkstemp_calls[0]["dir"] == scan_dir
    assert scan_dir.is_dir()
    # dirs are explicitly chmod'ed 0755 (umask-proof) so the clamd user can traverse them
    assert stat.S_IMODE(os.stat(scan_dir).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(settings.upload_dir).st_mode) == 0o755


def test_clamd_large_file_access_denied_has_clear_error(monkeypatch, tmp_path):
    # clamd running as another user cannot read a 0600 /tmp file -> "Access denied. ERROR"
    monkeypatch.setattr(settings, "stream_scan_max_size", 4)
    monkeypatch.setattr(
        tempfile,
        "mkstemp",
        lambda prefix="", dir=None: (
            os.open(str(tmp_path / "a.bin"), os.O_CREAT | os.O_WRONLY),
            str(tmp_path / "a.bin"),
        ),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda addr, timeout=None: FakeSocket(b"/x: Access denied. ERROR\x00"),
    )
    with pytest.raises(ScannerUnavailableError, match="clamd cannot read the temp scan file"):
        ClamdScanner().scan(b"12345")


def test_clamd_large_file_clean_via_temp_file(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "stream_scan_max_size", 4)
    monkeypatch.setattr(
        tempfile,
        "mkstemp",
        lambda prefix="", dir=None: (
            os.open(str(tmp_path / "c.bin"), os.O_CREAT | os.O_WRONLY),
            str(tmp_path / "c.bin"),
        ),
    )
    monkeypatch.setattr(
        socket, "create_connection", lambda addr, timeout=None: FakeSocket(b"/tmp/x: OK\x00")
    )
    result = ClamdScanner().scan(b"12345")
    assert result.verdict == "clean"


def test_clamd_large_file_size_limit_and_unexpected(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "stream_scan_max_size", 4)
    monkeypatch.setattr(
        tempfile,
        "mkstemp",
        lambda prefix="", dir=None: (
            os.open(str(tmp_path / "x.bin"), os.O_CREAT | os.O_WRONLY),
            str(tmp_path / "x.bin"),
        ),
    )
    # clamd rejects the file itself (StreamMaxLength) -> clear error
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda addr, timeout=None: FakeSocket(b"x: INSTREAM size limit exceeded\x00"),
    )
    with pytest.raises(ScannerUnavailableError, match="StreamMaxLength"):
        ClamdScanner().scan(b"12345")
    # anything else unexpected
    monkeypatch.setattr(
        socket, "create_connection", lambda addr, timeout=None: FakeSocket(b"x: weird\x00")
    )
    with pytest.raises(ScannerUnavailableError, match="unexpected clamd response"):
        ClamdScanner().scan(b"12345")
    # connection closed before any response -> break path
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: FakeSocket(b""))
    with pytest.raises(ScannerUnavailableError, match="unexpected clamd response"):
        ClamdScanner().scan(b"12345")


def test_clamd_small_file_uses_instream(monkeypatch):
    monkeypatch.setattr(settings, "stream_scan_max_size", 1024)
    fake = FakeSocket(b"stream: OK\x00")
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    ClamdScanner().scan(b"small")
    assert fake.sent.startswith(b"zINSTREAM\0")


def test_clamd_available_and_unavailable(monkeypatch):
    # available() does a real INSTREAM PING and requires PONG
    monkeypatch.setattr(
        socket, "create_connection", lambda addr, timeout=None: FakeSocket(b"PONG\x00")
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


def test_yara_scanner_combines_rule_files_into_one_rules_object(tmp_path):
    # duplicate rule names across files are fine: each file gets its own namespace
    (tmp_path / "a.yar").write_text("rule Same { condition: true }")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.yara").write_text("rule Same { condition: true }")
    scanner = YaraScanner(str(tmp_path))
    assert scanner._combined is not None and scanner._per_file == []
    assert scanner.scan(b"x") == ["Same"]


def test_yara_scanner_skips_broken_files_and_allows_duplicate_rule_names(tmp_path):
    (tmp_path / "broken.yar").write_text("rule Broken { condition: }")  # invalid syntax
    (tmp_path / "a.yar").write_text("rule Same { condition: true }")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.yara").write_text("rule Same { condition: true }")
    scanner = YaraScanner(str(tmp_path))
    # combined compile fails on the broken file -> per-file fallback, broken file skipped
    assert scanner._combined is None and len(scanner._per_file) == 2
    assert scanner.available() is True
    assert scanner.scan(b"x") == ["Same"]
    # fallback matches also run (via the thread pool) against a stored file path
    p = tmp_path / "f.bin"
    p.write_bytes(b"x")
    assert scanner.scan(b"x", path=p) == ["Same"]


def test_yara_scanner_hot_reloads_on_stamp_change(tmp_path):
    (tmp_path / "a.yar").write_text("rule R1 { condition: true }")
    scanner = YaraScanner(str(tmp_path))
    assert scanner.scan(b"x") == ["R1"]
    # new rule file without a stamp change is NOT picked up yet
    (tmp_path / "b.yar").write_text("rule R2 { condition: true }")
    assert scanner.scan(b"x") == ["R1"]
    # update-yara-rules.sh touches .rules-stamp -> recompile in a background thread
    stamp = tmp_path / ".rules-stamp"
    stamp.touch()
    scanner.scan(b"x")  # triggers the background reload
    reloading = scanner._reloading
    assert reloading is not None
    reloading.join()
    assert scanner.scan(b"x") == ["R1", "R2"]
    # stamp removed (e.g. rules dir replaced) -> recompile as well
    stamp.unlink()
    (tmp_path / "c.yar").write_text("rule R3 { condition: true }")
    scanner.scan(b"x")
    reloading = scanner._reloading
    assert reloading is not None
    reloading.join()
    assert scanner.scan(b"x") == ["R1", "R2", "R3"]


def test_yara_scanner_reload_is_background_and_does_not_block_scans(tmp_path, monkeypatch):
    (tmp_path / "a.yar").write_text("rule R1 { condition: true }")
    scanner = YaraScanner(str(tmp_path))
    assert scanner.scan(b"x") == ["R1"]
    (tmp_path / "b.yar").write_text("rule R2 { condition: true }")
    (tmp_path / ".rules-stamp").touch()
    # make the recompile block until we release it: scans must still answer (old rules)
    real_compile = scanner_module.yara.compile
    entered = threading.Event()
    release = threading.Event()

    def slow_compile(*args, **kwargs):
        entered.set()
        release.wait(timeout=10)
        return real_compile(*args, **kwargs)

    monkeypatch.setattr(scanner_module.yara, "compile", slow_compile)
    assert scanner.scan(b"x") == ["R1"]  # reload running in background
    assert scanner.scan(b"x") == ["R1"]  # second scan: reload already in flight
    assert entered.wait(timeout=5)
    release.set()
    reloading = scanner._reloading
    assert reloading is not None
    reloading.join()
    monkeypatch.setattr(scanner_module.yara, "compile", real_compile)
    assert scanner.scan(b"x") == ["R1", "R2"]


def test_struct_import_used():
    assert struct.pack(">I", 1) == b"\x00\x00\x00\x01"
    assert scanner_module.struct is struct
