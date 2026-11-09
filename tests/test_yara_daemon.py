import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from app.config import settings
from app.scanner import (
    ScannerUnavailableError,
    YaraDaemonClient,
    get_yara_scanner,
    reset_yara_cache,
)
from app.yara_daemon import handle_conn, main, serve


@pytest.fixture
def daemon(tmp_path):
    """A real yara daemon serving a one-rule set on a tmp Unix socket."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yar").write_text('rule R1 { strings: $m = "MALWARE-MARKER-XYZ" condition: $m }')
    sock_path = str(tmp_path / "yara.sock")
    threading.Thread(target=serve, args=(str(rules), sock_path), daemon=True).start()
    for _ in range(100):  # wait until the socket accepts connections
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(sock_path)
            break
        except OSError:
            time.sleep(0.05)
    else:
        pytest.fail("yara daemon did not start")
    yield rules, sock_path
    reset_yara_cache()


class _FakeSock:
    """Minimal socket stand-in for YaraDaemonClient._connect(): records sent bytes,
    replays a fixed NUL-terminated response."""

    def __init__(self, response):
        self.response = response
        self.sent = b""

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


def _raw(sock_path, payload, read=True):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(payload)
        if not read:
            return b""
        resp = b""
        while b"\x00" not in resp:
            part = s.recv(65536)
            if not part:
                break
            resp += part
        return resp.replace(b"\x00", b"")


def test_client_ping_and_version(daemon):
    client = YaraDaemonClient(daemon[1])
    assert client.available() is True
    assert client.version() == f"yara {__import__('yara').__version__}"


def test_client_unavailable_when_no_daemon(tmp_path):
    client = YaraDaemonClient(str(tmp_path / "missing.sock"))
    assert client.available() is False
    assert client.version() is None


def test_client_uses_yara_daemon_timeout(monkeypatch):
    # the daemon client socket timeout comes from YARA_DAEMON_TIMEOUT, not CLAMD_TIMEOUT
    monkeypatch.setattr(settings, "yara_daemon_timeout", 123.0)
    seen = {}

    class FakeSock:
        def connect(self, addr):
            pass

        def settimeout(self, t):
            seen["t"] = t

    monkeypatch.setattr(socket, "socket", lambda family, type_: FakeSock())
    YaraDaemonClient("/tmp/x.sock")._connect()
    assert seen["t"] == 123.0


def test_client_recv_handles_server_closing_without_nul(tmp_path):
    # server accepts then closes without any NUL-terminated response
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock_path = str(tmp_path / "x.sock")
    srv.bind(sock_path)
    srv.listen(1)

    def accept_and_close():
        conn, _ = srv.accept()
        conn.recv(64)  # consume the command so close() is a clean FIN, not RST
        conn.close()

    threading.Thread(target=accept_and_close, daemon=True).start()
    client = YaraDaemonClient(sock_path)
    assert client._roundtrip(b"zPING\0") == b""
    assert client.available() is False
    srv.close()


def test_scan_by_path_and_by_instream(daemon, tmp_path):
    rules, sock_path = daemon
    client = YaraDaemonClient(sock_path)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"xx MALWARE-MARKER-XYZ yy")
    assert client.scan(b"ignored", path=sample) == ["R1"]
    assert client.scan(b"xx MALWARE-MARKER-XYZ yy") == ["R1"]  # INSTREAM path
    assert client.scan(b"nothing here") == []


def test_scan_error_response_raises(daemon, monkeypatch):
    client = YaraDaemonClient(daemon[1])
    monkeypatch.setattr(client, "_connect", lambda: _FakeSock(b"ERROR broken rule\x00"))
    with pytest.raises(ScannerUnavailableError, match="ERROR broken rule"):
        client.scan(b"data")  # INSTREAM branch parses the ERROR reply


def test_client_scan_falls_back_to_instream_when_scanpath_fails(daemon, monkeypatch, tmp_path):
    # the sample vanished between the client's exists() check and the daemon's mmap:
    # zSCANPATH fails, the client must rescan the in-memory bytes via zINSTREAM
    client = YaraDaemonClient(daemon[1])
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"data")

    def boom(payload, timeout=None):
        raise ScannerUnavailableError("ERROR could not open file")

    monkeypatch.setattr(client, "_roundtrip", boom)
    monkeypatch.setattr(client, "_connect", lambda: _FakeSock(b'["R1"]\x00'))
    assert client.scan(b"data", path=sample) == ["R1"]


def test_scan_garbled_response_raises(daemon, monkeypatch):
    # daemon died mid-scan without answering (empty reply) or sent garbage:
    # the client must raise ScannerUnavailableError, not json.JSONDecodeError
    client = YaraDaemonClient(daemon[1])
    for garbage in (b"\x00", b"not json\x00"):
        monkeypatch.setattr(client, "_connect", lambda g=garbage: _FakeSock(g))
        with pytest.raises(ScannerUnavailableError, match="invalid response"):
            client.scan(b"data")


def test_scanpath_scan_failure_replies_error_over_socket(tmp_path, monkeypatch):
    # a scan failure that is NOT the vanished-file fallback (which the in-process
    # YaraScanner already retries on the bytes) must come back as an ERROR reply,
    # not kill the handler thread silently
    import yara  # ty: ignore[import-not-found]  # compiled extension, no stubs

    from app.scanner import YaraScanner

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yar").write_text("rule R1 { condition: true }")
    sock_path = str(tmp_path / "y.sock")

    def boom(self, data, path=None):
        raise yara.Error("could not open file /x")

    monkeypatch.setattr(YaraScanner, "scan", boom)
    threading.Thread(target=serve, args=(str(rules), sock_path), daemon=True).start()
    for _ in range(100):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(sock_path)
            break
        except OSError:
            time.sleep(0.05)
    else:
        pytest.fail("yara daemon did not start")
    resp = _raw(sock_path, b"zSCANPATH /x\0")
    assert resp.startswith(b"ERROR ")
    assert "could not open file" in resp.decode(errors="replace")


def test_handle_conn_scan_error_reply_and_send_failure(monkeypatch):
    import yara  # ty: ignore[import-not-found]  # compiled extension, no stubs

    class BoomScanner:
        engine = "YARA (local rules)"
        rules_count = 0
        rules_updated_at = None

        def scan(self, data, path=None):
            raise yara.Error("could not open file /x")

    class FakeConn:
        def __init__(self, fail_send=False):
            self._cmd = b"zSCANPATH /x\x00"
            self._i = 0
            self.sent = b""
            self.fail_send = fail_send

        def recv(self, n):
            if self._i >= len(self._cmd):
                return b""
            byte = self._cmd[self._i : self._i + 1]
            self._i += 1
            return byte

        def sendall(self, data):
            if self.fail_send:
                raise OSError("client gone")
            self.sent += data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    conn = FakeConn()
    handle_conn(conn, BoomScanner())  # ty: ignore[invalid-argument-type]
    assert conn.sent == b"ERROR could not open file /x\x00"
    # the ERROR reply itself failing (client vanished) must not crash the handler
    handle_conn(FakeConn(fail_send=True), BoomScanner())  # ty: ignore[invalid-argument-type]


def test_stats_and_unknown_command(daemon):
    _, sock_path = daemon
    stats = json.loads(_raw(sock_path, b"zSTATS\0"))
    assert stats["rules"] == 1 and stats["engine"] == "YARA (local rules)"
    assert stats["version"] and stats["rules_updated_at"] is not None
    assert _raw(sock_path, b"zBOGUS\0") == b"ERROR unknown command"


def test_instream_eof_mid_chunk_is_swallowed(daemon):
    # client disconnects mid-INSTREAM: server thread must not crash (OSError branch)
    _, sock_path = daemon
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(b"zINSTREAM\0" + struct.pack(">I", 100) + b"short")
    time.sleep(0.2)  # let the server thread hit the EOF


def test_get_yara_scanner_uses_daemon_socket(daemon, monkeypatch):
    rules, sock_path = daemon
    monkeypatch.setattr(settings, "yara_socket", sock_path)
    monkeypatch.setattr(settings, "yara_rules_dir", str(rules))
    reset_yara_cache()
    client = get_yara_scanner()
    assert isinstance(client, YaraDaemonClient)
    assert client.scan(b"MALWARE-MARKER-XYZ") == ["R1"]


def test_get_yara_scanner_daemon_down_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "yara_socket", str(tmp_path / "missing.sock"))
    reset_yara_cache()
    assert get_yara_scanner() is None


def test_get_yara_scanner_recovers_when_daemon_comes_up_later(daemon, monkeypatch, tmp_path):
    # the failure must NOT be cached: once the daemon starts answering, the next call
    # must pick it up without a worker restart (lru_cache used to freeze None forever)
    rules, sock_path = daemon
    missing = str(tmp_path / "later.sock")
    monkeypatch.setattr(settings, "yara_socket", missing)
    reset_yara_cache()
    assert get_yara_scanner() is None
    monkeypatch.setattr(settings, "yara_socket", sock_path)
    client = get_yara_scanner()
    assert isinstance(client, YaraDaemonClient)
    assert client.scan(b"MALWARE-MARKER-XYZ") == ["R1"]
    assert get_yara_scanner() is client  # success is memoized
    reset_yara_cache()


def test_healthz_reports_yara_daemon(client, daemon, monkeypatch):
    import app.main as main_module  # noqa: F401  (client fixture already booted the app)

    rules, sock_path = daemon
    monkeypatch.setattr(settings, "yara_socket", sock_path)
    monkeypatch.setattr(settings, "yara_rules_dir", str(rules))
    reset_yara_cache()
    body = client.get("/healthz").json()
    yara_eng = body["engines"][1]
    assert yara_eng["name"] == "YARA (daemon)"
    assert yara_eng["enabled"] and yara_eng["ready"] and yara_eng["rules"] == 1


def test_mem_info(monkeypatch):
    from app.yara_daemon import _mem_info

    rss, limit = _mem_info()
    assert rss is not None and rss > 0  # real /proc on Linux

    def no_proc(self):
        raise OSError("no proc")

    monkeypatch.setattr(Path, "read_text", no_proc)
    assert _mem_info() == (None, None)

    monkeypatch.setattr(
        Path, "read_text", lambda self: "VmRSS:\t 102400 kB\n" if "status" in str(self) else "max"
    )
    assert _mem_info() == (100.0, "max")


def test_healthz_detail_when_daemon_down(client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "yara_socket", str(tmp_path / "missing.sock"))
    monkeypatch.setattr(settings, "yara_rules_dir", "")
    reset_yara_cache()
    body = client.get("/healthz").json()
    yara_eng = body["engines"][1]
    assert yara_eng["enabled"] and yara_eng["ready"] is False
    assert "missing.sock" in yara_eng["detail"]
    reset_yara_cache()


def test_main_parses_args(monkeypatch, tmp_path):
    import app.yara_daemon as yd

    called = {}
    monkeypatch.setattr(yd, "serve", lambda r, s: called.update(rules=r, socket=s))
    monkeypatch.setattr(
        sys, "argv", ["yara_daemon", "--rules", str(tmp_path), "--socket", "/tmp/x.sock"]
    )
    main()
    assert called == {"rules": str(tmp_path), "socket": "/tmp/x.sock"}


def test_handle_conn_is_the_server_handler(daemon):
    # handle_conn is what each accepted connection runs; smoke it directly
    rules, sock_path = daemon
    from app.scanner import YaraScanner

    scanner = YaraScanner(str(rules))
    c1, c2 = socket.socketpair()
    threading.Thread(target=handle_conn, args=(c1, scanner), daemon=True).start()
    c2.sendall(b"zPING\0")
    assert c2.recv(64) == b"PONG\x00"
    c2.close()
