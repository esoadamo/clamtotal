import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from app.config import settings
from app.scanner import ScannerUnavailableError, YaraDaemonClient, get_yara_scanner
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
    get_yara_scanner.cache_clear()


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


def test_scan_error_response_raises(daemon, monkeypatch, tmp_path):
    client = YaraDaemonClient(daemon[1])
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    monkeypatch.setattr(client, "_roundtrip", lambda payload: b"ERROR broken rule")
    with pytest.raises(ScannerUnavailableError, match="ERROR broken rule"):
        client.scan(b"data", path=sample)  # path branch goes through _roundtrip


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
    get_yara_scanner.cache_clear()
    client = get_yara_scanner()
    assert isinstance(client, YaraDaemonClient)
    assert client.scan(b"MALWARE-MARKER-XYZ") == ["R1"]


def test_get_yara_scanner_daemon_down_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "yara_socket", str(tmp_path / "missing.sock"))
    get_yara_scanner.cache_clear()
    assert get_yara_scanner() is None


def test_healthz_reports_yara_daemon(client, daemon, monkeypatch):
    import app.main as main_module  # noqa: F401  (client fixture already booted the app)

    rules, sock_path = daemon
    monkeypatch.setattr(settings, "yara_socket", sock_path)
    monkeypatch.setattr(settings, "yara_rules_dir", str(rules))
    get_yara_scanner.cache_clear()
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
