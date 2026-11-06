"""Feed daemon: unix-socket server over its own feed DB + the app-side client."""

import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

import app.domain_feed as feed_mod
from app.config import settings
from app.domain_feed import DomainFeedClient, get_domain_feed, reset_domain_feed_cache
from app.feed_daemon import handle_conn, main, serve


@pytest.fixture
def daemon(tmp_path):
    """A real feed daemon serving a small seeded feed on a tmp Unix socket."""
    feed_dir = tmp_path / "feed"
    feed_dir.mkdir()
    (feed_dir / "tif.txt").write_text("# clamtotal-category: malware\n*.evil-example.com\n")
    (feed_dir / "gambling.txt").write_text(
        "# clamtotal-category: gambling\n0.0.0.0 casino-example.com\n"
    )
    (feed_dir / feed_mod.STAMP_NAME).touch()
    db_path = str(feed_dir / "feed.db")
    sock_path = str(tmp_path / "feed.sock")
    threading.Thread(target=serve, args=(str(feed_dir), db_path, sock_path), daemon=True).start()
    for _ in range(100):  # wait until the socket accepts connections
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(sock_path)
            break
        except OSError:
            time.sleep(0.05)
    else:
        pytest.fail("feed daemon did not start")
    yield feed_dir, db_path, sock_path
    reset_domain_feed_cache()


def _raw(sock_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(payload)
        resp = b""
        while b"\x00" not in resp:
            part = s.recv(65536)
            if not part:
                break
            resp += part
        return resp.replace(b"\x00", b"")


def test_daemon_uses_separate_db_and_serves_lookups(daemon):
    feed_dir, db_path, sock_path = daemon
    assert Path(db_path).is_file()  # feed.db — separate from the app database
    client = DomainFeedClient(sock_path)
    assert client.available() is True
    version = client.version()
    assert version is not None and "2 entries" in version
    assert client.lookup("www.evil-example.com") == [
        {"domain": "evil-example.com", "source": "tif", "category": "malware"}
    ]
    assert {m["category"] for m in client.lookup("casino-example.com")} == {"gambling"}
    assert client.lookup("clean-example.com") == []
    entries, updated = client.stats()
    assert entries == 2 and updated is not None


def test_client_unavailable_when_no_daemon(tmp_path):
    client = DomainFeedClient(str(tmp_path / "missing.sock"))
    assert client.available() is False
    assert client.version() is None
    assert client.stats() == (0, None)


def test_get_domain_feed_recovers_when_daemon_comes_up_later(daemon, monkeypatch, tmp_path):
    # the failure must NOT be cached: once the daemon answers, the next call must pick
    # it up without a worker restart (lru_cache used to freeze None forever)
    _, _, sock_path = daemon
    monkeypatch.setattr(settings, "domain_feed_socket", str(tmp_path / "later.sock"))
    reset_domain_feed_cache()
    assert get_domain_feed() is None
    monkeypatch.setattr(settings, "domain_feed_socket", sock_path)
    feed = get_domain_feed()
    assert isinstance(feed, DomainFeedClient)
    assert feed.stats()[0] == 2
    assert get_domain_feed() is feed  # success is memoized
    reset_domain_feed_cache()


def test_client_recv_handles_server_closing_without_nul(tmp_path):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock_path = str(tmp_path / "x.sock")
    srv.bind(sock_path)
    srv.listen(1)

    def accept_and_close():
        conn, _ = srv.accept()
        conn.recv(64)
        conn.close()

    threading.Thread(target=accept_and_close, daemon=True).start()
    client = DomainFeedClient(sock_path)
    assert client._roundtrip(b"zPING\0") == b""
    assert client.available() is False
    srv.close()


def test_client_lookup_error_response_raises(daemon, monkeypatch):
    client = DomainFeedClient(daemon[2])
    monkeypatch.setattr(client, "_roundtrip", lambda payload: b"ERROR broken")
    with pytest.raises(RuntimeError, match="ERROR broken"):
        client.lookup("x.com")


def test_stats_version_and_unknown_command_over_raw_socket(daemon):
    _, _, sock_path = daemon
    stats = json.loads(_raw(sock_path, b"zSTATS\0"))
    assert stats == {
        "engine": "Domain feed",
        "entries": 2,
        "updated_at": stats["updated_at"],
    }
    assert stats["updated_at"] is not None
    assert _raw(sock_path, b"zVERSION\0").startswith(b"domain-feed (2 entries)")
    assert _raw(sock_path, b"zPING\0") == b"PONG"
    assert _raw(sock_path, b"zBOGUS\0") == b"ERROR unknown command"


def test_disconnect_mid_command_is_swallowed(daemon):
    # client disconnects right after sending a partial command: server thread must
    # not crash (OSError branch in handle_conn)
    _, _, sock_path = daemon
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall(b"zLOOK")
    time.sleep(0.2)
    assert DomainFeedClient(sock_path).available() is True  # daemon still alive


def test_handle_conn_directly_via_socketpair(tmp_path):
    feed_dir = tmp_path / "feed"
    feed_dir.mkdir()
    (feed_dir / "l.txt").write_text("# clamtotal-category: malware\nbad-example.com\n")
    f = feed_mod.DomainFeed(str(feed_dir))
    c1, c2 = socket.socketpair()
    threading.Thread(target=handle_conn, args=(c1, f), daemon=True).start()
    c2.sendall(b"zLOOKUP bad-example.com\0")
    resp = b""
    while b"\x00" not in resp:
        resp += c2.recv(4096)
    assert json.loads(resp.replace(b"\x00", b""))[0]["domain"] == "bad-example.com"
    c2.close()


def test_get_domain_feed_uses_daemon_socket(daemon, monkeypatch):
    _, _, sock_path = daemon
    monkeypatch.setattr(settings, "domain_feed_socket", sock_path)
    reset_domain_feed_cache()
    client = get_domain_feed()
    assert isinstance(client, DomainFeedClient)
    assert client.lookup("evil-example.com")[0]["category"] == "malware"


def test_healthz_reports_feed_daemon(client, daemon, monkeypatch):
    _, _, sock_path = daemon
    monkeypatch.setattr(settings, "domain_feed_socket", sock_path)
    reset_domain_feed_cache()
    body = client.get("/healthz").json()
    feed_eng = body["engines"][2]
    assert feed_eng["type"] == "domain-feed"
    assert feed_eng["name"] == "Domain feed (daemon)"
    assert feed_eng["enabled"] and feed_eng["ready"] and feed_eng["rules"] == 2


def test_main_parses_args(monkeypatch, tmp_path):
    import app.feed_daemon as fd

    called = {}
    monkeypatch.setattr(fd, "serve", lambda d, db, s: called.update(feed=d, db=db, socket=s))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "feed_daemon",
            "--feed-dir",
            str(tmp_path),
            "--db",
            str(tmp_path / "feed.db"),
            "--socket",
            "/tmp/x.sock",
        ],
    )
    main()
    assert called == {
        "feed": str(tmp_path),
        "db": str(tmp_path / "feed.db"),
        "socket": "/tmp/x.sock",
    }
