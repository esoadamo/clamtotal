"""URL/domain scanning against the domain feed: parsing, import into the separate feed
DB, normalization, lookup, routes, and the healthz feed engine entry."""

import base64
import hashlib
import logging
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import func, select

import app.domain_feed as feed
from app.config import settings
from app.db import SessionLocal
from app.domain_feed import (
    DomainFeed,
    get_domain_feed,
    normalize_url_input,
    parse_feed_line,
    reset_domain_feed_cache,
    scan_url,
)
from app.models import UrlScan
from app.scanner import ScannerUnavailableError, reset_yara_cache


@pytest.fixture
def feed_dir(tmp_path, monkeypatch):
    d = tmp_path / "domain-feed"
    d.mkdir()
    monkeypatch.setattr(settings, "domain_feed_dir", str(d))
    monkeypatch.setattr(settings, "domain_feed_socket", "")
    reset_domain_feed_cache()
    yield d
    reset_domain_feed_cache()


def _seed(d: Path) -> None:
    (d / "hagezi-tif.txt").write_text(
        "# Title: test\n"
        "# clamtotal-category: malware\n"
        "*.evil-example.com\n"
        "badhost.net\n"
        "# comment\n"
        "\n"
    )
    (d / "gambling.txt").write_text(
        "# clamtotal-category: gambling\n0.0.0.0 casino-example.com\n||ads-example.org^\n"
    )
    (d / feed.STAMP_NAME).touch()


def _norm(value: str, require_tld: bool = False) -> tuple[str, str, str]:
    result = normalize_url_input(value, require_tld=require_tld)
    assert result is not None, value
    return result


# ---------------------------------------------------------------- parsing


def test_parse_feed_line_formats():
    assert parse_feed_line("example.com") == "example.com"
    assert parse_feed_line("*.sub.example.com") == "sub.example.com"
    assert parse_feed_line("0.0.0.0 example.com") == "example.com"
    assert parse_feed_line("127.0.0.1 example.com.") == "example.com"
    assert parse_feed_line("::1 localhost") is None  # IPv6 hosts entry -> localhost skip
    assert parse_feed_line("||example.com^$third-party") == "example.com"
    assert parse_feed_line("EXAMPLE.COM") == "example.com"
    assert parse_feed_line("192.168.0.1") == "192.168.0.1"  # bare IP entry kept
    assert parse_feed_line("# comment") is None
    assert parse_feed_line("   ") is None
    assert parse_feed_line("0.0.0.0 0.0.0.0") is None
    assert parse_feed_line("0.0.0.0 localhost") is None
    assert parse_feed_line("not a host line") is None  # multi-token, first not an IP
    assert parse_feed_line("bad_domain!.com") is None
    assert parse_feed_line("nodot") is None
    assert parse_feed_line("*.") is None


# ---------------------------------------------------------------- normalize


def test_normalize_url_input_full_urls():
    assert _norm("https://Sub.Example.COM/path?q=1#frag") == (
        base64.urlsafe_b64encode(b"https://sub.example.com/path?q=1").decode().rstrip("="),
        "https://sub.example.com/path?q=1",
        "sub.example.com",
    )
    # default ports are dropped, explicit ports kept
    _, url, host = _norm("http://example.com:80/a")
    assert url == "http://example.com/a" and host == "example.com"
    _, url, host = _norm("http://example.com:8080/a")
    assert url == "http://example.com:8080/a" and host == "example.com"
    # bare host and host/path
    assert _norm("example.com")[2] == "example.com"
    assert _norm("example.com/payload")[1] == "http://example.com/payload"
    # IP hosts work
    assert _norm("http://185.220.101.4/x")[2] == "185.220.101.4"
    # trailing dot stripped
    assert _norm("example.com.")[2] == "example.com"


def test_normalize_url_input_rejects_junk():
    for bad in [
        "",
        "   ",
        "x" * 2049,  # over MAX_URL_INPUT
        "user@example.com",  # email, not a URL
        "has space.com",
        "ftp://",  # no host
        "gopher://example.com",  # unsupported scheme
        "http://exa mple.com",
        "http://-bad-.com",
        "http://example.com:99999",  # invalid port
        "nodot",
    ]:
        assert normalize_url_input(bad) is None, bad


def test_normalize_url_require_tld():
    # search-box auto-detection: only real IANA TLDs become URL checks
    assert normalize_url_input("notes.txt", require_tld=True) is None
    assert _norm("evil-example.com", require_tld=True)[2] == "evil-example.com"
    assert _norm("185.220.101.4", require_tld=True)[2] == "185.220.101.4"  # IPs pass
    # explicit submissions accept any syntactically valid dotted host
    assert _norm("myserver.local")[2] == "myserver.local"


# ---------------------------------------------------------------- feed DB (separate from app DB)


def test_feed_uses_its_own_database(feed_dir):
    _seed(feed_dir)
    f = DomainFeed(str(feed_dir))
    assert feed_dir.joinpath(feed.FEED_DB_NAME).is_file()  # feed.db, not the app DB
    count, updated = f.stats()
    assert count == 4 and updated is not None
    assert f.available() is True
    assert "4 entries" in f.version()


def test_lookup_wildcard_and_multi_source(feed_dir):
    _seed(feed_dir)
    f = DomainFeed(str(feed_dir))
    # exact + parent walk: listed 'evil-example.com' blocks deep subdomains
    m = f.lookup("www.evil-example.com")
    assert m == [{"domain": "evil-example.com", "source": "hagezi-tif", "category": "malware"}]
    assert f.lookup("evil-example.com")[0]["source"] == "hagezi-tif"
    assert {r["category"] for r in f.lookup("casino-example.com")} == {"gambling"}
    assert {r["category"] for r in f.lookup("ads-example.org")} == {"gambling"}
    assert f.lookup("clean-example.com") == []
    assert f.lookup("185.220.101.4") == []  # IP: exact only, no parent walk


def test_import_replaces_and_skips_unreadable(feed_dir, monkeypatch):
    _seed(feed_dir)
    f = DomainFeed(str(feed_dir))
    assert f.stats()[0] == 4
    # re-import replaces, not appends
    (feed_dir / "hagezi-tif.txt").write_text("only-one.example\n")
    (feed_dir / "gambling.txt").unlink()
    assert f.load() == 1
    assert f.stats()[0] == 1
    # unreadable file is skipped
    (feed_dir / "a.txt").write_text("a-example.com\n")
    (feed_dir / "b.txt").write_text("b-example.com\n")
    real_read_text = Path.read_text

    def boom(self, *a, **kw):
        if self.name == "b.txt":
            raise OSError("nope")
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", boom)
    assert f.load() == 2  # only-one.example + a-example.com


def test_import_falls_back_when_lock_not_obtainable(feed_dir, monkeypatch):
    _seed(feed_dir)

    def boom(*args, **kwargs):
        raise OSError("read-only fs")

    monkeypatch.setattr(feed.fcntl, "flock", boom)
    f = DomainFeed(str(feed_dir))
    assert f.stats()[0] == 4  # lock failed -> imported anyway, without the lock


def test_import_missing_dir_is_empty(feed_dir, monkeypatch):
    monkeypatch.setattr(settings, "domain_feed_dir", str(feed_dir / "nope"))
    f = DomainFeed(str(feed_dir / "nope"))
    assert f.stats() == (0, None) and f.available() is False


def test_stamp_value_branches(feed_dir, monkeypatch):
    assert feed.stamp_value(str(feed_dir)) is None  # empty dir, no stamp
    (feed_dir / "x.txt").write_text("x-example.com\n")
    assert feed.stamp_value(str(feed_dir)) is not None  # falls back to newest .txt mtime
    stamp = feed_dir / feed.STAMP_NAME
    stamp.touch()
    assert feed.stamp_value(str(feed_dir)) == stamp.stat().st_mtime_ns  # stamp wins
    assert feed.stamp_value("") is None  # disabled
    assert feed.stamp_value(str(feed_dir / "missing")) is None


def test_reload_if_stamped_branches(feed_dir, monkeypatch, caplog):
    f = DomainFeed(str(feed_dir))
    # same stamp -> no-op
    f.reload_if_stamped()
    assert f._reloading is None
    _seed(feed_dir)
    # reload already running -> no second thread
    release = threading.Event()

    def sleeper():
        release.wait(10)

    t = threading.Thread(target=sleeper, daemon=True)
    f._reloading = t
    t.start()
    f.reload_if_stamped()
    release.set()
    t.join()
    assert f._reloading is t  # untouched
    # stamp changed -> background reload runs and loads the rows
    f._stamp = None
    f._reloading = None
    f.reload_if_stamped()
    assert f._reloading is not None
    f._reloading.join(timeout=30)
    assert f.stats()[0] == 4
    stamp_after = f._stamp
    f._reloading = None
    f.reload_if_stamped()  # same stamp now -> no new thread
    assert f._reloading is None
    assert f._stamp == stamp_after

    # reload failure is logged, not fatal
    def boom_load():
        raise RuntimeError("db locked")

    monkeypatch.setattr(DomainFeed, "load", boom_load)
    f._stamp = None
    with caplog.at_level(logging.ERROR, logger="app.domain_feed"):
        f.reload_if_stamped()
        assert f._reloading is not None
        f._reloading.join(timeout=30)
    assert "domain feed reload failed" in caplog.text


def test_get_domain_feed_resolution(feed_dir, monkeypatch, tmp_path):
    _seed(feed_dir)
    f = get_domain_feed()
    assert isinstance(f, DomainFeed) and f.stats()[0] == 4
    reset_domain_feed_cache()
    # socket set -> client (unavailable socket -> None)
    monkeypatch.setattr(settings, "domain_feed_socket", str(tmp_path / "missing.sock"))
    reset_domain_feed_cache()
    assert get_domain_feed() is None
    # nothing configured -> None
    monkeypatch.setattr(settings, "domain_feed_socket", "")
    monkeypatch.setattr(settings, "domain_feed_dir", "")
    reset_domain_feed_cache()
    assert get_domain_feed() is None
    # init failure -> None (logged), never crashes the app
    monkeypatch.setattr(settings, "domain_feed_dir", str(feed_dir))
    monkeypatch.setattr(
        DomainFeed,
        "__init__",
        lambda self, d, db_path=None: (_ for _ in ()).throw(OSError("no")),
        raising=False,
    )
    reset_domain_feed_cache()
    assert get_domain_feed() is None
    reset_domain_feed_cache()


# ---------------------------------------------------------------- scan_url


def test_scan_url_verdicts_and_cache(feed_dir):
    _seed(feed_dir)
    f = DomainFeed(str(feed_dir))
    with SessionLocal() as db:
        db.execute(__import__("sqlalchemy").delete(UrlScan))
        db.commit()
        hit = scan_url(db, "https://www.evil-example.com/payload", f)
        assert hit is not None and hit.verdict == "malicious"
        assert hit.host == "www.evil-example.com"
        assert hit.matches is not None and hit.matches[0]["category"] == "malware"
        miss = scan_url(db, "example.org", f)
        assert miss is not None and miss.verdict == "harmless" and miss.matches == []
        assert scan_url(db, "not a url at all !!", f) is None
        # re-checking the same URL refreshes the cached row (same url_id)
        again = scan_url(db, "https://www.evil-example.com/payload", f)
        assert again is not None and hit is not None
        assert again.url_id == hit.url_id
        count = db.execute(select(func.count()).select_from(UrlScan)).scalar()
        assert count == 2


# ---------------------------------------------------------------- routes


def test_api_scan_url_and_report(client, feed_dir):
    _seed(feed_dir)
    reset_domain_feed_cache()  # pick up the seeded feed dir
    r = client.post("/api/v2/urls", data={"url": "http://www.evil-example.com/x"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "malicious"
    assert body["categories"] == ["malware"]
    assert body["sources"] == ["hagezi-tif"]
    assert body["permalink"] == f"/ui/url/{body['id']}"
    report = client.get(f"/api/v2/urls/{body['id']}").json()
    assert report["verdict"] == "malicious" and report["host"] == "www.evil-example.com"
    assert report["stats"] == {"malicious": 1, "harmless": 0}
    assert report["matches"][0]["domain"] == "evil-example.com"
    ok = client.post("/api/v2/urls", data={"url": "example.org"}).json()
    assert ok["verdict"] == "harmless"
    assert client.get(f"/api/v2/urls/{ok['id']}").json()["stats"] == {
        "malicious": 0,
        "harmless": 1,
    }
    assert client.get("/api/v2/urls/doesnotexist").status_code == 404
    r = client.post("/api/v2/urls", data={"url": "not a url !!"})
    assert r.status_code == 400 and "not a valid URL" in r.json()["detail"]


def test_api_scan_url_disabled_without_feed(client, monkeypatch):
    monkeypatch.setattr(settings, "domain_feed_dir", "")
    monkeypatch.setattr(settings, "domain_feed_socket", "")
    reset_domain_feed_cache()
    r = client.post("/api/v2/urls", data={"url": "http://example.com/"})
    assert r.status_code == 503
    assert "DOMAIN_FEED" in r.json()["detail"]
    assert client.get("/ui/url/lookup", params={"url": "http://example.com/"}).status_code == 503
    reset_domain_feed_cache()


def test_api_scan_url_503_when_daemon_down_but_configured(client, monkeypatch, tmp_path):
    # socket configured but daemon not running: live 503 (re-probed, not cached)
    monkeypatch.setattr(settings, "domain_feed_dir", str(tmp_path))
    monkeypatch.setattr(settings, "domain_feed_socket", str(tmp_path / "missing.sock"))
    reset_domain_feed_cache()
    r = client.post("/api/v2/urls", data={"url": "http://example.com/"})
    assert r.status_code == 503
    body = client.get("/healthz").json()
    feed_eng = body["engines"][2]
    assert feed_eng["type"] == "domain-feed" and feed_eng["enabled"] is True
    assert feed_eng["ready"] is False and feed_eng["rules"] is None
    reset_domain_feed_cache()


def test_ui_url_lookup_and_report_pages(client, feed_dir, monkeypatch):
    _seed(feed_dir)
    reset_domain_feed_cache()
    r = client.get("/ui/url/lookup", params={"url": "casino-example.com"}, follow_redirects=False)
    assert r.status_code == 303
    url_id = r.headers["location"].rsplit("/", 1)[-1]
    page = client.get(f"/ui/url/{url_id}")
    assert page.status_code == 200
    assert "casino-example[.]com" in page.text  # defanged
    assert "gambling" in page.text and "malicious" in page.text
    assert client.get("/ui/url/nope").status_code == 404
    assert client.get("/ui/url/lookup", params={"url": "!!"}).status_code == 400
    # harmless report renders with the empty-feed note when nothing is loaded
    monkeypatch.setattr(settings, "domain_feed_dir", str(feed_dir / "empty"))
    reset_domain_feed_cache()
    r = client.get("/ui/url/lookup", params={"url": "plain-example.com"}, follow_redirects=False)
    page = client.get(r.headers["location"])
    assert "harmless" in page.text and "No domain-feed entries loaded" in page.text
    reset_domain_feed_cache()


def test_url_report_has_file_report_ui_and_relations(client, feed_dir):
    _seed(feed_dir)
    reset_domain_feed_cache()
    # a file scan that contains the URL/domain -> shows up in the URL report relations
    content = b"see http://www.evil-example.com/payload and evil-example.com here"
    client.post("/file/upload", files={"file": ("evil.bin", content)})
    sha = hashlib.sha256(content).hexdigest()
    for _ in range(30):
        if client.get(f"/api/v2/files/{sha}").json()["status"] == "done":
            break
        time.sleep(0.2)
    r = client.get("/ui/url/lookup", params={"url": "www.evil-example.com"}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get(r.headers["location"]).text
    # same UI as the file report: header card, detection ring, tabbed card
    assert 'class="tabs"' in page
    assert 'data-tab="detection"' in page and 'data-tab="details"' in page
    assert "det-widget" in page and "ring-num" in page
    assert 'id="detection-engines"' in page
    assert "malicious" in page and "hagezi-tif" in page and "malware" in page
    # relations tab links back to the file containing this domain
    assert 'data-tab="relations"' in page
    assert "evil.bin" in page and f"/ui/file/{sha}" in page
    # and vice versa: the file report links the URL to this scan
    file_page = client.get(f"/ui/file/{sha}").text
    assert "/ui/url/lookup?url=http%3A//www.evil-example.com/payload" in file_page


def test_search_shows_url_card_for_domains(client, feed_dir):
    _seed(feed_dir)
    reset_domain_feed_cache()
    page = client.get("/ui/search", params={"q": "www.evil-example.com"})
    assert page.status_code == 200
    assert "URL / domain check" in page.text
    assert "hxxp://www[.]evil-example[.]com" in page.text
    assert "malware" in page.text
    # file-name-like queries (non-IANA TLD) must NOT produce a URL card
    page = client.get("/ui/search", params={"q": "uniquename123.bin"})
    assert "URL / domain check" not in page.text
    # hash queries still redirect to the file report
    from app.models import Scan

    sha = "a" * 64
    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="1" * 32,
                sha1="1" * 40,
                file_name="h.bin",
                size=1,
                file_type="data",
                magic_hex="",
                verdict="clean",
                status="done",
                engine="x",
                urls=[],
            )
        )
        db.commit()
    r = client.get("/ui/search", params={"q": sha}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/ui/file/{sha}"


def test_home_page_has_url_form_without_internals(client):
    home = client.get("/ui/").text
    assert 'id="url-form"' in home
    assert 'action="/ui/url/lookup"' in home
    assert 'name="url"' in home
    # no feed/healthz/API internals shown to users on the home page
    assert "domain feed" not in home.lower()
    assert "/healthz" not in home
    assert "home-api-bar" not in home


def test_healthz_lists_domain_feed_as_engine(client, feed_dir, monkeypatch):
    _seed(feed_dir)
    reset_domain_feed_cache()
    body = client.get("/healthz").json()
    feed_eng = body["engines"][2]
    assert feed_eng["type"] == "domain-feed"
    assert feed_eng["name"] == "Domain feed"
    assert feed_eng["enabled"] and feed_eng["ready"]
    assert feed_eng["rules"] == 4 and feed_eng["rules_updated_at"] is not None
    # disabled when neither dir nor socket is configured
    monkeypatch.setattr(settings, "domain_feed_dir", "")
    monkeypatch.setattr(settings, "domain_feed_socket", "")
    reset_domain_feed_cache()
    body = client.get("/healthz").json()
    feed_eng = body["engines"][2]
    assert feed_eng["type"] == "domain-feed" and feed_eng["enabled"] is False
    assert feed_eng["ready"] is False and feed_eng["rules"] is None
    reset_domain_feed_cache()


def test_healthz_feed_alone_does_not_make_service_ok(client, feed_dir, monkeypatch):
    import app.main as main_module

    _seed(feed_dir)
    reset_domain_feed_cache()

    def boom():
        raise ScannerUnavailableError("no backend")

    monkeypatch.setattr(main_module, "get_scanner", boom)
    monkeypatch.setattr(main_module, "enabled_scanners", lambda: {"clamav", "yara"})
    monkeypatch.setattr(settings, "yara_rules_dir", "")  # no in-process yara engine

    reset_yara_cache()
    body = client.get("/healthz").json()
    reset_yara_cache()
    assert body["engines"][2]["type"] == "domain-feed" and body["engines"][2]["ready"] is True
    assert body["status"] == "degraded"  # feed ready, but no scan engine ready
    reset_domain_feed_cache()


def test_url_scan_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_upload", 2)
    for _ in range(2):
        assert client.post("/api/v2/urls", data={"url": "http://example.com/"}).status_code == 200
    assert client.post("/api/v2/urls", data={"url": "http://example.com/"}).status_code == 429
