"""URL/domain scanning: blocklist parsing/import, normalization, lookup, routes."""

import base64
import threading
from pathlib import Path

import pytest
from sqlalchemy import func, select

import app.blocklists as bl
from app.blocklists import (
    blocklist_stats,
    ensure_blocklists_loaded,
    import_blocklists,
    lookup_host,
    normalize_url_input,
    parse_blocklist_line,
    scan_url,
)
from app.config import settings
from app.db import SessionLocal
from app.models import BlocklistEntry, UrlScan


@pytest.fixture
def blocklist_dir(tmp_path, monkeypatch):
    d = tmp_path / "blocklists"
    d.mkdir()
    monkeypatch.setattr(settings, "url_blocklist_dir", str(d))
    monkeypatch.setattr(bl, "_loaded_stamp", None)
    monkeypatch.setattr(bl, "_import_thread", None)
    return d


def _seed_lists(d: Path) -> None:
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
    (d / bl.STAMP_NAME).touch()


def _import(d: Path) -> int:
    with SessionLocal() as db:
        return import_blocklists(db)


def _norm(value: str, require_tld: bool = False) -> tuple[str, str, str]:
    result = normalize_url_input(value, require_tld=require_tld)
    assert result is not None, value
    return result


# ---------------------------------------------------------------- parsing


def test_parse_blocklist_line_formats():
    assert parse_blocklist_line("example.com") == "example.com"
    assert parse_blocklist_line("*.sub.example.com") == "sub.example.com"
    assert parse_blocklist_line("0.0.0.0 example.com") == "example.com"
    assert parse_blocklist_line("127.0.0.1 example.com.") == "example.com"
    assert parse_blocklist_line("::1 localhost") is None  # IPv6 hosts entry -> localhost skip
    assert parse_blocklist_line("||example.com^$third-party") == "example.com"
    assert parse_blocklist_line("EXAMPLE.COM") == "example.com"
    assert parse_blocklist_line("192.168.0.1") == "192.168.0.1"  # bare IP entry kept
    assert parse_blocklist_line("# comment") is None
    assert parse_blocklist_line("   ") is None
    assert parse_blocklist_line("0.0.0.0 0.0.0.0") is None
    assert parse_blocklist_line("0.0.0.0 localhost") is None
    assert parse_blocklist_line("not a host line") is None  # multi-token, first not an IP
    assert parse_blocklist_line("bad_domain!.com") is None
    assert parse_blocklist_line("nodot") is None
    assert parse_blocklist_line("*.") is None


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


# ---------------------------------------------------------------- lookup


def test_lookup_host_wildcard_and_multi_source(blocklist_dir):
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    with SessionLocal() as db:
        # exact + parent walk: listed 'evil-example.com' blocks deep subdomains
        m = lookup_host(db, "www.evil-example.com")
        assert m == [{"domain": "evil-example.com", "source": "hagezi-tif", "category": "malware"}]
        assert lookup_host(db, "evil-example.com")[0]["source"] == "hagezi-tif"
        assert {r["category"] for r in lookup_host(db, "casino-example.com")} == {"gambling"}
        assert {r["category"] for r in lookup_host(db, "ads-example.org")} == {"gambling"}
        assert lookup_host(db, "clean-example.com") == []
        assert lookup_host(db, "185.220.101.4") == []  # IP: exact only, no parent walk
        # same domain in two lists -> both reported
        with SessionLocal() as db2:
            db2.execute(
                bl.insert(BlocklistEntry),
                [{"domain": "evil-example.com", "source": "urlhaus", "category": "malware"}],
            )
            db2.commit()
        m = lookup_host(db, "evil-example.com")
        assert {r["source"] for r in m} == {"hagezi-tif", "urlhaus"}


# ---------------------------------------------------------------- import / reload


def test_import_blocklists_reads_category_headers(blocklist_dir):
    _seed_lists(blocklist_dir)
    assert _import(blocklist_dir) == 4
    with SessionLocal() as db:
        rows = db.execute(select(BlocklistEntry)).scalars().all()
        by_domain = {r.domain: r for r in rows}
        assert by_domain["evil-example.com"].category == "malware"
        assert by_domain["casino-example.com"].category == "gambling"
        assert by_domain["ads-example.org"].source == "gambling"  # fallback: no header
    # re-import replaces, not appends
    (blocklist_dir / "hagezi-tif.txt").write_text("only-one.example\n")
    (blocklist_dir / "gambling.txt").unlink()
    assert _import(blocklist_dir) == 1
    with SessionLocal() as db:
        assert db.execute(select(func.count()).select_from(BlocklistEntry)).scalar() == 1


def test_import_blocklists_edge_cases(blocklist_dir, monkeypatch):
    # missing dir -> empty import, still returns 0
    monkeypatch.setattr(settings, "url_blocklist_dir", str(blocklist_dir / "nope"))
    assert _import(blocklist_dir) == 0
    # unreadable file is skipped
    monkeypatch.setattr(settings, "url_blocklist_dir", str(blocklist_dir))
    (blocklist_dir / "a.txt").write_text("a-example.com\n")
    (blocklist_dir / "b.txt").write_text("b-example.com\n")
    real_read_text = Path.read_text

    def boom(self, *a, **kw):
        if self.name == "b.txt":
            raise OSError("nope")
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", boom)
    assert _import(blocklist_dir) == 1


def test_stamp_value_branches(blocklist_dir, monkeypatch):
    assert bl._stamp_value() is None  # empty dir, no stamp
    (blocklist_dir / "x.txt").write_text("x-example.com\n")
    assert bl._stamp_value() is not None  # falls back to newest .txt mtime
    stamp = blocklist_dir / bl.STAMP_NAME
    stamp.touch()
    assert bl._stamp_value() == stamp.stat().st_mtime_ns  # stamp wins
    monkeypatch.setattr(settings, "url_blocklist_dir", "")  # disabled
    assert bl._stamp_value() is None
    monkeypatch.setattr(settings, "url_blocklist_dir", str(blocklist_dir / "missing"))
    assert bl._stamp_value() is None


def test_ensure_blocklists_loaded_branches(blocklist_dir, monkeypatch):
    # disabled -> no-op
    monkeypatch.setattr(settings, "url_blocklist_dir", "")
    ensure_blocklists_loaded()
    assert bl._import_thread is None
    monkeypatch.setattr(settings, "url_blocklist_dir", str(blocklist_dir))
    # stamp unchanged (both None) -> no-op
    ensure_blocklists_loaded()
    assert bl._import_thread is None
    # import already running -> no second thread
    _seed_lists(blocklist_dir)
    release = threading.Event()

    def sleeper():
        release.wait(10)

    t = threading.Thread(target=sleeper, daemon=True)
    monkeypatch.setattr(bl, "_import_thread", t)
    t.start()
    ensure_blocklists_loaded()
    release.set()
    t.join()
    assert bl._import_thread is t  # untouched
    # stamp changed -> background import runs and loads the rows
    monkeypatch.setattr(bl, "_loaded_stamp", None)
    monkeypatch.setattr(bl, "_import_thread", None)
    ensure_blocklists_loaded()
    assert bl._import_thread is not None
    bl._import_thread.join(timeout=30)
    with SessionLocal() as db:
        assert db.execute(select(func.count()).select_from(BlocklistEntry)).scalar() == 4
    stamp_after = bl._loaded_stamp
    bl._import_thread = None
    ensure_blocklists_loaded()  # same stamp now -> no new thread
    assert bl._import_thread is None
    assert bl._loaded_stamp == stamp_after


def test_blocklist_stats(blocklist_dir):
    with SessionLocal() as db:
        db.execute(bl.delete(BlocklistEntry))
        db.commit()
        count, updated = blocklist_stats(db)
        assert count == 0 and updated is None
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    with SessionLocal() as db:
        count, updated = blocklist_stats(db)
        assert count == 4 and updated is not None


# ---------------------------------------------------------------- scan_url


def test_scan_url_verdicts_and_cache(blocklist_dir):
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    with SessionLocal() as db:
        db.execute(bl.delete(UrlScan))
        db.commit()
        hit = scan_url(db, "https://www.evil-example.com/payload")
        assert hit is not None and hit.verdict == "malicious"
        assert hit.host == "www.evil-example.com"
        assert hit.matches is not None and hit.matches[0]["category"] == "malware"
        miss = scan_url(db, "example.org")
        assert miss is not None and miss.verdict == "harmless" and miss.matches == []
        assert scan_url(db, "not a url at all !!") is None
        # re-checking the same URL refreshes the cached row (same url_id)
        again = scan_url(db, "https://www.evil-example.com/payload")
        assert again is not None and hit is not None
        assert again.url_id == hit.url_id
        count = db.execute(select(func.count()).select_from(UrlScan)).scalar()
        assert count == 2


def test_scan_url_without_blocklist_dir(monkeypatch):
    monkeypatch.setattr(settings, "url_blocklist_dir", "")
    with SessionLocal() as db:
        scan = scan_url(db, "http://evil-example.com/")
        assert scan is not None and scan.verdict == "harmless" and scan.matches == []


# ---------------------------------------------------------------- routes


def test_api_scan_url_and_report(client, blocklist_dir):
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    r = client.post("/api/v2/urls", data={"url": "http://www.evil-example.com/x"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "malicious"
    assert body["categories"] == ["malware"]
    assert body["sources"] == ["hagezi-tif"]
    assert body["permalink"] == f"/ui/url/{body['id']}"
    # VT-style GET by id
    report = client.get(f"/api/v2/urls/{body['id']}").json()
    assert report["verdict"] == "malicious" and report["host"] == "www.evil-example.com"
    assert report["stats"] == {"malicious": 1, "harmless": 0}
    assert report["matches"][0]["domain"] == "evil-example.com"
    assert report["last_analysis"]
    # harmless + 404
    ok = client.post("/api/v2/urls", data={"url": "example.org"}).json()
    assert ok["verdict"] == "harmless"
    assert client.get(f"/api/v2/urls/{ok['id']}").json()["stats"] == {
        "malicious": 0,
        "harmless": 1,
    }
    assert client.get("/api/v2/urls/doesnotexist").status_code == 404
    # invalid input -> 400
    r = client.post("/api/v2/urls", data={"url": "not a url !!"})
    assert r.status_code == 400 and "not a valid URL" in r.json()["detail"]


def test_api_scan_url_disabled_without_dir(client, monkeypatch):
    monkeypatch.setattr(settings, "url_blocklist_dir", "")
    r = client.post("/api/v2/urls", data={"url": "http://example.com/"})
    assert r.status_code == 503
    assert "URL_BLOCKLIST_DIR" in r.json()["detail"]
    assert client.get("/ui/url/lookup", params={"url": "http://example.com/"}).status_code == 503


def test_ui_url_lookup_and_report_pages(client, blocklist_dir):
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    r = client.get("/ui/url/lookup", params={"url": "casino-example.com"}, follow_redirects=False)
    assert r.status_code == 303
    url_id = r.headers["location"].rsplit("/", 1)[-1]
    page = client.get(f"/ui/url/{url_id}")
    assert page.status_code == 200
    assert "casino-example[.]com" in page.text  # defanged
    assert "gambling" in page.text and "malicious" in page.text
    # unknown id -> 404 page
    assert client.get("/ui/url/nope").status_code == 404
    # invalid input -> 400
    assert client.get("/ui/url/lookup", params={"url": "!!"}).status_code == 400
    # harmless report renders with the empty-list note when no entries loaded
    monkeypatch_dir = Path(settings.url_blocklist_dir)
    for f in monkeypatch_dir.glob("*.txt"):
        f.unlink()
    with SessionLocal() as db:
        db.execute(bl.delete(BlocklistEntry))
        db.commit()
    r = client.get("/ui/url/lookup", params={"url": "plain-example.com"}, follow_redirects=False)
    page = client.get(r.headers["location"])
    assert "harmless" in page.text and "No blocklist entries loaded" in page.text


def test_search_shows_url_card_for_domains(client, blocklist_dir):
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    page = client.get("/ui/search", params={"q": "www.evil-example.com"})
    assert page.status_code == 200
    assert "URL / domain check" in page.text
    assert "hxxp://www[.]evil-example[.]com" in page.text
    assert "malware" in page.text
    # file-name-like queries (non-IANA TLD) must NOT produce a URL card
    page = client.get("/ui/search", params={"q": "uniquename123.bin"})
    assert "URL / domain check" not in page.text
    # hash queries still redirect to the file report
    sha = "a" * 64
    with SessionLocal() as db:
        from app.models import Scan

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


def test_home_page_has_url_form(client):
    home = client.get("/ui/").text
    assert 'id="url-form"' in home
    assert 'action="/ui/url/lookup"' in home
    assert 'name="url"' in home


def test_healthz_reports_blocklists(client, blocklist_dir, monkeypatch):
    _seed_lists(blocklist_dir)
    _import(blocklist_dir)
    body = client.get("/healthz").json()
    assert body["blocklists"]["enabled"] is True
    assert body["blocklists"]["entries"] == 4
    assert body["blocklists"]["updated_at"] is not None
    # disabled when URL_BLOCKLIST_DIR is unset
    monkeypatch.setattr(settings, "url_blocklist_dir", "")
    body = client.get("/healthz").json()
    assert body["blocklists"] == {"enabled": False, "entries": None, "updated_at": None}


def test_url_scan_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_upload", 2)
    for _ in range(2):
        assert client.post("/api/v2/urls", data={"url": "http://example.com/"}).status_code == 200
    assert client.post("/api/v2/urls", data={"url": "http://example.com/"}).status_code == 429
