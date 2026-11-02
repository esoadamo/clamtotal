"""Frontend contract tests: the rendered pages must expose the exact DOM/JS contract
that app/static/app.js wires up (ids, data attributes, script include)."""

import hashlib

from app.config import settings


def test_static_js_served(client):
    response = client.get("/static/app.js")
    assert response.status_code == 200
    assert "ClamTotal" in response.text
    assert "sha256HexPure" in response.text


def test_every_page_loads_app_js(client):
    for path in ["/ui/", "/ui/search?q=x", f"/ui/file/{'a' * 64}"]:
        page = client.get(path)
        assert page.status_code in (200, 404)
        assert '<script src="/static/app.js"></script>' in page.text, path


def test_home_upload_contract(client):
    home = client.get("/ui/").text
    # dropzone + hidden file input + progress UI + modal skeleton
    for marker in [
        'id="dropzone"',
        'id="file-input"',
        'id="dz-idle"',
        'id="dz-progress"',
        'id="dz-spinner"',
        'id="progress-bar"',
        'id="dz-error"',
        'id="modal-overlay"',
        'id="modal-cancel"',
        'id="modal-confirm"',
        'id="upload-form"',
        'action="/file/upload"',
    ]:
        assert marker in home, marker


def test_pending_report_contract(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_poll_interval_ms", 4321)
    sha = "9f" * 32
    from app.db import SessionLocal
    from app.models import Scan

    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="3" * 32,
                sha1="3" * 40,
                file_name="fe.bin",
                size=1,
                file_type="data",
                magic_hex="",
                verdict="pending",
                status="pending",
                engine="pending",
                urls=[],
            )
        )
        db.commit()
    page = client.get(f"/ui/file/{sha}").text
    assert 'id="pending-data"' in page
    assert f'data-sha="{sha}"' in page
    assert 'data-interval="4321"' in page
    assert "Scanning fe.bin" in page
    assert "vt-spin" not in page and "ct-spin" in page


def test_done_report_contract(client):
    content = b"frontend done report http://evil-example.com/path"
    client.post("/file/upload", files={"file": ("fe-done.bin", content)})
    sha = hashlib.sha256(content).hexdigest()
    page = client.get(f"/ui/file/{sha}")
    assert page.status_code == 200
    for marker in [
        'class="tabs"',
        'data-tab="detection"',
        'data-tab="details"',
        'data-tab="behavior"',
        'data-tab="network"',
        "det-widget",
        "ring-num",
    ]:
        assert marker in page.text, marker
    # defanged, non-clickable indicators
    assert "hxxp://evil-example[.]com/path" in page.text
    assert 'href="http://evil-example.com/path"' not in page.text
    assert "<a " not in page.text.split('id="tab-network"')[1].split("</section>")[0]


def test_recent_table_contract(client):
    client.post("/file/upload", files={"file": ("row.bin", b"recent row")})
    home = client.get("/ui/")
    assert "Recently analyzed files" in home.text
    assert "row.bin" in home.text
    assert "badge" in home.text


def test_not_found_page_contract(client):
    page = client.get(f"/ui/file/{'b' * 64}")
    assert page.status_code == 404
    assert "File not found" in page.text
    assert 'href="/ui/"' in page.text


def test_og_card_meta_on_all_pages(client):
    sha = hashlib.sha256(b"og card test").hexdigest()
    client.post("/file/upload", files={"file": ("og.bin", b"og card test")})
    for path in ["/ui/", "/ui/search?q=og", f"/ui/file/{sha}"]:
        page = client.get(path).text
        assert '<meta property="og:title"' in page, path
        assert '<meta property="og:image" content="/static/og-card.svg">' in page, path
        assert '<meta property="og:site_name" content="ClamTotal">' in page, path
        assert '<meta name="twitter:card" content="summary_large_image">' in page, path
        assert '<meta name="theme-color" content="#0f766e">' in page, path


def test_og_card_image_served(client):
    response = client.get("/static/og-card.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert 'width="1200"' in response.text and 'height="630"' in response.text


def test_modal_has_spinner_and_progress_styles(client):
    home = client.get("/ui/").text
    assert '<div class="modal-overlay" id="modal-overlay">' in home
    assert ".spinner" in home  # hashing/upload spinners
    assert ".progress-bar" in home
    assert "ct-spin" in home
