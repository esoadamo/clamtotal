"""Frontend contract tests: the rendered pages must expose the exact DOM/JS contract
that app/static/app.js wires up (ids, data attributes, script include)."""

import hashlib
from pathlib import Path

from app.config import settings


def test_static_js_served(client):
    response = client.get("/static/app.js")
    assert response.status_code == 200
    assert "ClamTotal" in response.text
    assert "sha256HexPure" in response.text


def test_every_page_loads_app_js(client):
    for path in ["/ui/", "/ui/search?q=x", "/ui/terms", f"/ui/file/{'a' * 64}"]:
        page = client.get(path)
        assert page.status_code in (200, 404)
        # script URL is versioned with the build stamp to bust browser/CDN caches
        assert '<script src="/static/app.js?v=' in page.text, path


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
        'data-chunk-size="',
        'data-ws-upload="',
        'data-ws-chunk-size="',
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
                engines=[
                    {
                        "name": "ClamAV (fake)",
                        "status": "done",
                        "verdict": "clean",
                        "signature": None,
                    },
                    {"name": "YARA (local rules)", "status": "scanning"},
                ],
            )
        )
        db.commit()
    page = client.get(f"/ui/file/{sha}").text
    assert 'id="scan-progress"' in page
    assert f'data-sha="{sha}"' in page
    assert 'data-interval="4321"' in page
    assert 'data-key="1:0"' in page  # one engine done, analysis not committed yet
    assert "vt-spin" not in page and "ct-spin" in page
    # the full results page renders immediately; while scanning, the Detection tab
    # shows one row per engine (spinner while scanning, verdict once done) and the
    # other tabs show placeholders that fill in as the scan progresses
    for marker in [
        'class="tabs"',
        'data-tab="detection"',
        'data-tab="details"',
        'data-tab="behavior"',
        'data-tab="network"',
        "det-widget",
        "ring-num",
    ]:
        assert marker in page, marker
    assert 'id="detection-engines"' in page
    assert page.count("<tr data-engine=") == 2
    assert "ClamAV (fake)" in page and "YARA (local rules)" in page
    assert "Undetected" in page  # done + clean
    assert "Scanning…" in page  # still scanning
    assert "engine-spinner" in page
    assert "Scanning… 1 of 2 engines finished" in page
    assert page.count("Analysis in progress…") == 2  # Behavior + Network placeholders
    assert "fe.bin" in page and sha in page  # header details are there from the start


def test_pending_report_without_engines_shows_generic_row(client):
    sha = "8e" * 32
    from app.db import SessionLocal
    from app.models import Scan

    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="4" * 32,
                sha1="4" * 40,
                file_name="legacy.bin",
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
    assert 'id="detection-engines"' in page
    assert page.count("<tr data-engine=") == 1  # fallback row when no engine list yet
    assert "Analysis engines" in page
    assert 'data-key="0:0"' in page


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
    # indicators stay defanged as text, but link LOCALLY to their own URL scan report
    network = page.text.split('id="tab-network"')[1].split("</section>")[0]
    assert 'href="http' not in network  # never a clickable external link
    assert 'href="/ui/url/lookup?url=' in network  # ...but clickable to the scan
    assert "url=http%3A//evil-example.com/path" in network
    # a finished report carries no polling hooks: the page must not reload itself
    assert 'id="scan-progress"' not in page.text
    assert "data-sha=" not in page.text


def test_home_layout_contract(client):
    home = client.get("/ui/").text
    # home: centered logo + tagline + FILE/URL/SEARCH widget tabs
    assert 'class="home-logo"' in home and "home-tagline" in home
    for tab in ['data-tab="file"', 'data-tab="url"', 'data-tab="search"']:
        assert tab in home, tab
    for panel in ['id="tab-file"', 'id="tab-url"', 'id="tab-search"']:
        assert panel in home, panel
    # the upload form still lives in the FILE panel with the full JS contract
    assert 'id="upload-form"' in home and 'action="/file/upload"' in home
    # URL tab keeps the URL form contract; no feed/API internals shown to users
    assert 'id="url-form"' in home and 'action="/ui/url/lookup"' in home
    assert "domain feed" not in home.lower()
    assert "/healthz" not in home
    # ToS + privacy notice under the widget; no "automate submissions" API box on the home page
    assert "home-notice" in home
    assert 'href="/ui/terms"' in home and "Terms of Service" in home
    assert 'href="/ui/privacy"' in home and "Privacy Notice" in home
    assert "not responsible for the contents of your submission" in home
    assert "home-api-bar" not in home and "automate submissions" not in home
    # warm friendly theme (teal on warm paper), not the dark VT palette
    assert "--bg: #f7f5f0" in home and "--brand: #0f766e" in home
    assert "#1a1a2e" not in home


def test_terms_of_service_page(client):
    page = client.get("/ui/terms")
    assert page.status_code == 200
    assert "Terms of Service" in page.text
    assert "as is" in page.text
    # linked from every page footer, next to the privacy policy
    for path in ["/ui/", "/ui/search?q=x", "/ui/privacy"]:
        assert 'href="/ui/terms"' in client.get(path).text, path


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


def test_download_button_disabled_when_sample_expired(client):
    content = b"expired sample content"
    client.post("/file/upload", files={"file": ("expired.bin", content)})
    sha = hashlib.sha256(content).hexdigest()
    page = client.get(f"/ui/file/{sha}").text
    assert f'href="/ui/file/{sha}/download"' in page  # enabled while the file is on disk

    (Path(settings.upload_dir) / sha).unlink()  # simulate TTL expiry removing the file
    resp = client.get(f"/ui/file/{sha}")
    assert resp.status_code == 200  # report page still renders
    page = resp.text
    assert f'href="/ui/file/{sha}/download"' not in page
    assert 'disabled title="The file is already expired and deleted"' in page
    assert client.get(f"/ui/file/{sha}/download").status_code == 404
    # the scan record is kept in the database, only the file was removed
    from app.db import SessionLocal
    from app.models import Scan

    with SessionLocal() as db:
        assert db.get(Scan, sha) is not None


def test_plausible_script_optional(client, monkeypatch):
    from app.main import templates

    page = client.get("/ui/").text
    assert "plausible" not in page  # off by default: no external script loaded
    monkeypatch.setitem(
        templates.env.globals, "plausible_script_url", "https://plausible.example/js/script.js"
    )
    for path in ["/ui/", "/ui/search?q=x", "/ui/privacy"]:
        page = client.get(path).text
        assert '<script defer src="https://plausible.example/js/script.js"></script>' in page, path


def test_footer_shows_app_version_when_set(client, monkeypatch):
    from app.main import templates

    assert "v261104" not in client.get("/ui/").text  # hidden when unset
    monkeypatch.setitem(templates.env.globals, "app_version", "261104.093000")
    page = client.get("/ui/").text
    assert "v261104.093000" in page


def test_footer_links_to_github_repo_and_api_docs(client):
    for path in ["/ui/", "/ui/search?q=x", "/ui/privacy"]:
        page = client.get(path).text
        assert 'href="https://github.com/esoadamo/clamtotal"' in page, path
        assert 'href="/docs"' in page, path  # link to the API docs (Swagger UI)


def test_mobile_viewport_and_media_query_on_all_pages(client):
    sha = hashlib.sha256(b"mobile view").hexdigest()
    client.post("/file/upload", files={"file": ("mobile.bin", b"mobile view")})
    for path in ["/ui/", "/ui/search?q=x", f"/ui/file/{sha}", "/ui/privacy"]:
        page = client.get(path).text
        assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page, path
        assert "@media (max-width: 640px)" in page, path
        assert ".appbar-search { flex: 1 1 100%" in page, path  # appbar search drops to its own row
