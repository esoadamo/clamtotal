import hashlib

from app.config import settings
from app.scanner import ScannerUnavailableError, get_scanner


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_upload_empty_file_400(client):
    response = client.post("/file/upload", files={"file": ("empty.bin", b"")})
    assert response.status_code == 400


def test_upload_too_large_413(client, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_size", 4)
    response = client.post("/file/upload", files={"file": ("big.bin", b"12345")})
    assert response.status_code == 413


def test_upload_scanner_unavailable_503(client, monkeypatch):
    def boom():
        raise ScannerUnavailableError("no backend")

    from app.main import app

    app.dependency_overrides[get_scanner] = boom
    try:
        response = client.post("/file/upload", files={"file": ("x.bin", b"data")})
        assert response.status_code == 503
        assert "no backend" in response.json()["detail"]
    finally:
        from fakes import fake_scanner

        app.dependency_overrides[get_scanner] = lambda: fake_scanner


def test_api_upload_empty_400(client):
    assert client.post("/api/v2/files", files={"file": ("e.bin", b"")}).status_code == 400


def test_report_lookup_by_sha1(client):
    content = b"sha1 lookup target"
    client.post("/file/upload", files={"file": ("sha1.bin", content)}, follow_redirects=False)
    sha1 = hashlib.sha1(content).hexdigest()
    response = client.get(f"/ui/file/{sha1}")
    assert response.status_code == 200 and "sha1.bin" in response.text


def test_download_unknown_hash_404(client):
    assert client.get(f"/ui/file/{'c' * 64}/download").status_code == 404


def test_download_missing_stored_sample_404(client, tmp_path, monkeypatch):
    content = b"ephemeral sample"
    client.post("/file/upload", files={"file": ("gone.bin", content)}, follow_redirects=False)
    sha = hashlib.sha256(content).hexdigest()
    import os

    os.remove(f"{settings.upload_dir}/{sha}")
    assert client.get(f"/ui/file/{sha}/download").status_code == 404


def test_rescan_unknown_404(client):
    assert client.post(f"/ui/file/{'d' * 64}/rescan").status_code == 404


def test_search_by_file_name(client):
    content = b"findme by name"
    client.post(
        "/file/upload", files={"file": ("uniquename123.bin", content)}, follow_redirects=False
    )
    response = client.get("/ui/search", params={"q": "uniquename123"})
    assert response.status_code == 200
    assert "uniquename123.bin" in response.text


def test_search_empty_query(client):
    response = client.get("/ui/search", params={"q": ""})
    assert response.status_code == 200
    assert "No results found" in response.text


def test_root_redirects_to_ui(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/"


def test_recent_scans_hidden_when_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "show_recent_scans", False)
    client.post("/file/upload", files={"file": ("hidden-recent.bin", b"x")})
    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Recently analyzed files" not in page.text
    monkeypatch.setattr(settings, "show_recent_scans", True)
    assert "Recently analyzed files" in client.get("/ui/").text


def test_raw_scanner_output_not_shown(client):
    content = b"raw output check"
    client.post("/file/upload", files={"file": ("raw.bin", content)})
    import hashlib

    sha = hashlib.sha256(content).hexdigest()
    page = client.get(f"/ui/file/{sha}")
    assert "Raw scanner output" not in page.text
    assert "stdin: OK" not in page.text


def test_no_airgapped_messaging(client):
    assert "airgapped" not in client.get("/ui/").text.lower()
    assert "offline" not in client.get("/ui/").text.lower()
