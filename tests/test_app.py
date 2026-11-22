import hashlib
from pathlib import Path

import pytest

from app.analysis import shannon_entropy

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def clean_file(marker: bytes = b"") -> bytes:
    """Unique per-marker content so the SHA-256 cache never leaks between tests."""
    return (
        b"hello clamtotal https://example.org/malware-report http://test.local/x " + marker + b"\n"
    )


def _upload(client, content: bytes, filename: str = "sample.bin"):
    """Upload via the async endpoint; returns (sha256, response). Scan runs as a background task."""
    response = client.post("/file/upload", files={"file": (filename, content)})
    return hashlib.sha256(content).hexdigest(), response


def test_index_lists_recent_scans(client):
    _upload(client, clean_file(b"index"), "first.bin")
    response = client.get("/ui/")
    assert response.status_code == 200
    assert "first.bin" in response.text


def test_upload_returns_hash_and_report_renders(client):
    content = clean_file(b"clean")
    sha256, response = _upload(client, content, "clean.bin")
    assert response.status_code == 202
    assert response.json()["sha256"] == sha256

    report = client.get(f"/ui/file/{sha256}")
    assert report.status_code == 200
    assert "clean.bin" in report.text
    assert "0/2" in report.text  # ClamAV + domain feed engines
    assert "hxxps://example[.]org/malware-report" in report.text  # defanged in the UI
    assert 'href="https://example.org' not in report.text


def test_upload_eicar_is_detected(client):
    sha256, response = _upload(client, EICAR, "eicar.com")
    assert response.status_code == 202
    report = client.get(f"/ui/file/{sha256}")
    assert "1/2" in report.text  # ClamAV + domain feed engines
    assert "Win.Test.EICAR_HDB-1" in report.text


def test_results_are_cached(client, fake):
    calls_before = fake.calls
    _upload(client, b"cache me", "cached.bin")
    _upload(client, b"cache me", "cached.bin")
    assert fake.calls == calls_before + 1


def test_rescan_forces_new_scan(client, fake):
    sha256, _ = _upload(client, b"rescan me", "rescan.bin")
    calls_before = fake.calls
    response = client.post(f"/ui/file/{sha256}/rescan", follow_redirects=False)
    assert response.status_code == 303
    assert fake.calls == calls_before + 1


def test_search_by_hash_redirects(client):
    content = clean_file(b"search")
    sha256, _ = _upload(client, content, "searchable.bin")
    response = client.get("/ui/search", params={"q": sha256}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/ui/file/{sha256}"


def test_search_unknown_hash_shows_empty_results(client):
    response = client.get("/ui/search", params={"q": "0" * 64})
    assert response.status_code == 200
    assert "No results found" in response.text


def test_report_lookup_by_md5(client):
    content = clean_file(b"md5")
    _upload(client, content, "md5lookup.bin")
    md5 = hashlib.md5(content).hexdigest()
    response = client.get(f"/ui/file/{md5}")
    assert response.status_code == 200
    assert "md5lookup.bin" in response.text


def test_unknown_report_returns_404(client):
    response = client.get(f"/ui/file/{'a' * 64}")
    assert response.status_code == 404


def test_api_upload_and_report(client):
    content = clean_file(b"api")
    response = client.post("/api/v2/files", files={"file": ("api.bin", content)})
    assert response.status_code == 202
    payload = response.json()
    sha256 = hashlib.sha256(content).hexdigest()
    assert payload["sha256"] == sha256
    assert payload["status"] == "pending"  # scan is async; row flips to done in the background
    assert client.get(f"/api/v2/files/{sha256}").json()["status"] == "done"

    report = client.get(f"/api/v2/files/{sha256}")
    assert report.status_code == 200
    data = report.json()
    assert data["verdict"] == "clean"
    assert "https://example.org/malware-report" in data["urls"]

    assert client.get(f"/api/v2/files/{'b' * 64}").status_code == 404


def test_download_stored_sample(client):
    content = clean_file(b"download")
    _upload(client, content, "download.bin")
    sha256 = hashlib.sha256(content).hexdigest()
    response = client.get(f"/ui/file/{sha256}/download")
    assert response.status_code == 200
    assert response.content == content


def test_report_entropy_is_cached_at_scan_time(client):
    from app.db import SessionLocal
    from app.models import Scan

    content = clean_file(b"entropy")
    sha256, _ = _upload(client, content, "entropy.bin")
    with SessionLocal() as db:
        scan = db.get(Scan, sha256)
        assert scan is not None
        assert scan.entropy == shannon_entropy(content)
    report = client.get(f"/ui/file/{sha256}")
    assert f"{shannon_entropy(content):.3f}" in report.text


def _legacy_scan(sha256: str, content: bytes) -> None:
    from app.db import SessionLocal
    from app.models import Scan

    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha256,
                md5=hashlib.md5(content).hexdigest(),
                sha1=hashlib.sha1(content).hexdigest(),
                file_name="legacy.bin",
                size=len(content),
                file_type="ASCII text",
                magic_hex="",
                verdict="clean",
                status="done",
                engine="clamscan",
                urls=[],
            )
        )
        db.commit()


def test_report_legacy_row_shows_unknown_entropy_without_reading_sample(client):
    """Rows from before the entropy column existed never gain a stored value; the
    report shows — and must not reconstruct it by reading the sample from disk."""
    from app.config import settings
    from app.db import SessionLocal
    from app.models import Scan

    content = b"legacy row scanned before the entropy column existed"
    sha256 = hashlib.sha256(content).hexdigest()
    _legacy_scan(sha256, content)
    sample = Path(settings.upload_dir) / sha256
    sample.parent.mkdir(exist_ok=True)
    sample.write_bytes(content)

    def forbidden(path, chunk_size=1024 * 1024):
        raise AssertionError("report rendering read the sample from disk")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("app.analysis.shannon_entropy_file", forbidden)
    try:
        report = client.get(f"/ui/file/{sha256}")
        assert report.status_code == 200
        assert "<dt>Entropy</dt><dd>\u2014</dd>" in report.text
    finally:
        monkeypatch.undo()
    with SessionLocal() as db:
        scan = db.get(Scan, sha256)
        assert scan is not None
        assert scan.entropy is None


def test_report_of_pending_scan_never_reads_the_sample(client):
    """A pending row has no entropy yet; the report page must not fall back to
    reading the sample from disk (that made opening a report O(file size))."""
    from app.config import settings
    from app.db import SessionLocal
    from app.models import Scan

    content = b"pending scan whose report must not read the sample"
    sha256 = hashlib.sha256(content).hexdigest()
    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha256,
                md5=hashlib.md5(content).hexdigest(),
                sha1=hashlib.sha1(content).hexdigest(),
                file_name="pending.bin",
                size=len(content),
                file_type="ASCII text",
                magic_hex="",
                verdict="pending",
                status="pending",
                engine="clamscan",
                urls=[],
            )
        )
        db.commit()
    report = client.get(f"/ui/file/{sha256}")
    assert report.status_code == 200
    assert "<dt>Entropy</dt><dd>\u2014</dd>" in report.text


def test_upload_capabilities(client, monkeypatch):
    from app.config import settings

    assert settings.chunk_upload_size > 0  # the default enables the chunked path
    caps = client.get("/api/v2/upload/capabilities")
    assert caps.status_code == 200
    body = caps.json()
    assert body == {
        "max_upload_size": settings.max_upload_size,
        "chunked": True,
        "chunk_size": settings.chunk_upload_size,
        "websocket": settings.ws_upload_enabled and settings.ws_chunk_size > 0,
        "ws_chunk_size": settings.ws_chunk_size,
    }
    monkeypatch.setattr(settings, "chunk_upload_size", 0)
    monkeypatch.setattr(settings, "ws_upload_enabled", False)
    body = client.get("/api/v2/upload/capabilities").json()
    assert body["chunked"] is False and body["chunk_size"] == 0
    assert body["websocket"] is False and body["ws_chunk_size"] >= 0
