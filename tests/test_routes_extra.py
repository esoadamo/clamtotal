import hashlib
import json
from pathlib import Path

from app.config import settings
from app.scanner import ScannerUnavailableError, get_scanner, reset_yara_cache


def test_openapi_docs_describe_current_rate_limits(client, monkeypatch):
    import app.main as m

    m.app.openapi_schema = None
    client.get("/openapi.json")  # generates and caches the schema
    desc = client.get("/openapi.json").json()["info"]["description"]  # cached branch
    assert "## Rate limits" in desc
    assert "unlimited (rate limit disabled)" in desc  # defaults: RATE_LIMIT_* = 0

    monkeypatch.setattr(settings, "rate_limit_upload", 10)
    monkeypatch.setattr(settings, "rate_limit_browse", 100)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)
    m.app.openapi_schema = None
    desc = client.get("/openapi.json").json()["info"]["description"]
    assert "Uploads (`POST /file/upload`, `POST /api/v2/files`): 10 requests per 60s" in desc
    assert (
        "Browsing result pages (`GET /ui/`, `/ui/search`, `/ui/file/{hash}`): 100 requests per 60s"
        in desc
    )
    assert "HTTP 429" in desc
    m.app.openapi_schema = None


def test_startup_recovers_pending_scans():
    import time

    from fastapi.testclient import TestClient

    from app.db import Base, SessionLocal, engine
    from app.main import app
    from app.models import Scan

    Base.metadata.create_all(engine)
    content = b"pending recovery sample"
    sha = hashlib.sha256(content).hexdigest()
    sha_gone = "c" * 64
    with SessionLocal() as db:
        for s in (sha, sha_gone):
            db.add(
                Scan(
                    sha256=s,
                    md5="4" * 32,
                    sha1="4" * 40,
                    file_name=f"{s[:6]}.bin",
                    size=len(content),
                    file_type="data",
                    magic_hex="",
                    verdict="pending",
                    status="pending",
                    engine="pending",
                    urls=[],
                )
            )
        db.commit()
    Path(settings.upload_dir, sha).write_bytes(content)  # stored sample exists
    # sha_gone has no file on disk -> row must be deleted on startup

    with TestClient(app):  # entering the client runs the lifespan -> recovery
        for _ in range(50):
            with SessionLocal() as db:
                row = db.get(Scan, sha)
                gone = db.get(Scan, sha_gone)
                if row and row.status == "done" and gone is None:
                    break
            time.sleep(0.1)
    with SessionLocal() as db:
        row = db.get(Scan, sha)
        assert row is not None and row.status == "done"  # re-scanned from the stored file
        assert db.get(Scan, sha_gone) is None  # deleted: file was gone


def test_openapi_documents_response_models(client):
    spec = client.get("/openapi.json").json()
    schemas = spec["components"]["schemas"]
    for name in [
        "UploadResponse",
        "ApiScanResponse",
        "FileReport",
        "HealthResponse",
        "EngineVerdict",
    ]:
        assert name in schemas, name
    upload = spec["paths"]["/file/upload"]["post"]
    assert upload["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/UploadResponse"
    )
    assert "202" in upload["responses"]
    api = spec["paths"]["/api/v2/files"]["post"]
    assert api["responses"]["202"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ApiScanResponse"
    )
    report = spec["paths"]["/api/v2/files/{hash_value}"]["get"]
    assert report["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/FileReport"
    )
    assert "404" in report["responses"]
    # FileReport fields are explicit
    props = schemas["FileReport"]["properties"]
    for f in ["sha256", "verdict", "status", "engines", "iocs", "behavior", "scanned_at"]:
        assert f in props, f
    assert props["engines"]["items"]["$ref"].endswith("/EngineVerdict")


def test_chunked_upload_assembles_and_scans(client, monkeypatch):
    import time

    monkeypatch.setattr(settings, "chunk_upload_size", 1024)  # 1 KiB chunks
    content = b"chunked upload test payload " * 200  # ~6 KiB -> 6 chunks
    sha = hashlib.sha256(content).hexdigest()
    total = 6
    for i in range(total - 1):
        r = client.post(
            "/file/upload/chunk",
            files={"file": (f"part{i}", content[i * 1024 : (i + 1) * 1024])},
            data={"sha256": sha, "index": str(i), "total": str(total), "name": "chunked.bin"},
        )
        assert r.status_code == 202
        assert r.json()["status"] == "chunk_stored"
        assert r.json()["received"] == i + 1
    # last chunk triggers assembly + scan
    r = client.post(
        "/file/upload/chunk",
        files={"file": ("part5", content[5 * 1024 :])},
        data={"sha256": sha, "index": "5", "total": str(total), "name": "chunked.bin"},
    )
    assert r.status_code == 202 and r.json()["sha256"] == sha
    for _ in range(50):
        if client.get(f"/api/v2/files/{sha}").json()["status"] == "done":
            break
        time.sleep(0.1)
    assert client.get(f"/api/v2/files/{sha}").json()["status"] == "done"
    assert not (Path(settings.upload_dir) / ".chunks" / sha).exists()  # cleaned up


def test_chunk_upload_rate_limit_scaled_by_chunk_size(client, monkeypatch):
    import app.main as m

    sha = "d" * 64
    # plain upload limit = 2 per window; chunk carries 1KB, max file is 512MB -> scaled up hugely
    monkeypatch.setattr(settings, "rate_limit_upload", 2)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 3600)
    monkeypatch.setattr(settings, "chunk_upload_size", 1024)
    monkeypatch.setattr(settings, "max_upload_size", 512 * 1024 * 1024)
    m._rate_buckets.clear()
    # many chunk requests must pass (scaled limit), while plain uploads are capped at 2
    for i in range(10):
        r = client.post(
            "/file/upload/chunk",
            files={"file": ("p", b"x" * 100)},
            data={"sha256": sha, "index": str(i), "total": "100"},
        )
        assert r.status_code == 202, (i, r.status_code)  # chunk_stored
    assert client.post("/file/upload", files={"file": ("a.bin", b"a" * 16)}).status_code in (
        200,
        202,
    )
    assert client.post("/file/upload", files={"file": ("b.bin", b"b" * 16)}).status_code in (
        200,
        202,
    )
    assert client.post("/file/upload", files={"file": ("c.bin", b"c" * 16)}).status_code == 429
    m._rate_buckets.clear()


def test_openapi_docs_mention_scaled_chunk_limit(client, monkeypatch):
    import app.main as m

    monkeypatch.setattr(settings, "rate_limit_upload", 5)
    monkeypatch.setattr(settings, "chunk_upload_size", 1024)
    monkeypatch.setattr(settings, "max_upload_size", 512 * 1024 * 1024)
    m.app.openapi_schema = None
    desc = client.get("/openapi.json").json()["info"]["description"]
    assert (
        "POST /file/upload/chunk" in desc and "scaled by MAX_UPLOAD_SIZE/CHUNK_UPLOAD_SIZE" in desc
    )
    m.app.openapi_schema = None


def test_chunked_upload_rejects_bad_input(client, monkeypatch):
    monkeypatch.setattr(settings, "chunk_upload_size", 1024)
    sha = "a" * 64
    # invalid sha / index / total
    assert (
        client.post(
            "/file/upload/chunk",
            files={"file": ("p", b"x")},
            data={"sha256": "zz", "index": "0", "total": "1"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/file/upload/chunk",
            files={"file": ("p", b"x")},
            data={"sha256": sha, "index": "5", "total": "2"},
        ).status_code
        == 400
    )
    # assembled hash mismatch -> 400, chunks cleaned
    r = client.post(
        "/file/upload/chunk",
        files={"file": ("p", b"wrong bytes")},
        data={"sha256": sha, "index": "0", "total": "1"},
    )
    assert r.status_code == 400
    assert "verification" in r.json()["detail"]
    # empty chunk rejected
    assert (
        client.post(
            "/file/upload/chunk",
            files={"file": ("p", b"")},
            data={"sha256": sha, "index": "0", "total": "1"},
        ).status_code
        == 400
    )
    # each chunk within MAX_UPLOAD_SIZE but their sum exceeds it -> 400 on assembly
    monkeypatch.setattr(settings, "max_upload_size", 10)
    for i in range(2):
        r = client.post(
            "/file/upload/chunk",
            files={"file": ("p", b"x" * 6)},
            data={"sha256": sha, "index": str(i), "total": "2"},
        )
    assert r.status_code == 400
    assert "verification" in r.json()["detail"]
    # disabled when CHUNK_UPLOAD_SIZE=0
    monkeypatch.setattr(settings, "chunk_upload_size", 0)
    assert (
        client.post(
            "/file/upload/chunk",
            files={"file": ("p", b"x")},
            data={"sha256": sha, "index": "0", "total": "1"},
        ).status_code
        == 404
    )


def test_healthz(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    clam, yara_eng, bl_eng = body["engines"]
    assert clam["type"] == "clamav" and clam["enabled"] and clam["ready"]
    assert clam["name"] == "ClamAV (fake)" and clam["version"] == "ClamAV 1.0.0 (fake)"
    assert clam["rules"] is None and clam["rules_updated_at"] is None  # no CLAMAV_DB_DIR
    assert yara_eng["type"] == "yara" and yara_eng["enabled"] and not yara_eng["ready"]
    assert yara_eng["version"] and yara_eng["rules"] is None
    # the domain feed is listed as an engine entry too (a feed, not a scan engine)
    assert bl_eng["type"] == "domain-feed" and bl_eng["enabled"]
    assert bl_eng["ready"] == (bl_eng["rules"] > 0)  # order-independent vs other tests


def test_healthz_clamav_down_is_degraded(client, monkeypatch):
    import app.main as main_module

    def boom():
        raise ScannerUnavailableError("no backend")

    monkeypatch.setattr(main_module, "get_scanner", boom)
    body = client.get("/healthz").json()
    assert body["status"] == "degraded"
    clam = body["engines"][0]
    assert clam["enabled"] and not clam["ready"]
    assert clam["name"] == "ClamAV" and clam["version"] is None


def test_healthz_engines_disabled_via_enabled_scanners(client, monkeypatch, tmp_path):
    import app.main as main_module
    from app.config import settings

    (tmp_path / "r.yar").write_text("rule R1 { condition: true }\nrule R2 { condition: true }")
    monkeypatch.setattr(main_module, "enabled_scanners", lambda: {"yara"})
    monkeypatch.setattr(settings, "yara_rules_dir", str(tmp_path))

    reset_yara_cache()
    body = client.get("/healthz").json()
    reset_yara_cache()
    assert body["status"] == "ok"
    clam, yara_eng, _bl_eng = body["engines"]
    assert clam == {
        "name": "ClamAV",
        "type": "clamav",
        "enabled": False,
        "ready": False,
        "version": None,
        "rules": None,
        "rules_updated_at": None,
        "detail": None,
    }
    # healthz reports yara stats from disk WITHOUT compiling the rules (no per-worker spike)
    assert yara_eng["enabled"] and yara_eng["ready"] and yara_eng["rules"] == 2
    assert yara_eng["rules_updated_at"] is not None


def test_healthz_yara_disabled_via_enabled_scanners(client, monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "enabled_scanners", lambda: {"clamav"})
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    yara_eng = body["engines"][1]
    assert yara_eng == {
        "name": "YARA (local rules)",
        "type": "yara",
        "enabled": False,
        "ready": False,
        "version": None,
        "rules": None,
        "rules_updated_at": None,
        "detail": None,
    }


def test_healthz_reports_clamav_db_stats(client, monkeypatch, tmp_path):
    from app.config import settings

    (tmp_path / "main.cvd").write_bytes(b"ClamAV-VDB:05 Nov 2026:27800:1234567:80:" + b"0" * 480)
    (tmp_path / "extra.hdb").write_text("a:1:S1\n# comment\n\nb:2:S2\n")
    monkeypatch.setattr(settings, "clamav_db_dir", str(tmp_path))
    body = client.get("/healthz").json()
    clam = body["engines"][0]
    assert clam["ready"] and clam["rules"] == 1234567 + 2
    assert clam["rules_updated_at"] is not None


def test_rate_limits_disabled_by_default(client):
    for i in range(5):
        r = client.post("/file/upload", files={"file": ("rl-off.bin", bytes([i]) * 16)})
        assert r.status_code in (200, 202)
        assert client.get("/ui/").status_code == 200
        assert client.get("/ui/search?q=x").status_code == 200


def test_upload_rate_limit_enforced_per_ip(client, monkeypatch):
    import app.main as m

    monkeypatch.setattr(settings, "rate_limit_upload", 2)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 3600)
    m._rate_buckets.clear()
    codes = [
        client.post(
            "/file/upload", files={"file": ("rl.bin", f"upload-rl-{i}".encode() * 4)}
        ).status_code
        for i in range(3)
    ]
    assert codes[:2] == [202, 202]
    assert codes[2] == 429
    # the api upload endpoint shares the same upload limit
    assert client.post("/api/v2/files", files={"file": ("rl2.bin", b"x" * 16)}).status_code == 429
    # browsing is unaffected by the upload limit
    assert client.get("/ui/").status_code == 200
    m._rate_buckets.clear()


def test_browse_rate_limit_enforced(client, monkeypatch):
    import app.main as m

    monkeypatch.setattr(settings, "rate_limit_browse", 2)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 3600)
    m._rate_buckets.clear()
    assert client.get("/ui/").status_code == 200
    assert client.get("/ui/search?q=x").status_code == 200
    assert client.get("/ui/").status_code == 429
    assert client.get(f"/ui/file/{'a' * 64}").status_code == 429
    # uploads are unaffected by the browse limit
    assert client.post("/file/upload", files={"file": ("rl3.bin", b"y" * 16)}).status_code in (
        200,
        202,
    )
    m._rate_buckets.clear()


def test_rate_limit_window_reset_and_bucket_purge(client, monkeypatch):
    import time

    import app.main as m

    monkeypatch.setattr(settings, "rate_limit_upload", 1)
    monkeypatch.setattr(
        settings, "rate_limit_window_seconds", 0
    )  # every request starts a new window
    m._rate_buckets.clear()
    for i in range(3):  # window resets each time, so never limited
        r = client.post("/file/upload", files={"file": ("w.bin", f"win-{i}".encode() * 4)})
        assert r.status_code in (200, 202)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 3600)
    m._rate_buckets.clear()
    assert client.post("/file/upload", files={"file": ("w2.bin", b"w2" * 8)}).status_code == 202
    assert client.post("/file/upload", files={"file": ("w3.bin", b"w3" * 8)}).status_code == 429
    # force the memory-bound purge path with >10000 stale buckets
    m._rate_buckets.update({f"stale:{i}": (time.time() - 7200, 1) for i in range(10001)})
    assert client.post("/file/upload", files={"file": ("w4.bin", b"w4" * 8)}).status_code == 429
    assert all(not k.startswith("stale:") for k in m._rate_buckets)
    m._rate_buckets.clear()


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


def test_upload_no_engine_available_503(client, monkeypatch):
    # e.g. ENABLED_SCANNERS=yara without YARA_RULES_DIR: fail fast instead of
    # leaving the scan 'pending' forever
    import app.main as main_module
    from app.main import app

    monkeypatch.setitem(app.dependency_overrides, get_scanner, lambda: None)
    monkeypatch.setattr(main_module, "get_yara_scanner", lambda: None)
    response = client.post("/file/upload", files={"file": ("x.bin", b"data")})
    assert response.status_code == 503
    assert "no scan engines" in response.json()["detail"]


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


def test_root_and_ui_serve_same_page(client):
    client.post("/file/upload", files={"file": ("root.bin", b"root page")})
    root = client.get("/")
    ui = client.get("/ui/")
    assert root.status_code == 200 and ui.status_code == 200  # no redirect anymore
    assert "Analyze suspicious" in root.text and "Analyze suspicious" in ui.text
    assert "root.bin" in root.text and "root.bin" in ui.text  # same content on both


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


def test_favicon_served(client):
    response = client.get("/favicon.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in response.text
    assert 'href="/favicon.svg"' in client.get("/ui/").text


def test_pending_page_uses_configured_poll_interval(client, monkeypatch):
    monkeypatch.setattr(settings, "scan_poll_interval_ms", 7000)
    sha = "ef" * 32
    from app.db import SessionLocal
    from app.models import Scan

    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="2" * 32,
                sha1="2" * 40,
                file_name="poll.bin",
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
    assert 'data-interval="7000"' in client.get(f"/ui/file/{sha}").text


def test_prune_uploads_removes_stale_chunk_dirs(tmp_path, monkeypatch):
    import os
    import time

    from app.main import _prune_uploads

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    chunks = tmp_path / ".chunks"
    stale = chunks / ("a" * 64)
    fresh = chunks / ("b" * 64)
    stale.mkdir(parents=True)
    fresh.mkdir(parents=True)
    (stale / "000000").write_bytes(b"partial")
    (fresh / "000000").write_bytes(b"partial")
    old = time.time() - 7200
    os.utime(stale, (old, old))

    monkeypatch.setattr(settings, "uploads_ttl", -1)  # samples kept forever...
    _prune_uploads()
    assert not stale.exists()  # ...but stale chunk dirs are pruned regardless
    assert fresh.exists()

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path / "missing"))
    _prune_uploads()  # missing upload dir must not crash


def test_prune_uploads_ttl(tmp_path, monkeypatch):
    from app.main import _prune_uploads

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    old = tmp_path / "old.bin"
    new = tmp_path / "new.bin"
    old.write_bytes(b"old")
    new.write_bytes(b"new")
    import os
    import time

    old_ts = time.time() - 3600
    os.utime(old, (old_ts, old_ts))

    monkeypatch.setattr(settings, "uploads_ttl", -1)
    _prune_uploads()
    assert old.exists() and new.exists()  # kept forever

    monkeypatch.setattr(settings, "uploads_ttl", 1)  # 1 minute
    _prune_uploads()
    assert not old.exists() and new.exists()

    monkeypatch.setattr(settings, "uploads_ttl", 0)  # delete immediately
    _prune_uploads()
    assert not new.exists()


def test_upload_ttl_zero_deletes_sample_after_scan(client, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "uploads_ttl", 0)
    content = b"ttl zero sample"
    client.post("/file/upload", files={"file": ("ttl0.bin", content)})
    sha = hashlib.sha256(content).hexdigest()
    stored = Path(settings.upload_dir) / sha
    assert not stored.exists()  # deleted right after the async scan
    # report still works (metadata kept in DB); download 404s
    assert client.get(f"/ui/file/{sha}").status_code == 200
    assert client.get(f"/ui/file/{sha}/download").status_code == 404


def test_prune_scans_ttl(client, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from app.db import SessionLocal
    from app.main import _prune_scans
    from app.models import Scan

    assert settings.scans_ttl == -1  # default: scans are stored infinitely

    def add_scan(sha, status, scanned_at):
        with SessionLocal() as db:
            db.add(
                Scan(
                    sha256=sha,
                    md5="0" * 32,
                    sha1="0" * 40,
                    file_name="s.bin",
                    size=1,
                    file_type="data",
                    magic_hex="",
                    verdict="clean" if status == "done" else "pending",
                    status=status,
                    engine="x",
                    urls=[],
                    scanned_at=scanned_at,
                )
            )
            db.commit()

    def exists(sha):
        with SessionLocal() as db:
            return db.get(Scan, sha) is not None

    now = datetime.now(UTC)
    fresh_done = "e1" * 32
    old_done = "e2" * 32
    old_pending = "e3" * 32
    add_scan(fresh_done, "done", now)
    add_scan(old_done, "done", now - timedelta(minutes=10))
    add_scan(old_pending, "pending", now - timedelta(minutes=10))
    # a stored sample for the old done row — pruned together with the record
    sample = Path(settings.upload_dir) / old_done
    sample.write_bytes(b"orphan sample")

    monkeypatch.setattr(settings, "scans_ttl", -1)
    _prune_scans()
    assert exists(fresh_done) and exists(old_done) and exists(old_pending)

    monkeypatch.setattr(settings, "scans_ttl", 1)  # keep 1 minute
    _prune_scans()
    assert exists(fresh_done)
    assert not exists(old_done) and not sample.exists()  # record + sample pruned
    assert exists(old_pending)  # pending scans are never pruned

    monkeypatch.setattr(settings, "scans_ttl", 0)  # delete immediately
    _prune_scans()
    assert not exists(fresh_done)
    assert exists(old_pending)


def test_upload_scans_ttl_zero_deletes_record_after_scan(client, monkeypatch):
    monkeypatch.setattr(settings, "scans_ttl", 0)
    content = b"scans ttl zero sample"
    client.post("/file/upload", files={"file": ("sttl0.bin", content)})
    sha = hashlib.sha256(content).hexdigest()
    # the scan ran (background task), then the record was deleted: no report, no API row
    assert client.get(f"/api/v2/files/{sha}").status_code == 404
    assert client.get(f"/ui/file/{sha}").status_code == 404
    assert not (Path(settings.upload_dir) / sha).exists()  # sample deleted with the record


def _add_scan_row(sha, status="done"):
    from app.db import SessionLocal
    from app.models import Scan

    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="0" * 32,
                sha1="0" * 40,
                file_name="s.bin",
                size=1,
                file_type="data",
                magic_hex="",
                verdict="clean" if status == "done" else "pending",
                status=status,
                engine="x",
                urls=[],
            )
        )
        db.commit()


def test_purge_uploads_keeps_sample_of_active_scan(tmp_path, monkeypatch):
    # a sample whose scan is enqueued/running (or whose row is still pending) must
    # survive even UPLOADS_TTL=0 — the in-flight scan still reads it by path
    from app.db import SessionLocal
    from app.main import (
        _prune_uploads,
        _sample_in_use,
        _scan_finished,
        _scan_started,
    )
    from app.models import Scan

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    monkeypatch.setattr(settings, "uploads_ttl", 0)
    sha = "ab" * 32
    sample = tmp_path / sha
    sample.write_bytes(b"in flight")
    _add_scan_row(sha, status="pending")

    _scan_started(sha)  # a scan is running for this hash
    with SessionLocal() as db:
        assert _sample_in_use(sha, db) is True
        assert _sample_in_use(sha, db, ignore=1) is True  # row still pending
        assert _sample_in_use("cd" * 32, db) is False  # no row, no scans
    _prune_uploads()
    assert sample.exists()  # in-flight: kept

    _scan_finished(sha)  # scan done, but the row is still pending
    with SessionLocal() as db:
        assert _sample_in_use(sha, db) is True  # pending row protects it
    _prune_uploads()
    assert sample.exists()

    with SessionLocal() as db:  # row finished -> no longer protected
        row = db.get(Scan, sha)
        assert row is not None
        row.status = "done"
        db.commit()
    _prune_uploads()
    assert not sample.exists()


def test_prune_scans_keeps_rescan_enqueued_mid_prune(client, monkeypatch):
    # a rescan enqueued while the TTL sweep runs must keep its record AND sample
    from datetime import UTC, datetime, timedelta

    from app.main import _prune_scans, _scan_finished, _scan_started

    sha = "ef" * 32
    _add_scan_row(sha, status="done")
    from app.db import SessionLocal
    from app.models import Scan  # noqa: F811

    with SessionLocal() as db:
        row = db.get(Scan, sha)
        assert row is not None
        row.scanned_at = datetime.now(UTC) - timedelta(minutes=10)
        db.commit()
    sample = Path(settings.upload_dir) / sha
    sample.write_bytes(b"rescan me")
    monkeypatch.setattr(settings, "scans_ttl", 0)

    _scan_started(sha)  # concurrent rescan in flight
    _prune_scans()
    with SessionLocal() as db:
        assert db.get(Scan, sha) is not None
    assert sample.exists()

    _scan_finished(sha)  # no other scan running anymore
    _prune_scans()
    with SessionLocal() as db:
        assert db.get(Scan, sha) is None
    assert not sample.exists()


def test_run_scan_ttl_zero_keeps_sample_while_rescan_in_flight(client, monkeypatch, tmp_path):
    # UPLOADS_TTL=0 must not delete the stored sample while ANOTHER scan for the
    # same hash is still running — that race made clamd's FILDES os.open() fail
    import app.main as main_module

    monkeypatch.setattr(settings, "uploads_ttl", 0)
    content = b"raced sample"
    sha = hashlib.sha256(content).hexdigest()
    stored = Path(settings.upload_dir) / sha
    stored.write_bytes(content)

    main_module._scan_started(sha)  # the current scan's own reference
    main_module._scan_started(sha)  # a concurrent rescan of the same hash
    main_module._run_scan(content, "raced.bin", path=stored)
    assert stored.exists()  # concurrent scan still needs the file

    main_module._scan_finished(sha)  # the other scan finished
    main_module._run_scan(content, "raced.bin", path=stored)
    assert not stored.exists()  # last scan out deletes it
    main_module._scan_finished(sha)


def test_enqueue_marks_sample_in_flight_until_task_finishes(client, tmp_path):
    from fastapi import BackgroundTasks

    import app.main as main_module
    from app.analysis import compute_hashes

    content = b"enqueue guard sample"
    hashes = compute_hashes(content)
    path = Path(settings.upload_dir) / hashes["sha256"]
    path.write_bytes(content)
    from app.db import SessionLocal

    with SessionLocal() as db:
        main_module._enqueue_scan_file(BackgroundTasks(), db, path, hashes, "g.bin")
        assert main_module._scans_in_flight[hashes["sha256"]] == 1  # protected at enqueue
    # ... the background task runs and releases the reference
    # (covered end-to-end by the client upload tests; here just release manually)
    main_module._scan_finished(hashes["sha256"])
    assert hashes["sha256"] not in main_module._scans_in_flight


def test_privacy_policy_scans_ttl_sentence_reflects_setting(client, monkeypatch):
    from app.config import settings as s

    monkeypatch.setattr(s, "scans_ttl", -1)
    page = client.get("/ui/privacy").text
    assert "All scan results are kept indefinitely." in page  # default: stored infinitely
    monkeypatch.setattr(s, "scans_ttl", 0)
    page = client.get("/ui/privacy").text
    assert "All scan results are deleted right after the scan finishes." in page
    monkeypatch.setattr(s, "scans_ttl", 5)
    page = client.get("/ui/privacy").text
    assert (
        "All scan results are deleted after 5 minutes. A background job prunes them every minute."
        in page
    )
    assert "deleted with it" in page  # sample goes away together with its scan result


def test_search_by_domain_ip_url_and_partial_hash(client):
    import time

    content = (
        b"indicator rich sample http://evil-example.com/payload 185.220.101.4 bad@evil-example.com"
    )
    client.post("/file/upload", files={"file": ("evil.bin", content)})
    sha = hashlib.sha256(content).hexdigest()
    for _ in range(30):
        if client.get(f"/api/v2/files/{sha}").json()["status"] == "done":
            break
        time.sleep(0.2)
    for q in [
        "evil-example.com",
        "185.220.101.4",
        "evil-example.com/payload",
        "bad@evil-example.com",
        sha[:16],
        sha,
    ]:
        page = client.get("/ui/search", params={"q": q})
        assert page.status_code in (200, 303), q
        if page.status_code == 200:
            assert "evil.bin" in page.text, f"q={q} did not find the file"


def test_search_no_false_positives(client):
    client.post("/file/upload", files={"file": ("plain.bin", b"nothing here")})
    page = client.get("/ui/search", params={"q": "totally-unrelated-xyz"})
    assert page.status_code == 200
    assert "No results found" in page.text


def test_privacy_policy_page(client):
    page = client.get("/ui/privacy")
    assert page.status_code == 200
    assert "Privacy policy" in page.text
    # linked from every page footer
    assert 'href="/ui/privacy"' in client.get("/ui/").text


def test_privacy_policy_is_user_focused(client):
    page = client.get("/ui/privacy").text
    assert "sent to the ClamTotal server" in page
    assert "nothing leaves your machine" not in page
    assert "What we collect" in page
    assert "stored in the local SQLite database on the server" in page


def test_privacy_policy_ttl_sentence_reflects_setting(client, monkeypatch):
    from app.config import settings as s

    monkeypatch.setattr(s, "uploads_ttl", -1)
    page = client.get("/ui/privacy").text
    assert "All uploaded files are kept indefinitely." in page
    assert "prunes" not in page  # nothing is ever pruned when kept indefinitely
    monkeypatch.setattr(s, "uploads_ttl", 0)
    page = client.get("/ui/privacy").text
    assert "All uploaded files are deleted right after upload." in page
    assert "prunes" not in page
    monkeypatch.setattr(s, "uploads_ttl", 5)
    assert (
        "All uploaded files are deleted after 5 minutes. A background job prunes them every minute."
        in client.get("/ui/privacy").text
    )
    monkeypatch.setattr(s, "uploads_ttl", 1)
    assert "All uploaded files are deleted after 1 minute." in client.get("/ui/privacy").text
    monkeypatch.setattr(s, "uploads_ttl", 120)
    assert "All uploaded files are deleted after 2 hours." in client.get("/ui/privacy").text
    monkeypatch.setattr(s, "uploads_ttl", 7200)
    assert "All uploaded files are deleted after 5 days." in client.get("/ui/privacy").text


def _ws_start(ws, sha, total, name="ws.bin"):
    ws.send_text(json.dumps({"type": "start", "sha256": sha, "total": total, "name": name}))


def test_upload_endpoints_accept_rescan_flag(client, fake):
    content = b"rescan flag sample"
    sha = hashlib.sha256(content).hexdigest()
    assert client.post("/file/upload", files={"file": ("r.bin", content)}).status_code == 202
    # without the flag the cached report is returned (200)
    r = client.post("/file/upload", files={"file": ("r.bin", content)})
    assert r.status_code == 200 and r.json()["cached"] is True
    # whole-file upload with rescan=true forces a new scan (202, scanner re-run)
    calls = fake.calls
    r = client.post("/file/upload?rescan=true", files={"file": ("r.bin", content)})
    assert r.status_code == 202 and r.json()["cached"] is False
    assert fake.calls == calls + 1
    # VT-style API accepts the same flag
    calls = fake.calls
    r = client.post("/api/v2/files?rescan=true", files={"file": ("r.bin", content)})
    assert r.status_code == 202
    assert fake.calls == calls + 1
    assert client.get(f"/api/v2/files/{sha}").json()["status"] == "done"


def test_chunk_upload_rescan_flag(client, fake, monkeypatch):
    monkeypatch.setattr(settings, "chunk_upload_size", 4)
    content = b"chunk-rescan-flag-sample"  # 24 bytes -> 6 chunks of 4
    sha = hashlib.sha256(content).hexdigest()
    client.post("/file/upload", files={"file": ("c.bin", content)})
    calls = fake.calls
    resp = None
    for i in range(6):
        resp = client.post(
            "/file/upload/chunk",
            data={"sha256": sha, "index": str(i), "total": "6", "name": "c.bin", "rescan": "true"},
            files={"file": ("c.bin", content[i * 4 : (i + 1) * 4])},
        )
    assert resp.status_code == 202 and resp.json()["cached"] is False
    assert fake.calls == calls + 1  # the rescan flag forced a new scan
    assert client.get(f"/api/v2/files/{sha}").json()["status"] == "done"


def test_ws_upload_rescan_flag(client, fake, monkeypatch):
    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    content = b"ws rescan flag sample"
    sha = hashlib.sha256(content).hexdigest()
    client.post("/file/upload", files={"file": ("w.bin", content)})
    calls = fake.calls
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text(
            json.dumps(
                {"type": "start", "sha256": sha, "total": 1, "name": "w.bin", "rescan": True}
            )
        )
        assert ws.receive_json()["type"] == "ready"
        ws.send_text(json.dumps({"type": "chunk", "index": 0, "size": len(content)}))
        ws.send_bytes(content)
        assert ws.receive_json()["type"] == "ack"
        done = ws.receive_json()
    assert done["type"] == "done" and done["cached"] is False
    # the scan runs in a daemon thread — wait for it like the happy-path test does
    import time

    for _ in range(50):
        if fake.calls > calls:
            break
        time.sleep(0.1)
    assert fake.calls == calls + 1


def test_ws_upload_happy_path_with_resume(client, monkeypatch):
    import time

    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    content = b"ws upload test payload " * 200  # 4600 bytes -> 5 chunks of 1 KiB
    sha = hashlib.sha256(content).hexdigest()
    total = 5
    # pre-store chunk 0 to exercise resume ("ready" must report it)
    chunks_dir = Path(settings.upload_dir) / ".chunks" / sha
    chunks_dir.mkdir(parents=True)
    (chunks_dir / "000000").write_bytes(content[:1024])
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, sha, total)
        ready = ws.receive_json()
        assert ready["type"] == "ready" and ready["received"] == [0]
        for i in range(1, total):
            part = content[i * 1024 : (i + 1) * 1024]
            ws.send_text(json.dumps({"type": "chunk", "index": i, "size": len(part)}))
            ws.send_bytes(part)
            ack = ws.receive_json()
            assert ack["type"] == "ack" and ack["index"] == i
        done = ws.receive_json()
        assert done["type"] == "done" and done["sha256"] == sha
    for _ in range(50):
        if client.get(f"/api/v2/files/{sha}").json()["status"] == "done":
            break
        time.sleep(0.1)
    assert client.get(f"/api/v2/files/{sha}").json()["status"] == "done"
    assert not chunks_dir.exists()  # cleaned up


def test_ws_upload_error_paths(client, monkeypatch):
    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    sha = "b" * 64
    # disabled endpoint
    monkeypatch.setattr(settings, "ws_upload_enabled", False)
    with client.websocket_connect("/file/upload/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error" and "disabled" in msg["detail"]
    monkeypatch.setattr(settings, "ws_upload_enabled", True)
    # invalid sha256 in start
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, "zz", 1)
        assert "invalid sha256" in ws.receive_json()["detail"]
    # chunk header before start
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text(json.dumps({"type": "chunk", "index": 0, "size": 1}))
        assert ws.receive_json()["detail"] == "start first"
    # malformed control message
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text("not json")
        assert ws.receive_json()["detail"] == "malformed control message"
    # unknown type
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text(json.dumps({"type": "bogus"}))
        assert "unknown message type" in ws.receive_json()["detail"]
    # invalid index/size
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, sha, 2)
        assert ws.receive_json()["type"] == "ready"
        ws.send_text(json.dumps({"type": "chunk", "index": 5, "size": 1}))
        assert ws.receive_json()["detail"] == "invalid index/size"
    # binary before chunk header
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, sha, 1)
        ws.receive_json()
        ws.send_bytes(b"x")
        assert ws.receive_json()["detail"] == "chunk header first"
    # chunk size mismatch (more bytes than announced)
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, sha, 1)
        ws.receive_json()
        ws.send_text(json.dumps({"type": "chunk", "index": 0, "size": 1}))
        ws.send_bytes(b"xx")
        assert ws.receive_json()["detail"] == "chunk size mismatch"
    # assembled hash mismatch -> verification error, chunks cleaned
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, sha, 1)
        ws.receive_json()
        ws.send_text(json.dumps({"type": "chunk", "index": 0, "size": 3}))
        ws.send_bytes(b"abc")
        ack = ws.receive_json()
        assert ack["type"] == "ack"
        err = ws.receive_json()
        assert err["type"] == "error" and "verification" in err["detail"]
    assert not (Path(settings.upload_dir) / ".chunks" / sha).exists()


def test_ws_upload_client_disconnect_is_clean(client, monkeypatch):
    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    sha = "c" * 64
    with client.websocket_connect("/file/upload/ws") as ws:
        _ws_start(ws, sha, 10)
        assert ws.receive_json()["type"] == "ready"
    # context exit closes the socket mid-upload; server must not raise
