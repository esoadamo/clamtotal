import hashlib
import json
import time
from pathlib import Path

from app.config import settings
from app.db import SessionLocal
from app.models import Scan


def _wait_done(client, sha: str) -> None:
    for _ in range(50):
        if client.get(f"/api/v2/files/{sha}").json().get("status") == "done":
            return
        time.sleep(0.1)
    raise AssertionError(f"scan for {sha} never finished")


def _assert_deleted(sha: str) -> None:
    assert not (Path(settings.upload_dir) / sha).exists()
    with SessionLocal() as db:
        assert db.get(Scan, sha) is None


def test_ephemeral_full_upload_deleted_after_one_view(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_ephemeral_upload", True)
    content = b"ephemeral full upload sample"
    sha = hashlib.sha256(content).hexdigest()
    r = client.post(
        "/file/upload", files={"file": ("e.bin", content)}, params={"ephemeral": "true"}
    )
    assert r.status_code == 202
    _wait_done(client, sha)
    # first view of the finished report: rendered once...
    assert client.get(f"/ui/file/{sha}").status_code == 200
    # ...then the sample AND the scan result are deleted
    _assert_deleted(sha)
    assert client.get(f"/ui/file/{sha}").status_code == 404
    assert client.get(f"/api/v2/files/{sha}").status_code == 404


def test_ephemeral_chunked_upload_deleted_after_one_view(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_ephemeral_upload", True)
    content = b"ephemeral chunked upload sample"
    sha = hashlib.sha256(content).hexdigest()
    half = len(content) // 2
    for i, part in enumerate((content[:half], content[half:])):
        r = client.post(
            "/file/upload/chunk",
            files={"file": ("e.bin", part)},
            data={
                "sha256": sha,
                "index": str(i),
                "total": "2",
                "name": "e.bin",
                "ephemeral": "true",
            },
        )
        assert r.status_code == 202
    _wait_done(client, sha)
    assert client.get(f"/ui/file/{sha}").status_code == 200
    _assert_deleted(sha)


def test_ephemeral_ws_upload_deleted_after_one_view(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_ephemeral_upload", True)
    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    content = b"ephemeral ws upload sample"
    sha = hashlib.sha256(content).hexdigest()
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text(
            json.dumps(
                {"type": "start", "sha256": sha, "total": 1, "name": "e.bin", "ephemeral": True}
            )
        )
        assert ws.receive_json()["type"] == "ready"
        ws.send_text(json.dumps({"type": "chunk", "index": 0, "size": len(content)}))
        ws.send_bytes(content)
        assert ws.receive_json()["type"] == "ack"
        assert ws.receive_json()["type"] == "done"
    _wait_done(client, sha)
    assert client.get(f"/ui/file/{sha}").status_code == 200
    _assert_deleted(sha)


def test_ephemeral_ignored_when_disabled(client):
    assert settings.allow_ephemeral_upload is False  # default off
    content = b"ephemeral disabled upload sample"
    sha = hashlib.sha256(content).hexdigest()
    client.post("/file/upload", files={"file": ("e.bin", content)}, params={"ephemeral": "true"})
    _wait_done(client, sha)
    assert client.get(f"/ui/file/{sha}").status_code == 200
    assert client.get(f"/ui/file/{sha}").status_code == 200  # nothing deleted
    with SessionLocal() as db:
        assert db.get(Scan, sha) is not None


def test_ephemeral_marks_cached_row_on_second_upload(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_ephemeral_upload", True)
    content = b"ephemeral cache hit sample"
    sha = hashlib.sha256(content).hexdigest()
    client.post("/file/upload", files={"file": ("e.bin", content)})
    _wait_done(client, sha)
    # second upload of the same file with the checkbox: cache hit, row marked ephemeral
    r = client.post(
        "/file/upload", files={"file": ("e.bin", content)}, params={"ephemeral": "true"}
    )
    assert r.status_code == 200 and r.json()["cached"] is True
    assert client.get(f"/ui/file/{sha}").status_code == 200
    _assert_deleted(sha)


def test_ephemeral_rescan_of_existing_row(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_ephemeral_upload", True)
    content = b"ephemeral rescan sample"
    sha = hashlib.sha256(content).hexdigest()
    client.post("/file/upload", files={"file": ("e.bin", content)})
    _wait_done(client, sha)
    # rescan + ephemeral: the pending row is flagged, then deleted after one view
    r = client.post(
        "/file/upload",
        files={"file": ("e.bin", content)},
        params={"rescan": "true", "ephemeral": "true"},
    )
    assert r.status_code == 202
    _wait_done(client, sha)
    assert client.get(f"/ui/file/{sha}").status_code == 200
    _assert_deleted(sha)


def test_index_passes_ephemeral_flag_to_the_ui(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_ephemeral_upload", True)
    assert 'data-ephemeral="1"' in client.get("/ui/").text
    monkeypatch.setattr(settings, "allow_ephemeral_upload", False)
    assert 'data-ephemeral="0"' in client.get("/ui/").text
