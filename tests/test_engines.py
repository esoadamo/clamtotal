"""Engine selection: `engines` picks which scan engines run on any upload path
(whole-file, HTTP chunked, WebSocket chunked, JSON API, rescan). Default: all."""

import hashlib
import json

import app.main as main_module
from app.scanner import ScannerUnavailableError


def _wait_done(client, sha: str) -> None:
    import time

    for _ in range(50):
        if client.get(f"/api/v2/files/{sha}").json().get("status") == "done":
            return
        time.sleep(0.1)
    raise AssertionError(f"scan for {sha} never finished")


def _engines(client, sha: str) -> list[dict]:
    return client.get(f"/api/v2/files/{sha}").json()["engines"]


def test_parse_engines_accepts_all_default_and_lists():
    assert main_module._parse_engines("") is None
    assert main_module._parse_engines(None) is None
    assert main_module._parse_engines("all") is None
    assert main_module._parse_engines(" clamav ") == frozenset({"clamav"})
    # selecting every available engine is the same as not selecting at all
    available = main_module._available_engines()
    assert main_module._parse_engines(",".join(sorted(available))) is None


def test_parse_engines_rejects_unknown_ids():
    import pytest
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        main_module._parse_engines("megascan,norton")
    assert exc.value.status_code == 400
    assert "unknown or unavailable engines" in exc.value.detail


def test_upload_runs_only_selected_engines(client):
    content = b"engine selection whole-file sample http://engine-test.example/x"
    sha = hashlib.sha256(content).hexdigest()
    r = client.post(
        "/file/upload", files={"file": ("e.bin", content)}, params={"engines": "clamav"}
    )
    assert r.status_code == 202
    _wait_done(client, sha)
    engines = _engines(client, sha)
    assert [e["name"] for e in engines] == ["ClamAV (fake)"]
    assert engines[0]["verdict"] == "clean"


def test_upload_rejects_unknown_engines(client):
    r = client.post(
        "/file/upload", files={"file": ("e.bin", b"blob")}, params={"engines": "yara,megascan"}
    )
    assert r.status_code == 400
    assert "megascan" in r.json()["detail"]


def test_api_v2_files_supports_engine_selection(client):
    content = b"engine selection json api sample"
    sha = hashlib.sha256(content).hexdigest()
    r = client.post(
        "/api/v2/files", files={"file": ("api.bin", content)}, params={"engines": "clamav"}
    )
    assert r.status_code == 202
    _wait_done(client, sha)
    assert [e["name"] for e in _engines(client, sha)] == ["ClamAV (fake)"]


def test_chunked_upload_supports_engine_selection(client):
    content = b"engine selection chunked sample http://engine-test.example/x"
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
                "engines": "clamav",
            },
        )
        assert r.status_code == 202
    _wait_done(client, sha)
    assert [e["name"] for e in _engines(client, sha)] == ["ClamAV (fake)"]


def test_ws_upload_supports_engine_selection(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    content = b"engine selection ws sample http://engine-test.example/x"
    sha = hashlib.sha256(content).hexdigest()
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text(
            json.dumps(
                {"type": "start", "sha256": sha, "total": 1, "name": "e.bin", "engines": ["clamav"]}
            )
        )
        assert ws.receive_json()["type"] == "ready"
        ws.send_text(json.dumps({"type": "chunk", "index": 0, "size": len(content)}))
        ws.send_bytes(content)
        assert ws.receive_json()["type"] == "ack"
        assert ws.receive_json()["type"] == "done"
    _wait_done(client, sha)
    assert [e["name"] for e in _engines(client, sha)] == ["ClamAV (fake)"]


def test_ws_upload_rejects_unknown_engines(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ws_chunk_size", 1024)
    with client.websocket_connect("/file/upload/ws") as ws:
        ws.send_text(
            json.dumps({"type": "start", "sha256": "a" * 64, "total": 1, "engines": "megascan"})
        )
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "megascan" in msg["detail"]


def test_rescan_with_engine_selection(client):
    content = b"engine selection rescan sample"
    sha = hashlib.sha256(content).hexdigest()
    client.post("/file/upload", files={"file": ("e.bin", content)})
    _wait_done(client, sha)
    r = client.post(f"/ui/file/{sha}/rescan", params={"engines": "clamav"}, follow_redirects=False)
    assert r.status_code == 303
    _wait_done(client, sha)
    assert [e["name"] for e in _engines(client, sha)] == ["ClamAV (fake)"]


def test_home_page_shows_engine_picker(client):
    home = client.get("/ui/").text
    assert 'id="engine-picker"' in home
    assert 'class="engine-check"' in home
    assert 'value="clamav"' in home
    assert "ClamAV (fake)" in home  # label from the active scanner
    assert "Engines to run (all by default)" in home


def test_engine_choices_include_yara_when_available(client, monkeypatch):
    class FakeYara:
        engine = "YARA (fake)"

    monkeypatch.setattr(main_module, "get_yara_scanner", lambda: FakeYara())
    home = client.get("/ui/").text
    assert 'value="yara"' in home
    assert "YARA (fake)" in home
    # the same fake also makes yara a valid `engines` selection on the API
    assert main_module._parse_engines("yara") == frozenset({"yara"})


def test_engine_choices_fallback_label_when_clamav_down(client, monkeypatch):
    def _raise():
        raise ScannerUnavailableError("clamd not reachable")

    monkeypatch.setattr(main_module, "get_scanner", _raise)
    home = client.get("/ui/").text
    assert 'value="clamav"' in home
    assert "ClamAV (fake)" not in home  # fallback label used instead of the scanner's
