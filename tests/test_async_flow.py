import hashlib

from fakes import fake_scanner

import app.main as main_module
from app.db import SessionLocal
from app.models import Scan
from app.scanner import ScannerUnavailableError, ScanResult


def test_pending_report_page_shows_spinner_and_polls(client):
    sha = "ab" * 32
    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="0" * 32,
                sha1="0" * 40,
                file_name="pending.bin",
                size=10,
                file_type="data",
                magic_hex="",
                verdict="pending",
                status="pending",
                engine="pending",
                urls=[],
                engines=[
                    {"name": "ClamAV (fake)", "status": "scanning"},
                    {"name": "YARA (local rules)", "status": "scanning"},
                ],
            )
        )
        db.commit()
    page = client.get(f"/ui/file/{sha}")
    assert page.status_code == 200
    assert "Scanning pending.bin" in page.text
    assert 'id="pending-data"' in page.text  # app.js polls /api/v2/files/{sha} until done
    assert 'id="engine-progress"' in page.text  # per-engine rows while scanning
    assert page.text.count('class="engine-row"') == 2
    api = client.get(f"/api/v2/files/{sha}").json()
    assert api["status"] == "pending"
    assert [e["status"] for e in api["engines"]] == ["scanning", "scanning"]


def test_engine_results_committed_as_they_arrive(client):
    """While the ClamAV engine is still running, the row already exists with that
    engine marked 'scanning'; once scan() returns, its entry flips to 'done'."""
    content = b"live engine progress sample"
    sha = hashlib.sha256(content).hexdigest()
    observed: dict = {}

    class SlowScanner:
        engine = "ClamAV (slow)"

        def scan(self, data, path=None):
            with SessionLocal() as db:  # separate session sees the committed progress
                row = db.get(Scan, sha)
                assert row is not None
                observed["status"] = row.status
                observed["engines"] = [dict(e) for e in (row.engines or [])]
            return ScanResult("clean", None, self.engine, "stdin: OK")

    with SessionLocal() as db:
        scan, cached = main_module._scan_and_store(db, SlowScanner(), content, "live.bin", False)
    assert cached is False
    assert observed["status"] == "pending"
    assert observed["engines"] == [{"name": "ClamAV (slow)", "status": "scanning"}]
    assert scan.status == "done"
    assert scan.engines == [
        {"name": "ClamAV (slow)", "status": "done", "verdict": "clean", "signature": None}
    ]


def test_engine_progress_includes_yara_when_available(client, monkeypatch, tmp_path):
    from app.scanner import YaraScanner

    (tmp_path / "test.yar").write_text(
        'rule Test_Marker { strings: $m = "MALWARE-MARKER-XYZ" condition: $m }'
    )
    monkeypatch.setattr(main_module, "get_yara_scanner", lambda: YaraScanner(str(tmp_path)))
    content = b"contains MALWARE-MARKER-XYZ here"
    with SessionLocal() as db:
        scan, _ = main_module._scan_and_store(db, fake_scanner, content, "m.bin", False)
    engines = scan.engines or []
    assert [e["name"] for e in engines] == ["ClamAV (fake)", "YARA (local rules)"]
    assert all(e["status"] == "done" for e in engines)
    assert engines[1]["verdict"] == "infected"
    assert engines[1]["signature"] == "Test_Marker"


def test_enqueue_marks_engines_scanning(client):
    from pathlib import Path

    from fastapi import BackgroundTasks

    from app.analysis import compute_hashes
    from app.config import settings

    content = b"enqueue engines state"
    sha = hashlib.sha256(content).hexdigest()
    path = Path(settings.upload_dir) / sha
    path.write_bytes(content)
    hashes = compute_hashes(content)
    with SessionLocal() as db:
        scan, cached = main_module._enqueue_scan_file(
            BackgroundTasks(), db, path, hashes, "enq.bin"
        )
        assert cached is False
        assert scan.status == "pending"
        assert scan.engines == [{"name": "ClamAV (fake)", "status": "scanning"}]
        # a forced rescan resets the per-engine progress back to "scanning"
        scan.status = "done"
        scan.verdict = "clean"
        db.commit()
        scan2, cached2 = main_module._enqueue_scan_file(
            BackgroundTasks(), db, path, hashes, "enq.bin", rescan=True
        )
        assert cached2 is False
        assert scan2.engines == [{"name": "ClamAV (fake)", "status": "scanning"}]


def test_scanning_engines_falls_back_without_clamav(client, monkeypatch):
    def boom():
        raise ScannerUnavailableError("no backend")

    monkeypatch.setattr(main_module, "get_scanner", boom)
    assert main_module._scanning_engines() == [{"name": "ClamAV", "status": "scanning"}]


def test_scanning_engines_lists_yara_when_available(client, monkeypatch, tmp_path):
    from app.scanner import YaraScanner

    (tmp_path / "r.yar").write_text("rule R { condition: true }")
    monkeypatch.setattr(main_module, "get_yara_scanner", lambda: YaraScanner(str(tmp_path)))
    engines = main_module._scanning_engines()
    assert [e["name"] for e in engines] == ["ClamAV (fake)", "YARA (local rules)"]
    assert all(e["status"] == "scanning" for e in engines)


def test_upload_twice_second_is_cached_200(client):
    content = b"cached async upload"
    first = client.post("/file/upload", files={"file": ("c.bin", content)})
    assert first.status_code == 202
    second = client.post("/file/upload", files={"file": ("c.bin", content)})
    assert second.status_code == 200
    assert second.json()["cached"] is True
    assert second.json()["sha256"] == hashlib.sha256(content).hexdigest()


def test_index_shows_pending_scan(client):
    sha = "cd" * 32
    with SessionLocal() as db:
        db.add(
            Scan(
                sha256=sha,
                md5="1" * 32,
                sha1="1" * 40,
                file_name="in-progress.bin",
                size=5,
                file_type="data",
                magic_hex="",
                verdict="pending",
                status="pending",
                engine="pending",
                urls=[],
            )
        )
        db.commit()
    assert "in-progress.bin" in client.get("/ui/").text
