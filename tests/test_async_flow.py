import hashlib

from app.db import SessionLocal
from app.models import Scan


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
            )
        )
        db.commit()
    page = client.get(f"/ui/file/{sha}")
    assert page.status_code == 200
    assert "Scanning pending.bin" in page.text
    assert "setInterval" in page.text  # polls /api/v2/files/{sha} until done
    api = client.get(f"/api/v2/files/{sha}").json()
    assert api["status"] == "pending"


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
