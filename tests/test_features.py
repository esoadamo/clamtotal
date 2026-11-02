import hashlib
import io
import zipfile

import app.main as main_module
from app.scanner import YaraScanner


def test_yara_engine_adds_detection(client, monkeypatch, tmp_path):
    (tmp_path / "test.yar").write_text(
        'rule Test_Marker { strings: $m = "MALWARE-MARKER-XYZ" condition: $m }'
    )
    monkeypatch.setattr(main_module, "get_yara_scanner", lambda: YaraScanner(str(tmp_path)))
    content = b"this file contains MALWARE-MARKER-XYZ inside"
    response = client.post("/file/upload", files={"file": ("marked.bin", content)})
    sha256 = hashlib.sha256(content).hexdigest()
    assert response.json()["sha256"] == sha256
    report = client.get(f"/api/v2/files/{sha256}").json()
    engine_names = [e["name"] for e in report["engines"]]
    assert any("YARA" in n for n in engine_names)
    assert report["verdict"] == "infected"
    assert "Test_Marker" in report["signature"]
    monkeypatch.undo()


def test_iocs_and_behavior_in_report(client):
    content = b"contact admin@evil-example.com or http://185.220.101.4/ payload powershell -enc AA"
    client.post("/file/upload", files={"file": ("ioc.bin", content)}, follow_redirects=False)
    sha256 = hashlib.sha256(content).hexdigest()
    report = client.get(f"/api/v2/files/{sha256}").json()
    assert "admin@evil-example.com" in report["iocs"]["emails"]
    assert any("185.220.101.4" in ip for ip in report["iocs"]["ips"])
    assert "powershell" in report["behavior"]["suspicious_strings"]
    assert report["sha512"] and len(report["sha512"]) == 128
    html = client.get(f"/ui/file/{sha256}").text
    assert "admin@evil-example.com" in html
    assert "Network" in html


def test_zip_upload_scans_embedded_files_recursively(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "invoice.pdf.exe",
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        zf.writestr("notes.txt", b"nothing suspicious here")
    client.post(
        "/file/upload", files={"file": ("bundle.zip", buf.getvalue())}, follow_redirects=False
    )
    sha256 = hashlib.sha256(buf.getvalue()).hexdigest()
    report = client.get(f"/api/v2/files/{sha256}").json()
    assert report["verdict"] == "infected"  # EICAR child propagates to the archive
    assert len(report["embedded"]) == 2
    names = {e["name"] for e in report["embedded"]}
    assert "invoice.pdf.exe" in names
    child = next(e for e in report["embedded"] if e["name"] == "invoice.pdf.exe")
    assert child["verdict"] == "infected"
    html = client.get(f"/ui/file/{sha256}").text
    assert "Embedded" in html


def test_relations_tab_links_files_sharing_iocs(client):
    marker = b"shared http://203.0.113.9/common"
    for name in ("a.bin", "b.bin"):
        client.post("/file/upload", files={"file": (name, marker + name.encode())})
    sha_a = hashlib.sha256(marker + b"a.bin").hexdigest()
    html = client.get(f"/ui/file/{sha_a}").text
    assert "Relations" in html
    assert "b.bin" in html


def test_alternative_names_tracked_per_hash(client):
    content = b"same content two names"
    client.post("/file/upload", files={"file": ("first-name.bin", content)})
    client.post("/file/upload", files={"file": ("second-name.exe", content)})
    import hashlib

    sha = hashlib.sha256(content).hexdigest()
    api = client.get(f"/api/v2/files/{sha}").json()
    assert api["names"] == ["first-name.bin", "second-name.exe"]
    page = client.get(f"/ui/file/{sha}").text
    assert "Alternative names" in page
    assert "second-name.exe" in page


def test_relations_connect_archive_and_members_by_hash(client):
    import hashlib
    import io
    import zipfile

    child_content = b"shared child payload http://203.0.113.7/deep"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner/payload.bin", child_content)
    client.post("/file/upload", files={"file": ("outer.zip", buf.getvalue())})
    archive_sha = hashlib.sha256(buf.getvalue()).hexdigest()
    child_sha = hashlib.sha256(child_content).hexdigest()

    # upload the child separately under a different name
    client.post("/file/upload", files={"file": ("standalone.dat", child_content)})

    child_page = client.get(f"/ui/file/{child_sha}").text
    assert "Relations" in child_page
    assert "embedded in outer.zip" in child_page

    archive_page = client.get(f"/ui/file/{archive_sha}").text
    assert "contained in this archive" in archive_page
    assert "payload.bin" in archive_page  # child's first-seen name; standalone.dat is an alt name


def test_second_archive_sharing_member_relates_archives(client):
    import hashlib
    import io
    import zipfile

    shared = b"common member content"
    for name in ("pack-a.zip", "pack-b.zip"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("shared.bin", shared)
            zf.writestr(name, b"unique to " + name.encode())
        client.post("/file/upload", files={"file": (name, buf.getvalue())})
    shared_sha = hashlib.sha256(shared).hexdigest()
    page = client.get(f"/ui/file/{shared_sha}").text
    assert "pack-a.zip" in page and "pack-b.zip" in page
