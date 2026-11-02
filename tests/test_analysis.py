import io
import zipfile

from app.analysis import (
    compute_hashes,
    extract_embedded_files,
    extract_iocs,
    extract_urls,
    find_suspicious_strings,
    list_archive_members,
    parse_office,
    parse_pdf,
    parse_pe,
    sniff_file_type,
)


def test_compute_hashes_includes_sha512_and_crc32():
    hashes = compute_hashes(b"abc")
    assert len(hashes["sha512"]) == 128
    assert len(hashes["crc32"]) == 8
    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"


def test_extract_iocs():
    data = (
        b"visit http://185.220.101.4/x or https://evil-example.com and mail bad@evil-example.com "
        b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
        b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa powershell -enc AAAA"
    )
    iocs = extract_iocs(data)
    assert "evil-example.com" in iocs["domains"]
    assert any("185.220.101.4" in ip for ip in iocs["ips"])
    assert "bad@evil-example.com" in iocs["emails"]
    assert any("HKLM" in k for k in iocs["registry_keys"])
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in iocs["bitcoin_addresses"]


def test_extract_iocs_punycode_flagged():
    iocs = extract_iocs(b"go to xn--nxasmq6b.example")
    assert any("xn--" in d for d in iocs["punycode_domains"])


def test_suspicious_strings_and_urls():
    data = b"powershell -enc AAAA https://example.org/a"
    assert "powershell" in find_suspicious_strings(data)
    assert extract_urls(data) == ["https://example.org/a"]


def test_parse_pdf_signals():
    pdf = (
        b"%PDF-1.4 1 0 obj /OpenAction /JS (app.launchURL) "
        b"/EmbeddedFile /Filespec (evil.exe) endobj"
    )
    parsed = parse_pdf(pdf)
    assert parsed and parsed["has_js"]
    assert "/OpenAction" in parsed["signals"]
    assert "evil.exe" in parsed["embedded_file_names"]


def test_parse_pe_rejects_non_pe():
    assert parse_pe(b"MZ" + b"\x00" * 10) is None
    assert parse_pe(b"not a pe") is None


def test_office_macro_detection():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"attribute vb_name autoopen document_open")
    parsed = parse_office(buf.getvalue())
    assert parsed and parsed["has_vba_project"] and parsed["auto_open_macro"]


def test_archive_listing_and_embedded_extraction():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"hello")
        zf.writestr("nested/payload.bin", b"MZ" + b"\x00" * 100)
    data = buf.getvalue()
    members = list_archive_members(data)
    assert members is not None
    assert {m["name"] for m in members} == {"readme.txt", "nested/payload.bin"}
    embedded = dict(extract_embedded_files(data))
    assert embedded["nested/payload.bin"].startswith(b"MZ")


def test_sniff_file_type():
    assert sniff_file_type(b"%PDF-1.7")[0] == "PDF document"
    assert sniff_file_type(b"plain text here")[0] == "ASCII text"
