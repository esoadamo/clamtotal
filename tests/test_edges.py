import io
import struct
import zipfile

from test_parsers import _minimal_elf64, _minimal_pe32

from app.analysis import (
    _rva_to_offset,
    extract_iocs,
    extract_urls,
    find_suspicious_strings,
    parse_elf,
    parse_pdf,
    parse_pe,
    shannon_entropy,
    sniff_file_type,
)


def test_extract_urls_limit():
    data = b" ".join(f"https://example.com/{i}".encode() for i in range(5))
    assert len(extract_urls(data, limit=2)) == 2


def test_extract_iocs_invalid_ip_skipped():
    iocs = extract_iocs(b"999.999.999.999 and 10.0.0.1")
    assert iocs["ips"] == ["10.0.0.1 (private)"]


def test_extract_iocs_limits():
    data = b" ".join(f"https://d{i}example.com".encode() for i in range(600))
    iocs = extract_iocs(data, limit=5)
    assert len(iocs["domains"]) == 5
    strings = find_suspicious_strings(b"powershell mshta rundll32 regsvr32", limit=2)
    assert len(strings) == 2


def test_sniff_variants():
    assert sniff_file_type(b"RIFF1234")[0].startswith("RIFF")
    assert sniff_file_type(b"\x00\x01\x02\x03")[0] == "data"
    assert sniff_file_type(b"")[0] == "data"
    assert shannon_entropy(b"") == 0.0


def test_rva_to_offset_miss():
    assert _rva_to_offset(0x9999, []) is None
    assert _rva_to_offset(0x1000, [(0x1000, 0x100, 0x200, 0x200)]) == 0x200


def test_parse_pe_bad_magic_and_truncated():
    pe = bytearray(_minimal_pe32())
    struct.pack_into("<H", pe, 0x98, 0x999)  # invalid optional-header magic
    assert parse_pe(bytes(pe)) is None
    bad = bytearray(_minimal_pe32())
    struct.pack_into("<I", bad, 0x3C, 0xFFF0)  # e_lfanew beyond EOF -> struct.error path
    assert parse_pe(bytes(bad)) is None


def test_parse_elf32_and_truncated():
    elf32 = bytearray(_minimal_elf64())
    elf32[4] = 1  # 32-bit class
    struct.pack_into("<I", elf32, 32, 0x100)  # 32-bit e_shoff
    struct.pack_into("<H", elf32, 46, 40)  # 32-bit e_shentsize
    struct.pack_into("<H", elf32, 48, 4)  # 32-bit e_shnum
    struct.pack_into("<H", elf32, 50, 3)  # 32-bit e_shstrndx
    parsed = parse_elf(bytes(elf32))
    assert parsed is not None and parsed["is64"] is False

    broken = bytearray(elf32)
    struct.pack_into("<I", broken, 32, 0xF000)  # e_shoff past EOF -> struct.error path
    assert parse_elf(bytes(broken)) is None
    assert parse_elf(b"\x7fELF" + b"\x00" * 20) is None


def test_parse_pdf_not_pdf():
    assert parse_pdf(b"plain text") is None


def test_extract_embedded_skips_directories():
    from app.analysis import extract_embedded_files

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("folder/", b"")
        zf.writestr("file.txt", b"data")
    assert [name for name, _ in extract_embedded_files(buf.getvalue())] == ["file.txt"]


def test_upload_pe_elf_pdf_routes(client):
    import hashlib

    pe = _minimal_pe32()
    client.post("/file/upload", files={"file": ("a.exe", pe)}, follow_redirects=False)
    report = client.get(f"/api/v2/files/{hashlib.sha256(pe).hexdigest()}").json()
    assert report["behavior"]["pe"]["sections"][0]["name"] == ".text"

    elf = _minimal_elf64()
    client.post("/file/upload", files={"file": ("a.elf", elf)}, follow_redirects=False)
    report = client.get(f"/api/v2/files/{hashlib.sha256(elf).hexdigest()}").json()
    assert report["behavior"]["elf"]["dynamic_symbols"] == ["system"]

    pdf = b"%PDF-1.4 /OpenAction /JS endobj"
    client.post("/file/upload", files={"file": ("a.pdf", pdf)}, follow_redirects=False)
    report = client.get(f"/api/v2/files/{hashlib.sha256(pdf).hexdigest()}").json()
    assert report["behavior"]["pdf"]["has_js"] is True
