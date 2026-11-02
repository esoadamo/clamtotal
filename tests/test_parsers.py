import io
import struct
import tarfile

from app.analysis import (
    extract_embedded_files,
    list_archive_members,
    parse_elf,
    parse_office,
    parse_pe,
    shannon_entropy,
)


def _minimal_pe32() -> bytes:
    """Craft a minimal PE32 with one section, one export, one import, one TLS callback."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    buf[0x40:0x44] = b"Rich"  # rich header marker before PE offset
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    # COFF header at 0x84
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x010F)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x10B)  # PE32 magic
    struct.pack_into("<I", buf, opt + 92, 16)  # NumberOfRvaAndSizes
    dirs = opt + 96
    # section: VA 0x1000, raw offset 0x200
    struct.pack_into("<II", buf, dirs + 0 * 8, 0x1000, 40)  # export dir
    struct.pack_into("<II", buf, dirs + 1 * 8, 0x1040, 20)  # import dir
    struct.pack_into("<II", buf, dirs + 9 * 8, 0x10C0, 16)  # TLS dir
    sec = opt + 0xE0
    buf[sec : sec + 6] = b".text\0"
    struct.pack_into("<IIII", buf, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    # export directory at RVA 0x1000 -> file 0x200
    struct.pack_into("<I", buf, 0x200 + 24, 1)  # NumberOfNames
    struct.pack_into("<I", buf, 0x200 + 32, 0x1028)  # AddressOfNames
    struct.pack_into("<I", buf, 0x228, 0x1030)  # names[0] RVA
    buf[0x230 : 0x230 + 13] = b"ExportedFunc\0"
    # import descriptor at RVA 0x1040 -> file 0x240
    struct.pack_into("<IIIII", buf, 0x240, 0x1060, 0, 0, 0x1080, 0x1060)
    struct.pack_into("<I", buf, 0x260, 0x10A0)  # thunk -> hint/name
    struct.pack_into("<I", buf, 0x264, 0)  # thunk terminator
    buf[0x280 : 0x280 + 13] = b"KERNEL32.dll\0"
    buf[0x2A0:0x2A2] = b"\x00\x00"
    buf[0x2A2 : 0x2A2 + 11] = b"ExitProcess\0"
    # TLS directory at RVA 0x10C0 -> file 0x2C0
    struct.pack_into("<I", buf, 0x2C0 + 8, 0x10D0)  # AddressOfCallBacks
    struct.pack_into("<I", buf, 0x2D0, 0x1500)  # one callback
    struct.pack_into("<I", buf, 0x2D4, 0)  # terminator
    return bytes(buf)


def _minimal_elf64() -> bytes:
    """Craft a minimal ELF64 with .dynsym/.dynstr/.shstrtab sections."""
    shstrtab = b"\0.dynsym\0.dynstr\0.shstrtab\0"
    dynstr = b"\0system\0"
    dynsym = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0, 0)  # one FUNC GLOBAL symbol "system"
    shoff = 0x100

    # section headers: null, .dynsym, .dynstr, .shstrtab
    def shdr(name, type_, offset, size):
        return struct.pack("<IIQQQQIIQQ", name, type_, 0, 0, offset, size, 0, 0, 1, 0)

    data = bytearray(0x200)
    data[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 4, 3)
    dynsym_off, dynstr_off, shstr_off = 0x40, 0x60, 0x80
    data[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    data[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    data[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    headers = shdr(0, 0, 0, 0)
    headers += shdr(1, 11, dynsym_off, len(dynsym))  # .dynsym, SHT_DYNSYM
    headers += shdr(9, 3, dynstr_off, len(dynstr))  # .dynstr
    headers += shdr(17, 3, shstr_off, len(shstrtab))  # .shstrtab
    data[shoff : shoff + len(headers)] = headers
    return bytes(data)


def test_parse_pe_full():
    pe = parse_pe(_minimal_pe32())
    assert pe is not None
    assert pe["is64"] is False
    assert pe["sections"][0]["name"] == ".text"
    assert pe["imphash"] is not None
    assert pe["imports"] == ["kernel32.dll.exitprocess"]
    assert pe["exports"] == ["ExportedFunc"]
    assert pe["tls_callbacks"] == ["0x1500"]
    assert pe["rich_header"] is True


def test_parse_pe_64bit_and_garbage():
    pe = bytearray(_minimal_pe32())
    struct.pack_into("<H", pe, 0x98, 0x20B)  # PE32+ magic
    parsed = parse_pe(bytes(pe))
    assert parsed is not None and parsed["is64"] is True
    assert parse_pe(b"MZ" + b"\x00" * 0x100) is None  # bad PE signature
    assert parse_pe(b"\x7fELF") is None  # not a PE


def test_parse_elf_full():
    elf = parse_elf(_minimal_elf64())
    assert elf is not None
    assert elf["is64"] is True
    names = [s["name"] for s in elf["sections"]]
    assert ".dynsym" in names and ".shstrtab" in names
    assert elf["dynamic_symbols"] == ["system"]


def test_parse_elf32_and_garbage():
    data = bytearray(_minimal_elf64())
    data[4] = 1  # 32-bit class marker
    assert parse_elf(bytes(data)) is not None
    assert parse_elf(b"\x7fELF" + b"\x00" * 10) is None
    assert parse_elf(b"MZ....") is None


def test_shannon_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_list_archive_members_variants():
    import gzip

    gz = gzip.compress(b"hello")
    members = list_archive_members(gz)
    assert members and members[0]["size"] == 5

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"abc"))
    members = list_archive_members(buf.getvalue())
    assert members == [{"name": "a.txt", "size": 3}]

    assert list_archive_members(b"not an archive") is None
    assert list_archive_members(b"PK\x03\x04corrupt") is None
    assert list_archive_members(b"\x1f\x8bcorrupt") is None


def test_extract_embedded_tar_and_errors():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("dir/b.bin")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"MZxx"))
    embedded = dict(extract_embedded_files(buf.getvalue()))
    assert embedded["dir/b.bin"] == b"MZxx"
    assert extract_embedded_files(b"PK\x03\x04corrupt") == []
    assert extract_embedded_files(b"plain text") == []


def test_parse_office_bad_zip():
    assert parse_office(b"PK\x03\x04corrupt") is None
    assert parse_office(b"not a zip") is None
