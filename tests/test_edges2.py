import socket
import struct

import pytest
from test_parsers import _minimal_pe32
from test_scanner import FakeSocket

from app.analysis import parse_pe
from app.scanner import ClamdScanner, ScannerUnavailableError


def test_parse_pe_import_name_outside_sections():
    pe = bytearray(_minimal_pe32())
    struct.pack_into("<I", pe, 0x240 + 12, 0x99999)  # Name RVA outside any section
    parsed = parse_pe(bytes(pe))
    assert parsed is not None and parsed["imports"] == []


def _pe_base(size=0x2000):
    pe = bytearray(size)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x010F)
    opt = 0x98
    struct.pack_into("<H", pe, opt, 0x10B)
    struct.pack_into("<I", pe, opt + 92, 16)
    struct.pack_into("<II", pe, opt + 96 + 8, 0x1040, 20)  # import dir
    sec = opt + 0xE0
    pe[sec : sec + 6] = b".text\0"
    struct.pack_into("<IIII", pe, sec + 8, 0x800, 0x1000, size - 0x200, 0x200)
    pe[0x280 : 0x280 + 13] = b"KERNEL32.dll\0"  # RVA 0x1080
    return pe


def test_parse_pe_descriptor_limit():
    pe = _pe_base(0x2000)
    for i in range(300):  # >256 valid descriptors with no thunks
        struct.pack_into("<IIIII", pe, 0x240 + i * 20, 0, 0, 0, 0x1080, 0)
    parsed = parse_pe(bytes(pe))
    assert parsed is not None and parsed["imports"] == []


def test_parse_pe_thunk_limit():
    pe = _pe_base(0x2000)
    struct.pack_into("<IIIII", pe, 0x240, 0x1800, 0, 0, 0x1080, 0x1800)
    for t in range(600):  # 600 nonzero thunks -> t > 512 cap
        struct.pack_into("<I", pe, 0xA00 + t * 4, 1)  # RVA 0x1800 -> file 0xA00
    parsed = parse_pe(bytes(pe))
    assert parsed is not None and parsed["imports"] == []


def test_parse_pe_struct_error_path():
    pe = bytearray(_minimal_pe32())
    struct.pack_into("<H", pe, 0x84 + 2, 50)  # 50 sections -> section table past EOF
    assert parse_pe(bytes(pe)) is None


def test_clamd_empty_response_breaks(monkeypatch):
    fake = FakeSocket(b"")  # recv returns b"" immediately
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: fake)
    with pytest.raises(ScannerUnavailableError):
        ClamdScanner().scan(b"data")
