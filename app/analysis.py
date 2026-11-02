from __future__ import annotations

import binascii
import hashlib
import io
import ipaddress
import math
import re
import struct
import tarfile
import zipfile
from collections import Counter
from pathlib import Path

# Official IANA TLD list, bundled for fully offline validation
# (source: data.iana.org/TLD/tlds-alpha-by-domain.txt)
_TLDS = frozenset(
    line.strip().lower()
    for line in (Path(__file__).parent / "data" / "tlds.txt").read_text().splitlines()
    if line.strip()
)

_URL_RE = re.compile(rb"(?:https?|ftp)://[^\s\"'<>()\[\]{}|\\^`]+", re.IGNORECASE)
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:xn--[a-zA-Z0-9-]+|[a-zA-Z]{2,})\b"
)
_EMAIL_RE = re.compile(rb"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_REGISTRY_RE = re.compile(
    rb"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
    rb"|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"'<>]+",
    re.IGNORECASE,
)
_BTC_RE = re.compile(rb"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")

_SUSPICIOUS_STRINGS: list[bytes] = [
    b"powershell",
    b"invoke-expression",
    b"downloadstring",
    b"downloadfile",
    b"iex(",
    b"mshta",
    b"rundll32",
    b"regsvr32",
    b"certutil -urlcache",
    b"cmd /c",
    b"cmd.exe /c",
    b"wscript.shell",
    b"cscript",
    b"schtasks",
    b"mimikatz",
    b"vssadmin",
    b"bcdedit",
    b"taskkill /f",
    b"wevtutil",
    b"base64 -d",
    b"frombase64string",
    b"-enc ",
    b"-encodedcommand",
    b"bitstransfer",
    b"add-type",
    b"reflection.assembly",
]

_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "PE32 executable (EXE/DLL)"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (DOCX/XLSX/JAR/APK)"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"RIFF", "RIFF container (WAV/AVI/WEBP)"),
    (b"\x1f\x8b", "gzip compressed data"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"ustar", "POSIX tar archive"),
]


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "crc32": f"{binascii.crc32(data) & 0xFFFFFFFF:08x}",
    }


def extract_urls(data: bytes, limit: int = 200) -> list[str]:
    urls: list[str] = []
    for match in _URL_RE.finditer(data):
        url = match.group(0).decode("utf-8", errors="ignore").rstrip(".,;:!")
        if url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break
    return urls


def extract_iocs(data: bytes, limit: int = 500) -> dict[str, list[str]]:
    """Extract indicators: domains, IPs, emails, registry paths, BTC addresses."""
    domains, ips, emails, registry, btc = [], [], [], [], []
    seen: set[str] = set()

    def _add(bucket: list[str], value: str) -> None:
        if value not in seen and len(bucket) < limit:
            seen.add(value)
            bucket.append(value)

    for m in _IPV4_RE.finditer(data):
        raw = m.group(0).decode()
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        _add(ips, f"{ip} (private)" if ip.is_private else str(ip))
    for m in _DOMAIN_RE.finditer(data):
        domain = m.group(0).decode("latin-1").lower().rstrip(".")
        if domain.rsplit(".", 1)[-1] in _TLDS:  # only real, existing TLDs
            _add(domains, domain)
    for m in _EMAIL_RE.finditer(data):
        _add(emails, m.group(0).decode("latin-1"))
    for m in _REGISTRY_RE.finditer(data):
        _add(registry, m.group(0).decode("latin-1"))
    for m in _BTC_RE.finditer(data):
        _add(btc, m.group(0).decode("latin-1"))
    return {
        "domains": domains,
        "ips": ips,
        "emails": emails,
        "registry_keys": registry,
        "bitcoin_addresses": btc,
        "punycode_domains": sorted(d for d in domains if "xn--" in d),
    }


def find_suspicious_strings(data: bytes, limit: int = 50) -> list[str]:
    lowered = data.lower()
    found, seen = [], set()
    for needle in _SUSPICIOUS_STRINGS:
        if needle in lowered and needle.decode() not in seen:
            seen.add(needle.decode())
            found.append(needle.decode())
        if len(found) >= limit:
            break
    return found


def sniff_file_type(data: bytes) -> tuple[str, str]:
    """Return (human-readable file type, first bytes as hex)."""
    for magic, description in _MAGIC_SIGNATURES:
        if data.startswith(magic):
            return description, data[:16].hex()
    sample = data[:4096]
    if sample and sum(1 for b in sample if b in b"\t\n\r" or 32 <= b < 127) / len(sample) > 0.95:
        return "ASCII text", data[:16].hex()
    return "data", data[:16].hex()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int | None:
    for virtual_address, virtual_size, raw_offset, _raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, _raw_size):
            return raw_offset + (rva - virtual_address)
    return None


def parse_pe(data: bytes) -> dict | None:
    """Minimal PE parser: sections, imports (+imphash), exports, TLS callbacks, Rich header."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return None
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return None
        coff = pe_offset + 4
        machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in (0x10B, 0x20B):
            return None
        is64 = magic == 0x20B
        data_dir_offset = opt + (112 if is64 else 96)
        num_dirs = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]
        dirs = []
        for i in range(min(num_dirs, 16)):
            rva, size = struct.unpack_from("<II", data, data_dir_offset + i * 8)
            dirs.append((rva, size))
        sec_offset = opt + opt_size
        sections = []
        for i in range(num_sections):
            name = (
                data[sec_offset + i * 40 : sec_offset + i * 40 + 8]
                .rstrip(b"\0")
                .decode("latin-1", "ignore")
            )
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, sec_offset + i * 40 + 8
            )
            sections.append((virtual_address, virtual_size, raw_offset, raw_size, name))
        pe_sections = [
            {
                "name": name,
                "virtual_address": hex(va),
                "virtual_size": vs,
                "raw_size": rs,
                "entropy": round(shannon_entropy(data[ro : ro + rs]), 3) if rs else 0.0,
            }
            for va, vs, ro, rs, name in sections
        ]

        def _read_cstring(offset: int) -> str:
            end = data.find(b"\0", offset)
            return data[offset : end if end != -1 else offset + 256].decode("latin-1", "ignore")

        imports: list[str] = []
        if len(dirs) > 1 and dirs[1][0]:
            imp_rva, _ = dirs[1]
            off = _rva_to_offset(imp_rva, [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections])
            if off:
                idx = 0
                while off + idx * 20 + 20 <= len(data):
                    orig_thunk, _, _, name_rva, fwd = struct.unpack_from(
                        "<IIIII", data, off + idx * 20
                    )
                    if name_rva == 0:
                        break
                    name_off = _rva_to_offset(
                        name_rva, [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
                    )
                    if not name_off:
                        break
                    dll = _read_cstring(name_off).lower()
                    thunk_rva = orig_thunk or fwd
                    thunk_off = _rva_to_offset(
                        thunk_rva, [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
                    )
                    if thunk_off:
                        tsize = 8 if is64 else 4
                        t = 0
                        while thunk_off + t * tsize + tsize <= len(data):
                            val = struct.unpack_from(
                                "<Q" if is64 else "<I", data, thunk_off + t * tsize
                            )[0]
                            if val == 0:
                                break
                            if not (val & (1 << 63 if is64 else 1 << 31)):
                                name2_off = _rva_to_offset(
                                    val & 0x7FFFFFFF,
                                    [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections],
                                )
                                if name2_off:
                                    imports.append(f"{dll}.{_read_cstring(name2_off + 2).lower()}")
                            t += 1
                            if t > 512:
                                break
                    idx += 1
                    if idx > 256:
                        break
        imphash = hashlib.md5(",".join(sorted(imports)).encode()).hexdigest() if imports else None

        exports: list[str] = []
        if len(dirs) > 0 and dirs[0][0]:
            exp_off = _rva_to_offset(
                dirs[0][0], [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
            )
            if exp_off and exp_off + 40 <= len(data):
                num_names = struct.unpack_from("<I", data, exp_off + 24)[0]
                names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
                names_off = _rva_to_offset(
                    names_rva, [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
                )
                if names_off:
                    for i in range(min(num_names, 512)):
                        nrva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                        noff = _rva_to_offset(
                            nrva, [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
                        )
                        if noff:
                            exports.append(_read_cstring(noff))

        tls_callbacks = []
        if len(dirs) > 9 and dirs[9][0]:
            tls_off = _rva_to_offset(
                dirs[9][0], [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
            )
            if tls_off and tls_off + (24 if is64 else 16) <= len(data):
                cb_rva = struct.unpack_from(
                    "<Q" if is64 else "<I", data, tls_off + (16 if is64 else 8)
                )[0]
                cb_off = _rva_to_offset(
                    cb_rva, [(va, vs, ro, rs) for va, vs, ro, rs, _ in sections]
                )
                t = 0
                while cb_off and cb_off + (8 if is64 else 4) <= len(data) and t < 16:
                    cb = struct.unpack_from(
                        "<Q" if is64 else "<I", data, cb_off + t * (8 if is64 else 4)
                    )[0]
                    if cb == 0:
                        break
                    tls_callbacks.append(hex(cb))
                    t += 1

        rich = b"Rich" in data[0x40:pe_offset] if pe_offset > 0x40 else False
        suspicious = sorted(
            s
            for s in find_suspicious_strings(data)
            if s
            in {
                "powershell",
                "mshta",
                "rundll32",
                "regsvr32",
                "certutil -urlcache",
                "wscript.shell",
            }
        )
        return {
            "machine": hex(machine),
            "is64": is64,
            "sections": pe_sections,
            "imports": imports[:512],
            "imphash": imphash,
            "exports": exports[:256],
            "tls_callbacks": tls_callbacks,
            "rich_header": rich,
            "suspicious_imports": suspicious,
        }
    except (struct.error, IndexError):
        return None


def parse_elf(data: bytes) -> dict | None:
    """Minimal ELF parser: sections and dynamic symbol names."""
    if len(data) < 64 or not data.startswith(b"\x7fELF"):
        return None
    try:
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        if is64:
            _, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = struct.unpack_from(
                endian + "HHIQQQIHHHHHH", data, 16
            )
        else:
            _, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = struct.unpack_from(
                endian + "HHIIIIIHHHHHH", data, 16
            )
        sections = []
        for i in range(min(shnum, 128)):
            base = shoff + i * shentsize
            if is64:
                name_off, sh_type, _, _, offset, size = struct.unpack_from(
                    endian + "IIQQQQ", data, base
                )
            else:
                name_off, sh_type, _, _, offset, size = struct.unpack_from(
                    endian + "IIIIII", data, base
                )
            sections.append((name_off, sh_type, offset, size))
        shstr = sections[shstrndx] if 0 <= shstrndx < len(sections) else None
        names = data[shstr[2] : shstr[2] + shstr[3]] if shstr else b""

        def _secname(off: int) -> str:
            end = names.find(b"\0", off)
            return names[off : end if end != -1 else off + 64].decode("latin-1", "ignore")

        dynsym = next((s for s in sections if s[1] == 11), None)
        dynstr = next((s for s in sections if _secname(s[0]) == ".dynstr"), None)
        imports: list[str] = []
        if dynsym and dynstr:
            strtab = data[dynstr[2] : dynstr[2] + dynstr[3]]
            entsize = 24 if is64 else 16
            count = min(dynsym[3] // entsize, 1024)
            for i in range(count):
                base = dynsym[2] + i * entsize
                st_name = struct.unpack_from(endian + "I", data, base)[0]
                if st_name and st_name < len(strtab):
                    end = strtab.find(b"\0", st_name)
                    name = strtab[st_name : end if end != -1 else st_name + 128].decode(
                        "latin-1", "ignore"
                    )
                    if name:
                        imports.append(name)
        return {
            "is64": is64,
            "sections": [
                {
                    "name": _secname(off),
                    "type": t,
                    "size": size,
                    "entropy": round(shannon_entropy(data[o : o + s]), 3) if s else 0.0,
                }
                for off, t, o, s in sections
            ],
            "dynamic_symbols": sorted(set(imports))[:512],
        }
    except (struct.error, IndexError):
        return None


_PDF_SIGNALS = [
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/URI",
]


def parse_pdf(data: bytes) -> dict | None:
    if not data.startswith(b"%PDF"):
        return None
    signals = [s.decode("latin-1") for s in _PDF_SIGNALS if s in data]
    embedded = [
        m.decode("latin-1", "ignore") for m in re.findall(rb"/Filespec\s*\(([^)]+)\)", data)
    ]
    return {
        "signals": signals,
        "object_count": len(re.findall(rb"\b\d+\s+\d+\s+obj\b", data)),
        "embedded_file_names": sorted(set(embedded))[:100],
        "has_js": b"/JavaScript" in data or b"/JS" in data,
    }


def parse_office(data: bytes) -> dict | None:
    """DOCX/XLSX/PPTX are ZIPs — detect VBA macros and suspicious parts."""
    if not data.startswith(b"PK\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            vba = [n for n in names if "vbaproject" in n.lower()]
            has_vba = bool(vba)
            auto_open = False
            if has_vba:
                blob = zf.read(vba[0]).lower()
                auto_open = (
                    b"autoopen" in blob or b"document_open" in blob or b"workbook_open" in blob
                )
            return {
                "parts": names[:200],
                "has_vba_project": has_vba,
                "auto_open_macro": auto_open,
                "embedded_objects": [
                    n for n in names if n.lower().endswith((".bin", ".exe", ".dll"))
                ][:50],
            }
    except (zipfile.BadZipFile, KeyError):
        return None


def list_archive_members(data: bytes, limit: int = 100) -> list[dict] | None:
    """List archive contents for ZIP / TAR / GZ; None if not a supported archive."""
    try:
        if data.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return [{"name": i.filename, "size": i.file_size} for i in zf.infolist()[:limit]]
        if data.startswith(b"\x1f\x8b"):
            import gzip

            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                raw = gz.read(16 * 1024 * 1024)
            name = getattr(gz, "name", "") or ""
            return [{"name": name or "gzip-content", "size": len(raw)}]
        if len(data) > 262 and data[257:262] == b"ustar":
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                return [
                    {"name": m.name, "size": m.size} for m in tf.getmembers()[:limit] if m.isfile()
                ]
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return None
    return None


def extract_embedded_files(data: bytes, limit: int = 10) -> list[tuple[str, bytes]]:
    """Pull candidate embedded files out of ZIP/TAR/GZ archives for recursive scanning."""
    out: list[tuple[str, bytes]] = []
    try:
        if data.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or len(out) >= limit or info.file_size > 32 * 1024 * 1024:
                        continue
                    out.append((info.filename, zf.read(info)))
        elif len(data) > 262 and data[257:262] == b"ustar":
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for m in tf.getmembers():
                    if m.isfile() and len(out) < limit and m.size <= 32 * 1024 * 1024:
                        fh = tf.extractfile(m)
                        if fh:
                            out.append((m.name, fh.read()))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return []
    return out
