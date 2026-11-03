import re
import threading
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import String, or_, select
from sqlalchemy.orm import Session

from app.analysis import (
    compute_hashes,
    extract_embedded_files,
    extract_iocs,
    extract_urls,
    find_suspicious_strings,
    list_archive_members,
    parse_elf,
    parse_office,
    parse_pdf,
    parse_pe,
    shannon_entropy,
    sniff_file_type,
)
from app.config import settings
from app.db import SessionLocal, get_db
from app.models import Scan
from app.scanner import Scanner, ScannerUnavailableError, get_scanner, get_yara_scanner


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    def loop() -> None:
        while True:
            _prune_uploads()
            time.sleep(60)

    threading.Thread(target=loop, daemon=True).start()
    yield


app = FastAPI(title="ClamTotal", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _defang(value: str) -> str:
    """Defang an indicator so it is displayed as text and never loaded by accident."""
    return value.replace("http", "hxxp").replace(".", "[.]")


templates.env.filters["defang"] = _defang

Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<path d="M16 2 4 7v8c0 7.5 5.1 13 12 15 6.9-2 12-7.5 12-15V7L16 2Z" fill="#0f766e"/>'
    '<path d="m10.5 16.5 3.8 3.8 7.2-7.6" stroke="#fbbf24" stroke-width="3" fill="none" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


@app.get("/favicon.svg", include_in_schema=False)
def favicon() -> Response:
    return Response(_FAVICON_SVG, media_type="image/svg+xml")


def _prune_uploads() -> None:
    """Delete stored samples past their TTL. ttl=-1 keeps them forever, 0 deletes immediately."""
    ttl = settings.uploads_ttl
    if ttl < 0:
        return
    now = time.time()
    for f in Path(settings.upload_dir).iterdir():
        if f.is_file() and (ttl == 0 or now - f.stat().st_mtime > ttl * 60):
            f.unlink(missing_ok=True)


@app.exception_handler(ScannerUnavailableError)
async def scanner_unavailable_handler(
    request: Request, exc: ScannerUnavailableError
) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


def _lookup(db: Session, hash_value: str) -> Scan | None:
    hash_value = hash_value.lower()
    if len(hash_value) == 64:
        return db.get(Scan, hash_value)
    return db.execute(
        select(Scan).where(or_(Scan.md5 == hash_value, Scan.sha1 == hash_value))
    ).scalar_one_or_none()


def _scan_and_store(
    db: Session,
    scanner: Scanner,
    data: bytes,
    file_name: str,
    rescan: bool,
    depth: int = 0,
) -> tuple[Scan, bool]:
    """Scan with all local engines, run offline analysis, persist. Returns (scan, was_cached)."""
    hashes = compute_hashes(data)
    existing = db.get(Scan, hashes["sha256"])
    if existing and not rescan:
        return existing, True

    # multi-engine verdicts: ClamAV (clamd/clamscan) + local YARA rules
    result = scanner.scan(data)
    engines = [{"name": result.engine, "verdict": result.verdict, "signature": result.signature}]
    yara = get_yara_scanner()
    if yara is not None:
        matches = yara.scan(data)
        engines.append(
            {
                "name": yara.engine,
                "verdict": "infected" if matches else "clean",
                "signature": ", ".join(matches) if matches else None,
            }
        )
    verdict = "infected" if any(e["verdict"] == "infected" for e in engines) else "clean"
    signature = next((e["signature"] for e in engines if e["verdict"] == "infected"), None)

    # offline static analysis, mimicking VirusTotal's Details/Behavior/Network tabs
    file_type, magic_hex = sniff_file_type(data)
    behavior: dict = {"suspicious_strings": find_suspicious_strings(data)}
    if file_type.startswith("PE32"):
        behavior["pe"] = parse_pe(data)
    elif file_type.startswith("ELF"):
        behavior["elf"] = parse_elf(data)
    elif file_type.startswith("PDF"):
        behavior["pdf"] = parse_pdf(data)
    elif file_type.startswith("ZIP"):
        office = parse_office(data)
        if office:
            behavior["office"] = office
        behavior["archive_members"] = list_archive_members(data)

    embedded: list[dict] = []
    if depth < settings.max_scan_depth:
        for member_name, member_data in extract_embedded_files(data, settings.max_embedded_files):
            child, _ = _scan_and_store(db, scanner, member_data, member_name, rescan, depth + 1)
            embedded.append(
                {
                    "name": member_name,
                    "sha256": child.sha256,
                    "size": child.size,
                    "verdict": child.verdict,
                }
            )

    fields = dict(
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha512=hashes["sha512"],
        crc32=hashes["crc32"],
        file_name=file_name,
        names=sorted({file_name} | set((existing.names or []) if existing else [])),
        size=len(data),
        file_type=file_type,
        magic_hex=magic_hex,
        verdict=verdict,
        status="done",
        signature=signature,
        engine=result.engine,
        urls=extract_urls(data),
        raw_output=result.raw,
        engines=engines,
        iocs=extract_iocs(data),
        behavior=behavior,
        embedded=embedded,
    )
    if existing:
        for key, value in fields.items():
            setattr(existing, key, value)
        scan = existing
    else:
        scan = Scan(sha256=hashes["sha256"], **fields)
        db.add(scan)
    db.commit()
    (Path(settings.upload_dir) / scan.sha256).write_bytes(data)
    return scan, False


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui/", status_code=303)


@app.get("/ui/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    recent = (
        db.execute(select(Scan).order_by(Scan.scanned_at.desc()).limit(20)).scalars().all()
        if settings.show_recent_scans
        else []
    )
    return templates.TemplateResponse(request, "index.html", {"recent": recent})


def _run_scan(data: bytes, file_name: str) -> None:
    """Background task: scan with all engines and mark the row done."""
    with SessionLocal() as db:
        scan, _ = _scan_and_store(db, get_scanner(), data, file_name, rescan=True)
    if settings.uploads_ttl == 0:  # delete the stored sample immediately after the scan
        (Path(settings.upload_dir) / scan.sha256).unlink(missing_ok=True)


def _enqueue_scan(
    background_tasks: BackgroundTasks, db: Session, data: bytes, file_name: str, rescan: bool
) -> tuple[Scan, bool]:
    """Return a cached done-row or enqueue an async scan. Returns (scan, was_cached)."""
    hashes = compute_hashes(data)
    existing = db.get(Scan, hashes["sha256"])
    if existing and existing.status == "done" and not rescan:
        if file_name not in (existing.names or []):  # record alternative names on cache hits
            existing.names = sorted(set(existing.names or []) | {file_name})
            db.commit()
        return existing, True
    file_type, magic_hex = sniff_file_type(data)
    if existing:
        existing.status = "pending"
        existing.verdict = "pending"
        existing.file_name = file_name
        names = sorted(set(existing.names or []) | {file_name})
        existing.names = names
        scan = existing
    else:
        scan = Scan(
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            file_name=file_name,
            names=[file_name],
            size=len(data),
            file_type=file_type,
            magic_hex=magic_hex,
            verdict="pending",
            status="pending",
            engine="pending",
            urls=[],
        )
        db.add(scan)
    db.commit()
    (Path(settings.upload_dir) / scan.sha256).write_bytes(data)
    background_tasks.add_task(_run_scan, data, file_name)
    return scan, False


@app.post("/file/upload")
async def upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    rescan: bool = False,
    db: Session = Depends(get_db),
    scanner: Scanner = Depends(get_scanner),  # fail fast (503) when no ClamAV backend
) -> JSONResponse:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    if len(data) > settings.max_upload_size:
        raise HTTPException(status_code=413, detail="file too large")
    scan, cached = _enqueue_scan(background_tasks, db, data, file.filename or "upload.bin", rescan)
    return JSONResponse(
        status_code=200 if cached else 202,
        content={"sha256": scan.sha256, "status": scan.status, "cached": cached},
    )


@app.get("/ui/file/{hash_value}", response_class=HTMLResponse)
def report(request: Request, hash_value: str, db: Session = Depends(get_db)) -> HTMLResponse:
    scan = _lookup(db, hash_value)
    if scan is None:
        return templates.TemplateResponse(
            request, "not_found.html", {"hash_value": hash_value}, status_code=404
        )
    stored = Path(settings.upload_dir) / scan.sha256
    entropy = shannon_entropy(stored.read_bytes()) if stored.exists() else 0.0
    pending = scan.status != "done"
    # relations: shared IOCs + archive membership (this file embedded in another scan, or this
    # archive containing other scans) — all resolved locally by hash, VT-style
    relations: list[tuple[Scan, list[str]]] = []
    if not pending:
        my_iocs = {v for values in (scan.iocs or {}).values() for v in values if isinstance(v, str)}
        my_embedded = {c["sha256"] for c in scan.embedded or []}
        for other in db.execute(select(Scan).where(Scan.sha256 != scan.sha256)).scalars():
            reasons: list[str] = []
            shared = sorted(
                {v for values in (other.iocs or {}).values() for v in values if isinstance(v, str)}
                & my_iocs
            )
            if shared:
                reasons.append("shared indicators: " + ", ".join(shared[:3]))
            if scan.sha256 in {c["sha256"] for c in other.embedded or []}:
                reasons.append(f"embedded in {other.file_name}")
            if other.sha256 in my_embedded:
                reasons.append(f"contained in this archive ({other.file_name})")
            if reasons:
                relations.append((other, reasons))
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "scan": scan,
            "entropy": entropy,
            "relations": relations[:10],
            "pending": pending,
            "poll_interval": settings.scan_poll_interval_ms,
        },
    )


@app.get("/ui/file/{hash_value}/download")
def download(hash_value: str, db: Session = Depends(get_db)) -> FileResponse:
    scan = _lookup(db, hash_value)
    if scan is None:
        raise HTTPException(status_code=404, detail="file not found")
    path = Path(settings.upload_dir) / scan.sha256
    if not path.exists():
        raise HTTPException(status_code=404, detail="stored sample not found")
    return FileResponse(path, filename=scan.file_name)


@app.post("/ui/file/{hash_value}/rescan")
def rescan(
    background_tasks: BackgroundTasks,
    hash_value: str,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    scan = _lookup(db, hash_value)
    stored = Path(settings.upload_dir) / scan.sha256 if scan else None
    if scan is None or stored is None or not stored.exists():
        raise HTTPException(status_code=404, detail="stored sample not found")
    _enqueue_scan(background_tasks, db, stored.read_bytes(), scan.file_name, rescan=True)
    return RedirectResponse(f"/ui/file/{scan.sha256}", status_code=303)


@app.get("/ui/privacy", response_class=HTMLResponse)
def privacy(request: Request) -> HTMLResponse:
    ttl = settings.uploads_ttl
    if ttl < 0:
        ttl_sentence = "All uploaded files are kept indefinitely."
    elif ttl == 0:
        ttl_sentence = "All uploaded files are deleted right after upload."
    else:
        if ttl >= 1440 and ttl % 1440 == 0:
            n, unit = ttl // 1440, "day"
        elif ttl >= 60 and ttl % 60 == 0:
            n, unit = ttl // 60, "hour"
        else:
            n, unit = ttl, "minute"
        ttl_sentence = (
            f"All uploaded files are deleted after {n} {unit}{'s' if n != 1 else ''}. "
            "A background job prunes them every minute."
        )
    return templates.TemplateResponse(request, "privacy.html", {"ttl_sentence": ttl_sentence})


@app.get("/ui/search", response_class=HTMLResponse)
def search(request: Request, q: str = "", db: Session = Depends(get_db)) -> Response:
    q = q.strip()
    if _HASH_RE.match(q):
        scan = _lookup(db, q)
        if scan is not None:
            return RedirectResponse(f"/ui/file/{scan.sha256}", status_code=303)
    results = []
    if q:
        like = f"%{q}%"
        # VT-style: match file names, any hash (full or partial), and any stored
        # indicator (URLs, domains, IPs, emails, registry keys, BTC addresses)
        results = (
            db.execute(
                select(Scan)
                .where(
                    or_(
                        Scan.file_name.ilike(like),
                        Scan.sha256.ilike(like),
                        Scan.md5.ilike(like),
                        Scan.sha1.ilike(like),
                        Scan.sha512.ilike(like),
                        Scan.urls.cast(String).ilike(like),
                        Scan.iocs.cast(String).ilike(like),
                    )
                )
                .order_by(Scan.scanned_at.desc())
                .limit(50)
            )
            .scalars()
            .all()
        )
    return templates.TemplateResponse(request, "search.html", {"q": q, "results": results})


@app.post("/api/v2/files")
async def api_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    scanner: Scanner = Depends(get_scanner),  # fail fast (503) when no ClamAV backend
) -> JSONResponse:
    data = await file.read()
    if not data:
        return JSONResponse(status_code=400, content={"detail": "empty file"})
    scan, cached = _enqueue_scan(background_tasks, db, data, file.filename or "upload.bin", False)
    return JSONResponse(
        status_code=200 if cached else 202,
        content={
            "sha256": scan.sha256,
            "md5": scan.md5,
            "sha1": scan.sha1,
            "status": scan.status,
            "permalink": f"/ui/file/{scan.sha256}",
        },
    )


@app.get("/api/v2/files/{hash_value}")
def api_report(hash_value: str, db: Session = Depends(get_db)) -> JSONResponse:
    scan = _lookup(db, hash_value)
    if scan is None:
        return JSONResponse(status_code=404, content={"detail": "not found"})
    return JSONResponse(
        {
            "sha256": scan.sha256,
            "md5": scan.md5,
            "sha1": scan.sha1,
            "sha512": scan.sha512,
            "crc32": scan.crc32,
            "file_name": scan.file_name,
            "names": scan.names,
            "size": scan.size,
            "file_type": scan.file_type,
            "verdict": scan.verdict,
            "status": scan.status,
            "signature": scan.signature,
            "engines": scan.engines,
            "urls": scan.urls,
            "iocs": scan.iocs,
            "behavior": scan.behavior,
            "embedded": scan.embedded,
            "scanned_at": scan.scanned_at.isoformat(),
        }
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
