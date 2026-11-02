import re
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.analysis import compute_hashes, extract_urls, shannon_entropy, sniff_file_type
from app.config import settings
from app.db import get_db
from app.models import Scan
from app.scanner import Scanner, ScannerUnavailableError, get_scanner

app = FastAPI(title="ClamTotal", version="0.1.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


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
    db: Session, scanner: Scanner, data: bytes, file_name: str, rescan: bool
) -> tuple[Scan, bool]:
    """Scan data with ClamAV and persist the result. Returns (scan, was_cached)."""
    hashes = compute_hashes(data)
    existing = db.get(Scan, hashes["sha256"])
    if existing and not rescan:
        return existing, True
    result = scanner.scan(data)
    file_type, magic_hex = sniff_file_type(data)
    if existing:
        existing.md5, existing.sha1 = hashes["md5"], hashes["sha1"]
        existing.file_name, existing.size = file_name, len(data)
        existing.file_type, existing.magic_hex = file_type, magic_hex
        existing.verdict, existing.signature = result.verdict, result.signature
        existing.engine, existing.urls, existing.raw_output = (
            result.engine,
            extract_urls(data),
            result.raw,
        )
        scan = existing
    else:
        scan = Scan(
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            file_name=file_name,
            size=len(data),
            file_type=file_type,
            magic_hex=magic_hex,
            verdict=result.verdict,
            signature=result.signature,
            engine=result.engine,
            urls=extract_urls(data),
            raw_output=result.raw,
        )
        db.add(scan)
    db.commit()
    (Path(settings.upload_dir) / scan.sha256).write_bytes(data)
    return scan, False


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    recent = db.execute(select(Scan).order_by(Scan.scanned_at.desc()).limit(20)).scalars().all()
    return templates.TemplateResponse(request, "index.html", {"recent": recent})


@app.post("/file/upload")
async def upload(
    file: UploadFile = File(...),
    rescan: bool = False,
    db: Session = Depends(get_db),
    scanner: Scanner = Depends(get_scanner),
) -> RedirectResponse:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    if len(data) > settings.max_upload_size:
        raise HTTPException(status_code=413, detail="file too large")
    scan, _ = _scan_and_store(db, scanner, data, file.filename or "upload.bin", rescan)
    return RedirectResponse(f"/file/{scan.sha256}", status_code=303)


@app.get("/file/{hash_value}", response_class=HTMLResponse)
def report(request: Request, hash_value: str, db: Session = Depends(get_db)) -> HTMLResponse:
    scan = _lookup(db, hash_value)
    if scan is None:
        return templates.TemplateResponse(
            request, "not_found.html", {"hash_value": hash_value}, status_code=404
        )
    stored = Path(settings.upload_dir) / scan.sha256
    entropy = shannon_entropy(stored.read_bytes()) if stored.exists() else 0.0
    return templates.TemplateResponse(request, "report.html", {"scan": scan, "entropy": entropy})


@app.get("/file/{hash_value}/download")
def download(hash_value: str, db: Session = Depends(get_db)) -> FileResponse:
    scan = _lookup(db, hash_value)
    if scan is None:
        raise HTTPException(status_code=404, detail="file not found")
    path = Path(settings.upload_dir) / scan.sha256
    if not path.exists():
        raise HTTPException(status_code=404, detail="stored sample not found")
    return FileResponse(path, filename=scan.file_name)


@app.post("/file/{hash_value}/rescan")
def rescan(
    hash_value: str,
    db: Session = Depends(get_db),
    scanner: Scanner = Depends(get_scanner),
) -> RedirectResponse:
    scan = _lookup(db, hash_value)
    stored = Path(settings.upload_dir) / scan.sha256 if scan else None
    if scan is None or stored is None or not stored.exists():
        raise HTTPException(status_code=404, detail="stored sample not found")
    _scan_and_store(db, scanner, stored.read_bytes(), scan.file_name, rescan=True)
    return RedirectResponse(f"/file/{scan.sha256}", status_code=303)


@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = "", db: Session = Depends(get_db)) -> Response:
    q = q.strip()
    if _HASH_RE.match(q):
        scan = _lookup(db, q)
        if scan is not None:
            return RedirectResponse(f"/file/{scan.sha256}", status_code=303)
    results = []
    if q:
        results = (
            db.execute(
                select(Scan)
                .where(Scan.file_name.ilike(f"%{q}%"))
                .order_by(Scan.scanned_at.desc())
                .limit(50)
            )
            .scalars()
            .all()
        )
    return templates.TemplateResponse(request, "search.html", {"q": q, "results": results})


@app.post("/api/v2/files")
async def api_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    scanner: Scanner = Depends(get_scanner),
) -> JSONResponse:
    data = await file.read()
    if not data:
        return JSONResponse(status_code=400, content={"detail": "empty file"})
    scan, _ = _scan_and_store(db, scanner, data, file.filename or "upload.bin", rescan=False)
    return JSONResponse(
        status_code=200,
        content={
            "sha256": scan.sha256,
            "md5": scan.md5,
            "sha1": scan.sha1,
            "permalink": f"/file/{scan.sha256}",
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
            "file_name": scan.file_name,
            "size": scan.size,
            "file_type": scan.file_type,
            "verdict": scan.verdict,
            "signature": scan.signature,
            "engine": scan.engine,
            "urls": scan.urls,
            "scanned_at": scan.scanned_at.isoformat(),
        }
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
