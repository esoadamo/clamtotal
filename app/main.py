import faulthandler
import json
import logging
import os
import re
import shutil
import threading
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yara  # ty: ignore[unresolved-import]  # compiled extension, no stubs
from anyio import to_thread
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
)
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import String, or_, select
from sqlalchemy.orm import Session

from app.analysis import (
    compute_hashes,
    compute_hashes_file,
    extract_embedded_files,
    extract_iocs,
    extract_urls,
    find_suspicious_strings,
    list_archive_members,
    parse_elf,
    parse_office,
    parse_pdf,
    parse_pe,
    shannon_entropy_file,
    sniff_file_type,
)
from app.config import settings
from app.db import SessionLocal, get_db
from app.models import Scan
from app.scanner import (
    Scanner,
    ScannerUnavailableError,
    ScanResult,
    clamav_db_stats,
    enabled_scanners,
    get_scanner,
    get_yara_scanner,
)
from app.schemas import (
    ApiScanResponse,
    ChunkUploadResponse,
    EngineHealth,
    ErrorResponse,
    FileReport,
    HealthResponse,
    UploadResponse,
)

logger = logging.getLogger("app")
# uvicorn only configures its own loggers, so without a handler the app's INFO
# records would be dropped (root has no handlers); propagate is kept so tests'
# caplog still captures via the root logger
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

# dump a native traceback to stderr on hard crashes (SIGSEGV etc.) so a dying
# worker leaves evidence in the container logs instead of just "Child process died"
faulthandler.enable()


def _recover_pending_scans() -> None:
    """Startup recovery: scans left in 'pending' by a restart are re-run if the
    stored sample still exists, or their DB row is deleted if it was pruned."""
    with SessionLocal() as db:
        pending = db.execute(select(Scan).where(Scan.status == "pending")).scalars().all()
        rerun = 0
        for scan in pending:
            stored = Path(settings.upload_dir) / scan.sha256
            if stored.exists():
                rerun += 1
                threading.Thread(
                    target=_run_scan_file, args=(stored, scan.file_name), daemon=True
                ).start()
            else:
                db.delete(scan)
        db.commit()
    if pending:
        logger.info(
            "startup recovery: %d pending scan(s), %d re-run, %d dropped",
            len(pending),
            rerun,
            len(pending) - rerun,
        )


def _probe_scanner_at_startup() -> None:
    """Resolve the ClamAV backend once at startup, warming the scanner cache: the
    first probe may wait ~60s for clamd to load its databases and must not happen
    inside an upload request (a reloader restart or proxy timeout in that window
    surfaces as a 502). Later requests then fail fast with 503 while it is down."""
    try:
        scanner = get_scanner()
    except ScannerUnavailableError as exc:
        logger.warning("ClamAV backend unavailable at startup: %s", exc)
    else:
        logger.info(
            "ClamAV backend at startup: %s",
            scanner.engine if scanner is not None else "disabled via ENABLED_SCANNERS",
        )


def _rss_mb() -> float | None:
    """Worker RSS from /proc/self/status (Linux containers), None elsewhere."""
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    _probe_scanner_at_startup()
    _recover_pending_scans()
    rss = _rss_mb()
    logger.info(
        "worker up: pid=%d rss=%s",
        os.getpid(),
        f"{rss:.0f} MB" if rss is not None else "unknown",
    )

    def loop() -> None:
        while True:
            _prune_uploads()
            time.sleep(60)

    threading.Thread(target=loop, daemon=True).start()
    yield


app = FastAPI(title="ClamTotal", version="0.1.0", lifespan=lifespan)


def _rate_limits_doc() -> str:
    window = settings.rate_limit_window_seconds

    def fmt(limit: int, endpoints: str) -> str:
        if limit <= 0:
            return f"- {endpoints}: unlimited (rate limit disabled)"
        return f"- {endpoints}: {limit} requests per {window}s per IP (HTTP 429 when exceeded)"

    lines = [
        "## Rate limits (per client IP)",
        fmt(
            settings.rate_limit_upload,
            "Uploads (`POST /file/upload`, `POST /api/v2/files`)",
        ),
        fmt(
            settings.rate_limit_browse,
            "Browsing result pages (`GET /ui/`, `/ui/search`, `/ui/file/{hash}`)",
        ),
    ]
    if settings.rate_limit_upload > 0 and settings.chunk_upload_size > 0:
        scaled = max(
            settings.rate_limit_upload,
            settings.rate_limit_upload
            * settings.max_upload_size
            // max(settings.chunk_upload_size, 1),
        )
        lines.append(
            f"- Chunked uploads (`POST /file/upload/chunk`): {scaled} requests per {window}s per IP"
            " (scaled by MAX_UPLOAD_SIZE/CHUNK_UPLOAD_SIZE, so both paths allow the same bytes)"
        )
    return "\n".join(lines)


def _custom_openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    schema["info"]["description"] = (
        "ClamTotal API — VirusTotal-style file analysis.\n\n" + _rate_limits_doc()
    )
    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi  # type: ignore
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _defang(value: str) -> str:
    """Defang an indicator so it is displayed as text and never loaded by accident."""
    return value.replace("http", "hxxp").replace(".", "[.]")


templates.env.filters["defang"] = _defang
_plausible_url: Any = settings.plausible_script_url  # Any: jinja globals stub excludes str
templates.env.globals["plausible_script_url"] = _plausible_url
_app_version: Any = settings.app_version  # Any: jinja globals stub excludes str
templates.env.globals["app_version"] = _app_version

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
    """Delete stored samples past their TTL (ttl=-1 keeps them forever, 0 deletes
    immediately) and always remove stale partial chunked uploads: a chunk dir is
    temporary by design — if the client disconnects or never sends the last chunk,
    the whole .chunks/<sha256>/ dir is deleted after 1h."""
    now = time.time()
    upload_dir = Path(settings.upload_dir)
    if not upload_dir.is_dir():
        return
    chunks_root = upload_dir / ".chunks"
    if chunks_root.is_dir():
        for chunk_dir in chunks_root.iterdir():
            if chunk_dir.is_dir() and now - chunk_dir.stat().st_mtime > 3600:
                shutil.rmtree(chunk_dir, ignore_errors=True)
    ttl = settings.uploads_ttl
    if ttl < 0:
        return
    for f in upload_dir.iterdir():
        if f.is_file() and (ttl == 0 or now - f.stat().st_mtime > ttl * 60):
            f.unlink(missing_ok=True)


_rate_buckets: dict[str, tuple[float, int]] = {}
_rate_lock = threading.Lock()


def _rate_limit_host(host: str, limit: int, kind: str) -> None:
    """Optional fixed-window per-IP rate limit; limit <= 0 disables it."""
    if limit <= 0:
        return
    now = time.time()
    ident = f"{kind}:{host}"
    with _rate_lock:
        start, count = _rate_buckets.get(ident, (now, 0))
        if now - start >= settings.rate_limit_window_seconds:
            start, count = now, 0
        count += 1
        _rate_buckets[ident] = (start, count)
        if len(_rate_buckets) > 10000:  # bound memory: drop stale windows
            stale = [
                k
                for k, (s, _) in _rate_buckets.items()
                if now - s >= settings.rate_limit_window_seconds
            ]
            for k in stale:
                del _rate_buckets[k]
        if count > limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded, try again later")


def _rate_limit(request: Request, limit: int, kind: str) -> None:
    _rate_limit_host(request.client.host if request.client else "unknown", limit, kind)


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


def _require_any_engine(scanner: Scanner | None = Depends(get_scanner)) -> Scanner | None:
    """Upload fail-fast: 503 when no scan engine is enabled AND available, so an upload
    never gets stuck 'pending' forever (e.g. ENABLED_SCANNERS=yara without YARA_RULES_DIR,
    or both engines disabled). ClamAV enabled but down still raises from get_scanner()."""
    if scanner is None and get_yara_scanner() is None:
        raise ScannerUnavailableError(
            "no scan engines enabled/available (check ENABLED_SCANNERS and YARA_RULES_DIR)"
        )
    return scanner


def _scanning_engines(scanner: Scanner | None = None) -> list[dict]:
    """Initial per-engine progress rows (all "scanning") for a freshly enqueued scan.
    The ClamAV engine name comes from the active scanner when one is already resolved
    (lru_cached, so this does not block); when ClamAV is enabled but not resolvable
    right now, fall back to a generic name. ClamAV disabled via ENABLED_SCANNERS
    (get_scanner() is None) simply gets no row."""
    engines: list[dict] = []
    if scanner is not None:
        engines.append({"name": scanner.engine, "status": "scanning"})
    else:
        try:
            clam = get_scanner()
        except ScannerUnavailableError:
            engines.append({"name": "ClamAV", "status": "scanning"})
        else:
            if clam is not None:
                engines.append({"name": clam.engine, "status": "scanning"})
    yara = get_yara_scanner()
    if yara is not None:
        engines.append({"name": yara.engine, "status": "scanning"})
    return engines


def _scan_and_store(
    db: Session,
    scanner: Scanner | None,
    data: bytes,
    file_name: str,
    rescan: bool,
    depth: int = 0,
    path: Path | None = None,
) -> tuple[Scan, bool]:
    """Scan with all local engines, run offline analysis, persist. Returns (scan, was_cached).
    Engine results are committed one by one as they arrive (per-engine status
    "scanning" -> "done"), so the report page shows each verdict live."""
    hashes = compute_hashes(data)
    existing = db.get(Scan, hashes["sha256"])
    if existing and not rescan:
        return existing, True

    scan = existing
    if scan is None:
        scan = Scan(
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            file_name=file_name,
            names=[file_name],
            size=len(data),
            file_type="pending",
            magic_hex="",
            verdict="pending",
            status="pending",
            engine="pending",
            urls=[],
        )
        db.add(scan)
    # multi-engine verdicts: ClamAV (clamd/clamscan) + local YARA rules, each flipped
    # to "done" with its verdict (and committed) the moment the engine finishes.
    # NB: always assign a fresh copy to the JSON column — mutating an assigned list
    # in place also mutates SQLAlchemy's committed state, and later commits then
    # see no change and silently skip the UPDATE.
    engines = _scanning_engines(scanner)
    if not engines:
        raise ScannerUnavailableError(
            "no scan engines enabled/available (check ENABLED_SCANNERS and YARA_RULES_DIR)"
        )
    scan.engines = [dict(e) for e in engines]
    scan.status = "pending"
    scan.verdict = "pending"
    db.commit()

    result: ScanResult | None = None
    engine_idx = 0
    if scanner is not None:
        result = scanner.scan(data, path=path)
        engines[engine_idx].update(
            {"status": "done", "verdict": result.verdict, "signature": result.signature}
        )
        engine_idx += 1
        scan.engines = [dict(e) for e in engines]
        db.commit()

    yara = get_yara_scanner()
    if yara is not None:
        matches = yara.scan(data, path=path)
        engines[engine_idx].update(
            {
                "status": "done",
                "verdict": "infected" if matches else "clean",
                "signature": ", ".join(matches) if matches else None,
            }
        )
        scan.engines = [dict(e) for e in engines]
        db.commit()

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

    # commit the offline analysis (extended hashes, urls, iocs, behavior) while the
    # scan is still pending, so the report page fills in the tabs progressively
    urls = extract_urls(data)
    iocs = extract_iocs(data)
    scan.sha512 = hashes["sha512"]
    scan.crc32 = hashes["crc32"]
    scan.file_type = file_type
    scan.magic_hex = magic_hex
    scan.urls = urls
    scan.iocs = iocs
    scan.behavior = behavior
    db.commit()

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
        engine=result.engine if result is not None else engines[-1]["name"],
        urls=urls,
        raw_output=result.raw if result is not None else "",
        engines=engines,
        iocs=iocs,
        behavior=behavior,
        embedded=embedded,
    )
    for key, value in fields.items():
        setattr(scan, key, value)
    db.commit()
    (Path(settings.upload_dir) / scan.sha256).write_bytes(data)
    return scan, False


def _render_index(request: Request, db: Session) -> HTMLResponse:
    _rate_limit(request, settings.rate_limit_browse, "browse")
    recent = (
        db.execute(select(Scan).order_by(Scan.scanned_at.desc()).limit(20)).scalars().all()
        if settings.show_recent_scans
        else []
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "recent": recent,
            "chunk_size": settings.chunk_upload_size,
            "ws_enabled": settings.ws_upload_enabled and settings.ws_chunk_size > 0,
            "ws_chunk_size": settings.ws_chunk_size,
        },
    )


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    return _render_index(request, db)


@app.get("/ui/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    return _render_index(request, db)


def _run_scan(data: bytes, file_name: str, path: Path | None = None) -> None:
    """Background task: scan with all engines and mark the row done. Never raises:
    a failed scan is logged (with traceback) and the row stays 'pending' for the
    next startup recovery, instead of killing the worker thread silently."""
    logger.info("scan started: %s (%d bytes)", file_name, len(data))
    try:
        with SessionLocal() as db:
            scan, _ = _scan_and_store(db, get_scanner(), data, file_name, rescan=True, path=path)
    except Exception:
        logger.exception("scan failed: %s", file_name)
        return
    logger.info(
        "scan done: %s (%s) verdict=%s signature=%s",
        scan.sha256,
        file_name,
        scan.verdict,
        scan.signature,
    )
    if settings.uploads_ttl == 0:  # delete the stored sample immediately after the scan
        (Path(settings.upload_dir) / scan.sha256).unlink(missing_ok=True)


def _run_scan_file(path: Path, file_name: str) -> None:
    """Background scan of an already-stored sample: the file is read once here, in the
    background, instead of holding the whole upload in the request's memory."""
    try:
        _run_scan(path.read_bytes(), file_name, path=path)
    except Exception:
        logger.exception("scan of stored file failed: %s", path)


def _enqueue_scan(
    background_tasks: BackgroundTasks, db: Session, data: bytes, file_name: str, rescan: bool
) -> tuple[Scan, bool]:
    """Whole-file upload: persist the bytes first, then enqueue the scan from disk."""
    hashes = compute_hashes(data)
    path = Path(settings.upload_dir) / hashes["sha256"]
    path.write_bytes(data)
    return _enqueue_scan_file(background_tasks, db, path, hashes, file_name, rescan)


def _enqueue_scan_file(
    background_tasks: BackgroundTasks | None,
    db: Session,
    path: Path,
    hashes: dict[str, str],
    file_name: str,
    rescan: bool = False,
) -> tuple[Scan, bool]:
    """Return a cached done-row or enqueue an async scan of the already-stored file.
    `hashes` must equal compute_hashes_file(path) — on the chunked path they are computed
    in one streaming pass during assembly, so large files are never re-read/re-hashed
    on the request path. Returns (scan, was_cached)."""
    existing = db.get(Scan, hashes["sha256"])
    if existing and existing.status == "done" and not rescan:
        if file_name not in (existing.names or []):  # record alternative names on cache hits
            existing.names = sorted(set(existing.names or []) | {file_name})
            db.commit()
        return existing, True
    with open(path, "rb") as f:
        head = f.read(65536)  # sniff_file_type only inspects the head of the file
    file_type, magic_hex = sniff_file_type(head)
    if existing:
        already_pending = existing.status == "pending"
        existing.status = "pending"
        existing.verdict = "pending"
        existing.file_name = file_name
        if not already_pending:
            # Fresh (re)scan: reset the per-engine progress. When a scan is already
            # running for this hash, keep the live progress as-is — resetting it to
            # "scanning" would make finished engines flicker back (e.g. the same
            # file enqueued twice via websocket + HTTP fallback).
            existing.engines = _scanning_engines()
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
            size=path.stat().st_size,
            file_type=file_type,
            magic_hex=magic_hex,
            verdict="pending",
            status="pending",
            engine="pending",
            urls=[],
            engines=_scanning_engines(),
        )
        db.add(scan)
    db.commit()
    if background_tasks is not None:
        background_tasks.add_task(_run_scan_file, path, file_name)
    else:
        # websocket endpoints get no BackgroundTasks from starlette — run the scan
        # in a daemon thread instead (same as startup recovery)
        threading.Thread(target=_run_scan_file, args=(path, file_name), daemon=True).start()
    return scan, False


@app.post(
    "/file/upload",
    response_model=UploadResponse,
    responses={
        202: {"model": UploadResponse, "description": "scan queued"},
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def upload(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    rescan: bool = False,
    db: Session = Depends(get_db),
    scanner: Scanner | None = Depends(
        _require_any_engine
    ),  # 503 when no engine is enabled+available
) -> JSONResponse:
    _rate_limit(request, settings.rate_limit_upload, "upload")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    if len(data) > settings.max_upload_size:
        raise HTTPException(status_code=413, detail="file too large")
    # hashing/sniffing a large file is CPU-heavy — run off the event loop so other
    # requests (incl. in-flight chunk uploads) are not stalled while it runs
    scan, cached = await to_thread.run_sync(
        _enqueue_scan, background_tasks, db, data, file.filename or "upload.bin", rescan
    )
    return JSONResponse(
        status_code=200 if cached else 202,
        content={"sha256": scan.sha256, "status": scan.status, "cached": cached},
    )


_CHUNK_NAME_RE = re.compile(r"^[0-9a-f]{64}$")


def _assemble_chunks(
    chunks_dir: Path, total: int, sha256: str
) -> tuple[Path, dict[str, str]] | None:
    """Stream chunk files into one assembled file (never holds the whole file in RAM),
    then hash it in a single streaming pass. Returns (path, hashes), or None when the
    size cap is exceeded or the SHA-256 does not match."""
    assembled = chunks_dir / "assembled"
    size = 0
    with open(assembled, "wb") as out:
        for i in range(total):
            block = (chunks_dir / f"{i:06d}").read_bytes()
            size += len(block)
            if size > settings.max_upload_size:
                return None
            out.write(block)
    hashes = compute_hashes_file(assembled)
    if hashes["sha256"] != sha256:
        return None
    return assembled, hashes


@app.post(
    "/file/upload/chunk",
    response_model=UploadResponse,
    responses={
        202: {"model": ChunkUploadResponse, "description": "chunk stored, more expected"},
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def upload_chunk(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    sha256: str = Form(...),
    index: int = Form(...),
    total: int = Form(...),
    name: str = Form(""),
    db: Session = Depends(get_db),
    scanner: Scanner | None = Depends(
        _require_any_engine
    ),  # 503 when no engine is enabled+available
) -> JSONResponse:
    """Chunked upload for large files (behind proxies with request-body size limits).
    Chunks are stored under UPLOAD_DIR/.chunks/<sha256>/; when the last one arrives the
    file is reassembled, its SHA-256 verified, and the normal scan is enqueued."""
    if settings.chunk_upload_size <= 0:
        raise HTTPException(status_code=404, detail="chunked upload disabled")
    # each chunk request carries only chunk_upload_size bytes, while a whole-file upload
    # carries up to max_upload_size — scale the request limit so both paths allow the
    # same BYTES per window (never fewer requests than the plain upload limit)
    upload_limit = settings.rate_limit_upload
    if upload_limit > 0:
        upload_limit = max(
            upload_limit,
            upload_limit * settings.max_upload_size // max(settings.chunk_upload_size, 1),
        )
    # separate bucket from whole-file uploads so the scaled limit applies to chunks only
    _rate_limit(request, upload_limit, "upload_chunk")
    if not _CHUNK_NAME_RE.match(sha256) or total < 1 or not 0 <= index < total:
        raise HTTPException(status_code=400, detail="invalid sha256/index/total")
    data = await file.read()
    if not data or len(data) > settings.max_upload_size:
        raise HTTPException(status_code=400, detail="empty or oversized chunk")
    chunks_dir = Path(settings.upload_dir) / ".chunks" / sha256
    chunks_dir.mkdir(parents=True, exist_ok=True)
    # blocking disk write off the event loop so in-flight requests are not stalled
    await to_thread.run_sync((chunks_dir / f"{index:06d}").write_bytes, data)
    received = len(list(chunks_dir.iterdir()))
    if received < total:
        return JSONResponse(
            status_code=202,
            content={
                "status": "chunk_stored",
                "sha256": sha256,
                "received": received,
                "total": total,
            },
        )
    # reassemble + hash off the event loop: up to MAX_UPLOAD_SIZE of CPU/IO work,
    # streamed to disk so the whole file is never held in memory at once
    result = await to_thread.run_sync(_assemble_chunks, chunks_dir, total, sha256)
    if result is None:
        shutil.rmtree(chunks_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="assembled file failed hash/size verification")
    assembled, hashes = result
    final = Path(settings.upload_dir) / sha256
    shutil.move(str(assembled), str(final))
    shutil.rmtree(chunks_dir, ignore_errors=True)
    scan, cached = await to_thread.run_sync(
        _enqueue_scan_file,
        background_tasks,
        db,
        final,
        hashes,
        name or file.filename or "upload.bin",
    )
    return JSONResponse(
        status_code=200 if cached else 202,
        content={"sha256": scan.sha256, "status": scan.status, "cached": cached},
    )


@app.websocket("/file/upload/ws")
async def upload_ws(
    websocket: WebSocket,
    db: Session = Depends(get_db),
    scanner: Scanner | None = Depends(
        _require_any_engine
    ),  # 503 when no engine is enabled+available
) -> None:
    # Chunked upload over one persistent WebSocket: small binary frames and no
    # per-request proxy body cap / ~100s timeout (Cloudflare limits that bite HTTP
    # chunks). Resumable: on (re)connect the client sends "start" and the server
    # replies with the chunk indices it already stored. The client falls back to
    # POST /file/upload/chunk when the socket fails.
    #
    # Protocol (JSON text frames for control, binary frames for payload):
    #   client -> {"type":"start","sha256","total","name"}
    #   server -> {"type":"ready","received":[indices]}
    #   client -> {"type":"chunk","index":i,"size":n} then n bytes as binary frame(s)
    #   server -> {"type":"ack","index":i,"received":k}  (k == total -> assemble+scan)
    #   server -> {"type":"done","sha256","cached"} | {"type":"error","detail"}
    await websocket.accept()
    if not (settings.ws_upload_enabled and settings.ws_chunk_size > 0):
        await websocket.send_text(
            json.dumps({"type": "error", "detail": "websocket upload disabled"})
        )
        await websocket.close()
        return
    _rate_limit_host(
        websocket.client.host if websocket.client else "unknown",
        settings.rate_limit_upload,
        "upload_ws",
    )
    chunks_dir: Path | None = None
    sha256 = ""
    total = 0
    name = ""
    pending_index = -1
    pending_size = 0
    buf = bytearray()

    async def fail(detail: str) -> None:
        await websocket.send_text(json.dumps({"type": "error", "detail": detail}))
        await websocket.close()

    while True:
        msg = await websocket.receive()
        if msg.get("type") == "websocket.disconnect":
            return
        if "text" in msg:
            try:
                ctrl = json.loads(msg["text"])
                kind = ctrl["type"]
                if kind == "start":
                    sha256 = str(ctrl["sha256"])
                    total = int(ctrl["total"])
                    name = str(ctrl.get("name", ""))
                    if not _CHUNK_NAME_RE.match(sha256) or total < 1:
                        await fail("invalid sha256/total")
                        return
                    chunks_dir = Path(settings.upload_dir) / ".chunks" / sha256
                    chunks_dir.mkdir(parents=True, exist_ok=True)
                    received = sorted(int(p.stem) for p in chunks_dir.iterdir() if p.stem.isdigit())
                    await websocket.send_text(json.dumps({"type": "ready", "received": received}))
                elif kind == "chunk":
                    if chunks_dir is None:
                        await fail("start first")
                        return
                    pending_index = int(ctrl["index"])
                    pending_size = int(ctrl["size"])
                    if (
                        not 0 <= pending_index < total
                        or not 0 < pending_size <= settings.max_upload_size
                    ):
                        await fail("invalid index/size")
                        return
                    buf = bytearray()
                else:
                    await fail(f"unknown message type {kind!r}")
                    return
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                await fail("malformed control message")
                return
        else:  # binary payload frame
            if pending_index < 0 or chunks_dir is None:
                await fail("chunk header first")
                return
            buf += msg["bytes"]
            if len(buf) > pending_size:
                await fail("chunk size mismatch")
                return
            if len(buf) == pending_size:
                data = bytes(buf)
                idx = pending_index
                buf = bytearray()
                pending_index = -1
                await to_thread.run_sync((chunks_dir / f"{idx:06d}").write_bytes, data)
                received = len(list(chunks_dir.iterdir()))
                await websocket.send_text(
                    json.dumps({"type": "ack", "index": idx, "received": received})
                )
                if received >= total:
                    # same as the HTTP path: stream-assemble, verify, enqueue from disk
                    result = await to_thread.run_sync(_assemble_chunks, chunks_dir, total, sha256)
                    if result is None:
                        shutil.rmtree(chunks_dir, ignore_errors=True)
                        await fail("assembled file failed hash/size verification")
                        return
                    assembled, hashes = result
                    final = Path(settings.upload_dir) / sha256
                    shutil.move(str(assembled), str(final))
                    shutil.rmtree(chunks_dir, ignore_errors=True)
                    scan, cached = await to_thread.run_sync(
                        _enqueue_scan_file,
                        None,  # no BackgroundTasks on websockets — scan runs in a thread
                        db,
                        final,
                        hashes,
                        name or "upload.bin",
                    )
                    await websocket.send_text(
                        json.dumps({"type": "done", "sha256": scan.sha256, "cached": cached})
                    )
                    await websocket.close()
                    return


@app.get("/ui/file/{hash_value}", response_class=HTMLResponse)
def report(request: Request, hash_value: str, db: Session = Depends(get_db)) -> HTMLResponse:
    _rate_limit(request, settings.rate_limit_browse, "browse")
    scan = _lookup(db, hash_value)
    if scan is None:
        return templates.TemplateResponse(
            request, "not_found.html", {"hash_value": hash_value}, status_code=404
        )
    stored = Path(settings.upload_dir) / scan.sha256
    stored_exists = stored.exists()
    entropy = shannon_entropy_file(stored) if stored_exists else 0.0
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
            "stored_exists": stored_exists,
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
    scanner: Scanner | None = Depends(
        _require_any_engine
    ),  # 503 when no engine is enabled+available
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
    _rate_limit(request, settings.rate_limit_browse, "browse")
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


@app.post(
    "/api/v2/files",
    response_model=ApiScanResponse,
    responses={
        202: {"model": ApiScanResponse, "description": "scan queued"},
        400: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def api_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    scanner: Scanner | None = Depends(
        _require_any_engine
    ),  # 503 when no engine is enabled+available
) -> JSONResponse:
    _rate_limit(request, settings.rate_limit_upload, "upload")
    data = await file.read()
    if not data:
        return JSONResponse(status_code=400, content={"detail": "empty file"})
    scan, cached = await to_thread.run_sync(
        _enqueue_scan, background_tasks, db, data, file.filename or "upload.bin", False
    )
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


@app.get(
    "/api/v2/files/{hash_value}",
    response_model=FileReport,
    responses={404: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
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


def _iso_utc(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    """Service health plus per-engine readiness: whether each engine is enabled
    (ENABLED_SCANNERS), ready (clamd PING / clamscan present / YARA rules loaded),
    its version, rule count, and last rules update time."""
    enabled = enabled_scanners()
    engines: list[EngineHealth] = []
    if "clamav" in enabled:
        try:
            scanner = get_scanner()
        except ScannerUnavailableError:
            scanner = None
        ready = scanner is not None and scanner.available()
        rules, updated = clamav_db_stats(settings.clamav_db_dir)
        engines.append(
            EngineHealth(
                name=scanner.engine if scanner is not None else "ClamAV",
                type="clamav",
                enabled=True,
                ready=ready,
                version=scanner.version() if scanner is not None else None,
                rules=rules,
                rules_updated_at=_iso_utc(updated),
            )
        )
    else:
        engines.append(
            EngineHealth(
                name="ClamAV",
                type="clamav",
                enabled=False,
                ready=False,
                version=None,
                rules=None,
                rules_updated_at=None,
            )
        )
    if "yara" in enabled:
        yara_scanner = get_yara_scanner()
        engines.append(
            EngineHealth(
                name=yara_scanner.engine if yara_scanner is not None else "YARA (local rules)",
                type="yara",
                enabled=True,
                ready=yara_scanner is not None and yara_scanner.available(),
                version=getattr(yara, "__version__", None),
                rules=yara_scanner.rules_count if yara_scanner is not None else None,
                rules_updated_at=(
                    _iso_utc(yara_scanner.rules_updated_at) if yara_scanner is not None else None
                ),
            )
        )
    else:
        engines.append(
            EngineHealth(
                name="YARA (local rules)",
                type="yara",
                enabled=False,
                ready=False,
                version=None,
                rules=None,
                rules_updated_at=None,
            )
        )
    status = "ok" if any(e.enabled and e.ready for e in engines) else "degraded"
    return HealthResponse(status=status, engines=engines)
