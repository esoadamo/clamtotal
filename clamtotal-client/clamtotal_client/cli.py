"""clamtotal-client: scan files and fetch reports from a ClamTotal server.

Every option falls back to an environment variable: --url -> CLAMTOTAL_URL
(default https://clamtotal.com), --timeout -> CLAMTOTAL_TIMEOUT,
--token -> CLAMTOTAL_API_KEY, --engines (scan) -> CLAMTOTAL_ENGINES.

`scan` picks the best upload transport the server supports (direct,
HTTP-chunked, or WebSocket; see GET /api/v2/upload/capabilities), shows a
live progress line with speed and ETA while uploading, then polls until the
analysis is finished and prints the verdict. `--no-wait-result` skips the
waiting and prints only the upload response. A hash the server already knows
(pending or analyzed) is not uploaded again unless `--rescan` is passed.

`describe <file>` hashes a local file and shows its report (uploading it only
when the server does not know it yet, or with `--rescan`); `describe --hash`
looks a hash up and never uploads.
"""

import argparse
import hashlib
import json
import os
import sys
import time

from . import __version__, api

WAIT_RESULT_DEFAULT = 300.0


def _opt(value, env, default):
    return value if value is not None else os.environ.get(env, default)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clamtotal-client",
        description="Scan files and fetch reports from a ClamTotal server",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--url",
        help=f"ClamTotal backend base URL (env CLAMTOTAL_URL, default {api.DEFAULT_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="request timeout in seconds (env CLAMTOTAL_TIMEOUT, default 60)",
    )
    parser.add_argument("--token", help="API key sent as X-Api-Key (env CLAMTOTAL_API_KEY)")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="upload a file for scanning")
    scan.add_argument("file", nargs="+", help="file(s) to scan")
    scan.add_argument("--rescan", action="store_true", help="force a re-analysis")
    scan.add_argument("--ephemeral", action="store_true", help="do not persist the sample")
    scan.add_argument(
        "--no-progress",
        action="store_true",
        help="hide the upload progress indicator (shown on stderr by default)",
    )
    scan.add_argument(
        "--engines",
        metavar="IDS",
        help="comma-separated engines to run (clamav, yara, domain-feed; default: all; "
        "env CLAMTOTAL_ENGINES)",
    )
    scan.add_argument(
        "--wait",
        type=float,
        metavar="SECONDS",
        help=f"max seconds to wait for the analysis (default: {WAIT_RESULT_DEFAULT:g})",
    )
    scan.add_argument(
        "--no-wait-result",
        action="store_true",
        help="print the upload response only; do not wait for the scan result",
    )
    scan.add_argument("--json", action="store_true", help="print raw JSON responses")

    describe = sub.add_parser(
        "describe",
        help="show the report for a file or a hash; uploads the file only when unknown",
    )
    describe.add_argument(
        "target", nargs="?", help="local file path, or a MD5 / SHA-1 / SHA-256 of a known sample"
    )
    describe.add_argument(
        "--hash", metavar="SHA", help="describe this hash (never upload anything)"
    )
    describe.add_argument(
        "--rescan", action="store_true", help="re-analyze the file (uploads it again)"
    )
    describe.add_argument("--json", action="store_true", help="print raw JSON report")

    url_cmd = sub.add_parser("url", help="check a URL/domain against the domain feed")
    url_cmd.add_argument("target", help="URL or domain to check")
    url_cmd.add_argument("--json", action="store_true", help="print raw JSON response")
    return parser


def _print_scan_result(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    status = "cached" if result.get("status") == "done" else result.get("status", "?")
    print(f"sha256: {result.get('sha256', '?')}  status: {status}")


def _wait_for_report(args: argparse.Namespace, sha256: str, budget: float) -> dict:
    deadline = time.monotonic() + budget
    while True:
        report = api.get_report(args.base_url, sha256, token=args.token, timeout=args.timeout)
        if report.get("status") != "pending" or time.monotonic() >= deadline:
            return report
        time.sleep(1.0)


def _report_exit_code(report: dict) -> tuple[int, list[str]]:
    """0 only when every enabled engine finished and reported no detection.
    Any infection -> 2. An engine that never delivered its verdict (still
    scanning, timed out, report pending) -> 1, because 'clean' is unproven.
    Servers without per-engine dicts fall back to the overall verdict/status."""
    engines = [e for e in report.get("engines") or [] if isinstance(e, dict)]
    if report.get("verdict") == "infected" or any(e.get("verdict") == "infected" for e in engines):
        return 2, []
    if not engines:
        return (0, []) if report.get("status") == "done" else (1, [])
    unfinished = [e.get("name", "?") for e in engines if e.get("status") != "done"]
    return (0, []) if not unfinished else (1, unfinished)


def _show_report(report: dict, as_json: bool, timed_out: bool) -> int:
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        verdict = report.get("verdict", "?")
        sig = report.get("signature") or "no signature"
        print(f"verdict: {verdict}  signature: {sig}")
    code, unfinished = _report_exit_code(report)
    if timed_out:
        print(f"scan still pending (sha256: {report.get('sha256', '?')})", file=sys.stderr)
    elif unfinished:
        print(f"no clean verdict from: {', '.join(unfinished)}", file=sys.stderr)
    return code


def _defang(value: str) -> str:
    """Neutralize a URL for safe reading/copy-paste into reports: the JSON API
    serves raw URLs, so the human output defangs them (hxxp + [.]) — --json
    keeps the raw value for machines."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    units = ("KB", "MB", "GB", "TB")
    value, unit = float(n), -1
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    return f"{round(value, 1):g} {units[unit]}"


def _fmt_eta(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds >= 60:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds}s"


def _progress_printer(path: str, transport: str):
    """Live upload line on stderr, redrawn in place. Reports the transfer rate
    and ETA once enough bytes have flowed to estimate them."""
    name = os.path.basename(path)
    label = {
        "direct": "uploading",
        "chunked": "uploading (chunked)",
        "websocket": "uploading (ws)",
    }[transport]
    start = time.monotonic()

    def report(sent: int, total: int) -> None:
        pct = min(100, sent * 100 // max(total, 1))
        stats = ""
        elapsed = time.monotonic() - start
        rate = sent / elapsed if elapsed > 0.25 else 0
        if rate > 0:
            stats = f", {_fmt_bytes(int(rate))}/s"
            if sent < total:
                stats += f", eta {_fmt_eta((total - sent) / rate)}"
        print(
            f"\r{label} {name}: {pct}% ({_fmt_bytes(sent)} of {_fmt_bytes(total)}){stats}   ",
            end="",
            file=sys.stderr,
            flush=True,
        )

    return report


def _choose_transport(size: int, caps: dict) -> str:
    """Best transport for this file given what the server supports: one request
    for small files; the resumable single-connection WebSocket for large ones;
    HTTP chunks when the WS path is unavailable."""
    if not caps.get("chunked") or caps.get("chunk_size", 0) <= 0:
        return "direct"  # no chunking possible: one whole-file request
    if size <= caps["chunk_size"]:
        return "direct"
    if caps.get("websocket") and caps.get("ws_chunk_size", 0) > 0:
        return "websocket"
    return "chunked"


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _upload(
    args: argparse.Namespace,
    path: str,
    size: int,
    caps: dict,
    show_progress: bool,
    sha256: str | None = None,
):
    transport = _choose_transport(size, caps)
    while True:
        progress = _progress_printer(path, transport) if show_progress else None
        try:
            with open(path, "rb") as fh:
                if transport == "direct":
                    return api.post_file(
                        args.base_url,
                        "/api/v2/files",
                        os.path.basename(path),
                        fh.read(),
                        token=args.token,
                        timeout=args.timeout,
                        rescan=args.rescan,
                        ephemeral=args.ephemeral,
                        engines=args.engines,
                        progress=progress,
                    )
                sha256 = sha256 or _sha256_file(path)
                if transport == "websocket":
                    return api.upload_ws(
                        args.base_url,
                        fh,
                        os.path.basename(path),
                        size,
                        sha256,
                        caps["ws_chunk_size"],
                        token=args.token,
                        timeout=args.timeout,
                        rescan=args.rescan,
                        ephemeral=args.ephemeral,
                        engines=args.engines,
                        progress=progress,
                    )
                return api.post_file_chunked(
                    args.base_url,
                    fh,
                    os.path.basename(path),
                    size,
                    sha256,
                    caps["chunk_size"],
                    token=args.token,
                    timeout=args.timeout,
                    rescan=args.rescan,
                    ephemeral=args.ephemeral,
                    engines=args.engines,
                    progress=progress,
                )
        except api.ClientError:
            # the websocket path degrades to HTTP chunks (the server shares the
            # chunk storage, so a retried chunk set resumes instead of restarting)
            if transport == "websocket" and caps.get("chunked"):
                caps = dict(caps, websocket=False)
                transport = "chunked"
                continue
            raise


def cmd_scan(args: argparse.Namespace) -> int:
    exit_code = 0
    args.engines = _opt(args.engines, "CLAMTOTAL_ENGINES", None) or ""
    for path in args.file:
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        show_progress = not args.no_progress
        try:
            sha256 = _sha256_file(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        existing = None
        if not args.rescan:  # a known (or already queued) hash: no need to upload again
            try:
                existing = api.get_report(
                    args.base_url, sha256, token=args.token, timeout=args.timeout
                )
            except api.ClientError:
                existing = None
        if existing is not None:
            print(
                f"{os.path.basename(path)}: {sha256} already analyzed on the server;"
                " not re-uploading (use --rescan to force a new analysis)",
                file=sys.stderr,
            )
            result = existing
        else:
            try:
                caps = api.get_capabilities(args.base_url, token=args.token, timeout=args.timeout)
            except api.ClientError:
                caps = {}  # an older server without the endpoint: whole-file POST only
            try:
                result = _upload(args, path, size, caps, show_progress, sha256=sha256)
            except api.ClientError as exc:
                if show_progress:
                    print(file=sys.stderr, flush=True)  # close the progress line
                print(f"error: {exc}", file=sys.stderr)
                exit_code = 1
                continue
            except OSError as exc:
                if show_progress:
                    print(file=sys.stderr, flush=True)
                print(f"error: cannot read {path}: {exc}", file=sys.stderr)
                exit_code = 1
                continue
        if show_progress:
            print(file=sys.stderr, flush=True)  # close the progress line
        if args.no_wait_result:
            _print_scan_result(result, args.json)
            continue
        sha256 = result.get("sha256")
        if not sha256:  # no waitable id in the response: show it and move on
            _print_scan_result(result, args.json)
            exit_code = exit_code or 1
            continue
        budget = args.wait if args.wait is not None else WAIT_RESULT_DEFAULT
        report = _wait_for_report(args, sha256, budget)
        timed_out = report.get("status") == "pending"
        exit_code = exit_code or _show_report(report, args.json, timed_out)
    return exit_code


def cmd_describe(args: argparse.Namespace) -> int:
    """Describe a local file or a hash. The hash of an existing file is used
    directly (uploading again only when the server does not know the sample or
    --rescan was passed); a bare --hash lookup never uploads. --rescan without
    a sample file is impossible: the daemon rescans only what it can read."""
    target = args.hash or (args.target or "").strip()
    if not target:
        print("error: describe needs a local file or --hash", file=sys.stderr)
        return 1
    path = None
    if args.hash is None:  # a real local file wins over hash-shaped input
        try:
            if os.path.isfile(args.target):
                path = args.target
        except (OSError, TypeError):
            path = None
    try:
        sha256 = _sha256_file(path) if path else target
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 1
    report = None
    try:
        report = api.get_report(args.base_url, sha256, token=args.token, timeout=args.timeout)
    except api.ClientError as exc:
        if path is None:  # nothing to fall back to: report the lookup failure
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if args.rescan or report is None:
        if path is None:
            print(
                f"error: no report for {target}; pass the sample file instead of --hash"
                " so it can be analyzed",
                file=sys.stderr,
            )
            return 1
        args.engines = _opt(None, "CLAMTOTAL_ENGINES", None) or ""
        args.ephemeral = False
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 1
        try:
            caps = api.get_capabilities(args.base_url, token=args.token, timeout=args.timeout)
        except api.ClientError:
            caps = {}
        try:
            result = _upload(args, path, size, caps, False)
        except (api.ClientError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        sha256 = result.get("sha256") or sha256
        report = _wait_for_report(args, sha256, WAIT_RESULT_DEFAULT)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        sig = report.get("signature") or "no signature"
        print(f"verdict:   {report.get('verdict', '?')}  ({sig})")
        print(f"file:      {report.get('file_name', '?')}  ({report.get('size', '?')} bytes)")
        print(f"type:      {report.get('file_type', '?')}")
        engines = ", ".join(
            e.get("name", "?") if isinstance(e, dict) else str(e)
            for e in report.get("engines") or []
        )
        print(f"engines:   {engines or '?'}")
        for algo in ("sha256", "sha1", "md5", "sha512", "crc32"):
            print(f"{algo + ':':<10} {report.get(algo, '?')}")
        urls = report.get("urls") or []
        if urls:
            print("urls:")
            for u in urls:
                print(f"  {_defang(u)}")
    code, unfinished = _report_exit_code(report)
    if report.get("status") == "pending":
        print(f"scan still pending (sha256: {report.get('sha256', '?')})", file=sys.stderr)
    elif unfinished:
        print(f"no clean verdict from: {', '.join(unfinished)}", file=sys.stderr)
    return code


def cmd_url(args: argparse.Namespace) -> int:
    try:
        result = api.post_url(args.base_url, args.target, token=args.token, timeout=args.timeout)
    except api.ClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"verdict: {result.get('verdict', '?')}  id: {result.get('id', '?')}")
        print(f"url:     {_defang(result.get('url', '?'))}")
        for cat in result.get("categories", []):
            print(f"category: {cat}")
    return 2 if result.get("verdict") == "malicious" else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.base_url = _opt(args.url, "CLAMTOTAL_URL", api.DEFAULT_URL)
    args.timeout = float(_opt(args.timeout, "CLAMTOTAL_TIMEOUT", api.DEFAULT_TIMEOUT))
    args.token = _opt(args.token, "CLAMTOTAL_API_KEY", None)
    return {"scan": cmd_scan, "describe": cmd_describe, "url": cmd_url}[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
