"""clamtotal-client: scan files and fetch reports from a ClamTotal server.

Every option falls back to an environment variable: --url -> CLAMTOTAL_URL
(default https://clamtotal.com), --timeout -> CLAMTOTAL_TIMEOUT,
--token -> CLAMTOTAL_API_KEY.
"""

import argparse
import json
import os
import sys
import time

from . import __version__, api


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
        "--engines",
        metavar="IDS",
        help="comma-separated engines to run (clamav, yara, domain-feed; default: all)",
    )
    scan.add_argument(
        "--wait",
        type=float,
        metavar="SECONDS",
        help="poll until the analysis finishes (max seconds), then print the verdict",
    )
    scan.add_argument("--json", action="store_true", help="print raw JSON responses")

    describe = sub.add_parser("describe", help="show the report for a hash")
    describe.add_argument("hash", help="MD5 / SHA-1 / SHA-256 of a known sample")
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


def _wait_for_verdict(args: argparse.Namespace, sha256: str) -> int:
    deadline = time.monotonic() + (args.wait or 0)
    while True:
        report = api.get_report(args.base_url, sha256, token=args.token, timeout=args.timeout)
        if report.get("status") != "pending" or time.monotonic() >= deadline:
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                verdict = report.get("verdict", "?")
                sig = report.get("signature") or "no signature"
                print(f"verdict: {verdict}  signature: {sig}")
            return 2 if report.get("verdict") == "infected" else 0
        time.sleep(1.0)


def cmd_scan(args: argparse.Namespace) -> int:
    exit_code = 0
    for path in args.file:
        try:
            with open(path, "rb") as fh:
                content = fh.read()
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        try:
            result = api.post_file(
                args.base_url,
                "/api/v2/files",
                os.path.basename(path),
                content,
                token=args.token,
                timeout=args.timeout,
                rescan=args.rescan,
                ephemeral=args.ephemeral,
                engines=args.engines or "",
            )
        except api.ClientError as exc:
            print(f"error: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        _print_scan_result(result, args.json)
        if args.wait is not None and result.get("status") != "done":
            exit_code = exit_code or _wait_for_verdict(args, result["sha256"])
    return exit_code


def cmd_describe(args: argparse.Namespace) -> int:
    try:
        report = api.get_report(args.base_url, args.hash, token=args.token, timeout=args.timeout)
    except api.ClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2))
    verdict = report.get("verdict", "?")
    if not args.json:
        print(f"verdict:   {verdict}  ({report.get('signature') or 'no signature'})")
        print(f"file:      {report.get('file_name', '?')}  ({report.get('size', '?')} bytes)")
    if not args.json:
        print(f"type:      {report.get('file_type', '?')}")
        print(f"engines:   {', '.join(report.get('engines', [])) or '?'}")
        for algo in ("sha256", "sha1", "md5", "sha512", "crc32"):
            print(f"{algo + ':':<10} {report.get(algo, '?')}")
        urls = report.get("urls") or []
        if urls:
            print("urls:")
            for u in urls:
                print(f"  {u}")
    return 2 if verdict == "infected" else 0


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
