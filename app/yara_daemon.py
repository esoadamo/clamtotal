"""YARA scan daemon: compiles the rule set ONCE in a single process and serves match
requests over a Unix socket (clamd-style NUL-terminated z-commands), so uvicorn
workers don't each compile the rules into their own RAM — with --workers N that
multiplied memory and the kernel OOM-killed workers on the first scan/health check.

Protocol (all commands and responses NUL-terminated):
  zPING\0                    -> PONG\0
  zVERSION\0                 -> "yara <version>"\0
  zSTATS\0                   -> JSON {"engine","version","rules","rules_updated_at"}\0
  zSCANPATH <path>\0         -> JSON list of matching rule names\0 (daemon mmaps the file)
  zINSTREAM\0 <4B-len><data>... <4B 0>  -> JSON list of matches\0 (in-memory samples)
  anything else              -> ERROR <message>\0
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import threading
from pathlib import Path

import yara  # ty: ignore[unresolved-import]  # compiled extension, no stubs

from app.scanner import YaraScanner, rss_mb

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise OSError("connection closed mid-message")
        data += part
    return data


def _recv_command(conn: socket.socket) -> bytes:
    # read byte-by-byte up to the NUL terminator: a bulk recv could swallow the
    # first INSTREAM chunk bytes that follow the command on the same connection
    cmd = b""
    while True:
        part = conn.recv(1)
        if not part or part == b"\x00":
            break
        cmd += part
    return cmd.strip()


def _handle_instream(conn: socket.socket, scanner: YaraScanner) -> None:
    data = b""
    while True:
        (size,) = struct.unpack(">I", _recv_exact(conn, 4))
        if size == 0:
            break
        data += _recv_exact(conn, size)
    _send_matches(conn, scanner.scan(data))


def _send_matches(conn: socket.socket, matches: list[str]) -> None:
    conn.sendall(json.dumps(matches).encode() + b"\x00")


def handle_conn(conn: socket.socket, scanner: YaraScanner) -> None:
    try:
        with conn:
            cmd = _recv_command(conn)
            if cmd == b"zPING":
                conn.sendall(b"PONG\x00")
            elif cmd == b"zVERSION":
                conn.sendall(f"yara {yara.__version__}\x00".encode())
            elif cmd == b"zSTATS":
                conn.sendall(
                    json.dumps(
                        {
                            "engine": scanner.engine,
                            "version": yara.__version__,
                            "rules": scanner.rules_count,
                            "rules_updated_at": scanner.rules_updated_at,
                        }
                    ).encode()
                    + b"\x00"
                )
            elif cmd.startswith(b"zSCANPATH "):
                path = cmd[len(b"zSCANPATH ") :].decode(errors="replace")
                _send_matches(conn, scanner.scan(b"", path=Path(path)))
            elif cmd == b"zINSTREAM":
                _handle_instream(conn, scanner)
            else:
                conn.sendall(b"ERROR unknown command\x00")
    except OSError:
        pass  # client went away mid-command


def _mem_info() -> tuple[float | None, str | None]:
    """(RSS in MB, cgroup memory limit as text) for startup logging — the compile of
    a large rule set is the main memory spike; if the daemon gets SIGKILLed during it,
    the kernel OOM killer hit the cgroup limit."""
    limit = None
    for p in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            limit = Path(p).read_text().strip()
            break
        except OSError:
            continue
    return rss_mb(), limit


def serve(rules_dir: str, socket_path: str) -> None:
    """Listen on the Unix socket forever, one thread per connection (yara releases
    the GIL during match(), so scans overlap)."""
    rss, limit = _mem_info()
    logger.info(
        "yara daemon starting: rules=%s rss_before=%.0fMB cgroup_limit=%s",
        rules_dir,
        rss or 0,
        limit or "?",
    )
    scanner = YaraScanner(rules_dir)
    rss, _ = _mem_info()
    logger.info("yara daemon ready on %s: rss_after_compile=%.0fMB", socket_path, rss or 0)
    Path(socket_path).unlink(missing_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn, scanner), daemon=True).start()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    parser = argparse.ArgumentParser(description="ClamTotal YARA scan daemon")
    parser.add_argument("--rules", required=True, help="YARA rules directory")
    parser.add_argument("--socket", required=True, help="Unix socket path to listen on")
    args = parser.parse_args()
    serve(args.rules, args.socket)


if __name__ == "__main__":  # pragma: no cover
    main()
