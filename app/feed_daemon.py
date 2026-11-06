"""Domain feed daemon: imports the downloaded domain-feed lists into their OWN SQLite
database (feed.db inside the feed dir — separate from the app database) ONCE in a single
process and serves lookups over a Unix socket (clamd-style NUL-terminated z-commands),
so uvicorn workers don't each import the lists. Hot-reloads in a background thread when
.feed-stamp changes (touched by scripts/update-domain-feed.sh). Started by the container
entrypoint, like the YARA daemon.

Protocol (all commands and responses NUL-terminated):
  zPING\\0                 -> PONG\\0
  zVERSION\\0              -> "domain-feed (<n> entries)"\\0
  zSTATS\\0                -> JSON {"engine","entries","updated_at"}\\0
  zLOOKUP <host>\\0        -> JSON [{"domain","source","category"}, ...]\\0
  anything else           -> ERROR <message>\\0
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import threading
from pathlib import Path

from app.domain_feed import DomainFeed

logger = logging.getLogger(__name__)


def _recv_command(conn: socket.socket) -> bytes:
    # read byte-by-byte up to the NUL terminator
    cmd = b""
    while True:
        part = conn.recv(1)
        if not part or part == b"\x00":
            break
        cmd += part
    return cmd.strip()


def handle_conn(conn: socket.socket, feed: DomainFeed) -> None:
    try:
        with conn:
            cmd = _recv_command(conn)
            try:
                if cmd == b"zPING":
                    conn.sendall(b"PONG\x00")
                elif cmd == b"zVERSION":
                    conn.sendall(feed.version().encode() + b"\x00")
                elif cmd == b"zSTATS":
                    entries, updated = feed.stats()
                    conn.sendall(
                        json.dumps(
                            {"engine": feed.engine, "entries": entries, "updated_at": updated}
                        ).encode()
                        + b"\x00"
                    )
                elif cmd.startswith(b"zLOOKUP "):
                    host = cmd[len(b"zLOOKUP ") :].decode(errors="replace")
                    conn.sendall(json.dumps(feed.lookup(host)).encode() + b"\x00")
                else:
                    conn.sendall(b"ERROR unknown command\x00")
            except Exception:
                # a failed lookup must answer ERROR while the conn is still open,
                # not drop the connection silently
                logger.exception("feed daemon: command failed")
                conn.sendall(b"ERROR internal error\x00")
    except OSError:
        pass  # client went away mid-command


def serve(feed_dir: str, db_path: str, socket_path: str) -> None:
    """Listen on the Unix socket forever, one thread per connection."""
    logger.info("domain feed daemon starting: feed=%s db=%s", feed_dir, db_path)
    feed = DomainFeed(feed_dir)
    logger.info("domain feed daemon ready on %s: %s", socket_path, feed.version())
    Path(socket_path).unlink(missing_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn, feed), daemon=True).start()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    parser = argparse.ArgumentParser(description="ClamTotal domain feed daemon")
    parser.add_argument(
        "--feed-dir", required=True, help="directory with the downloaded feed .txt files"
    )
    parser.add_argument(
        "--db", required=True, help="SQLite database file for the feed (separate from the app DB)"
    )
    parser.add_argument("--socket", required=True, help="Unix socket path to listen on")
    args = parser.parse_args()
    serve(args.feed_dir, args.db, args.socket)


if __name__ == "__main__":  # pragma: no cover
    main()
