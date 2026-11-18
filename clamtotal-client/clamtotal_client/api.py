"""Minimal stdlib-only HTTP client for the ClamTotal VT-style JSON API.

Upload transports (selected by the CLI from the server's advertised capabilities,
see GET /api/v2/upload/capabilities):

- direct:  one multipart POST of the whole file (small files, fewest requests)
- chunked:  many small multipart POSTs to /file/upload/chunk (proxy body caps)
- websocket: one persistent /file/upload/ws connection with small binary frames
"""

import base64
import json
import os
import socket
import ssl
import struct
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterable
from typing import Protocol

DEFAULT_URL = "https://clamtotal.com"
DEFAULT_TIMEOUT = 60.0
PROGRESS_CHUNK = 1024 * 1024


class ClientError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


def _request(
    base_url: str,
    path: str,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    data: bytes | Iterable[bytes] | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    url = base_url.rstrip("/") + path
    req_headers = {"User-Agent": "clamtotal-client"}
    if token:
        req_headers["X-Api-Key"] = token
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail", exc.reason)
        except (ValueError, AttributeError):
            detail = str(exc.reason or exc)
        raise ClientError(exc.code, str(detail)) from exc
    except urllib.error.URLError as exc:
        raise ClientError(0, f"cannot reach {url}: {exc.reason}") from exc
    if not body:
        return {}
    return json.loads(body)


def get_capabilities(
    base_url: str,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Server's upload support. Older servers 404 here; the caller falls back
    to whole-file uploads, which every version supports."""
    return _request(base_url, "/api/v2/upload/capabilities", token=token, timeout=timeout)


def _form_field(boundary: str, name: str, value: str) -> bytes:
    return (
        f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
    )


class _ProgressBody:
    """Multipart request body that reports (payload_bytes_sent, file_size)
    back as http.client streams the iterator chunk by chunk. Only the file's
    payload bytes count, so progress tracks exactly the file, not the
    multipart overhead; progress_offset is the file offset the body starts at."""

    def __init__(
        self,
        parts: list[tuple[bytes, bool]],
        payload_bytes: int,
        file_size: int,
        progress,
        offset: int,
    ) -> None:
        self._parts = parts
        self._payload_total = file_size
        self._offset = offset
        self._payload_bytes = payload_bytes
        self._progress = progress

    def __iter__(self):
        sent = 0
        for part, is_payload in self._parts:
            yield part
            if is_payload:
                sent += len(part)
                self._progress(self._offset + sent, self._payload_total)


def _post_multipart(
    base_url: str,
    path: str,
    fields: list[tuple[str, str]],
    filename: str,
    payload_slices: list[bytes],
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    progress=None,
    progress_offset: int = 0,
    payload_total: int | None = None,
) -> dict:
    boundary = f"----clamtotal-client-{uuid.uuid4().hex}"
    parts: list[tuple[bytes, bool]] = [(f"--{boundary}\r\n".encode(), False)]
    for name, value in fields:
        parts.append((_form_field(boundary, name, value), False))
    parts.append(
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
            False,
        )
    )
    parts.extend((chunk, True) for chunk in payload_slices)
    parts.append((f"\r\n--{boundary}--\r\n".encode(), False))
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    body: bytes | Iterable[bytes]
    if progress is None:
        body = b"".join(part for part, _ in parts)
    else:
        payload_bytes = sum(len(c) for c in payload_slices)
        body = _ProgressBody(
            parts,
            payload_bytes,
            payload_total if payload_total is not None else payload_bytes,
            progress,
            progress_offset,
        )
        # urllib/http.client would fall back to chunked encoding for an iterator
        # body; the server accepts that, but an explicit Content-Length is safer
        headers["Content-Length"] = str(sum(len(part) for part, _ in parts))
    return _request(base_url, path, token=token, timeout=timeout, data=body, headers=headers)


def _upload_fields(rescan: bool, ephemeral: bool, engines: str) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    for name, value in (("rescan", rescan), ("ephemeral", ephemeral)):
        if value:
            fields.append((name, "true"))
    if engines:
        fields.append(("engines", engines))
    return fields


def post_file(
    base_url: str,
    path: str,
    filename: str,
    content: bytes,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    rescan: bool = False,
    ephemeral: bool = False,
    engines: str = "",
    progress=None,
) -> dict:
    """Direct whole-file upload: POST <path> with one multipart body."""
    payload_slices = [
        content[i : i + PROGRESS_CHUNK] for i in range(0, max(len(content), 1), PROGRESS_CHUNK)
    ]
    return _post_multipart(
        base_url,
        path,
        _upload_fields(rescan, ephemeral, engines),
        filename,
        payload_slices,
        token=token,
        timeout=timeout,
        progress=progress,
    )


def post_file_chunked(
    base_url: str,
    fh,
    filename: str,
    size: int,
    sha256: str,
    chunk_size: int,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    rescan: bool = False,
    ephemeral: bool = False,
    engines: str = "",
    progress=None,
) -> dict:
    """HTTP chunked upload: one POST /file/upload/chunk per slice, in order.
    The last chunk's response is the normal upload response (sha256/status/cached)."""
    total = max(1, (size + chunk_size - 1) // chunk_size)
    result = {}
    for index in range(total):
        offset = index * chunk_size
        fh.seek(offset)
        chunk = fh.read(min(chunk_size, size - offset))
        payload_slices = [
            chunk[i : i + PROGRESS_CHUNK] for i in range(0, max(len(chunk), 1), PROGRESS_CHUNK)
        ]
        result = _post_multipart(
            base_url,
            "/file/upload/chunk",
            _upload_fields(rescan, ephemeral, engines)
            + [
                ("sha256", sha256),
                ("index", str(index)),
                ("total", str(total)),
                ("name", filename),
            ],
            filename,
            payload_slices,
            token=token,
            timeout=timeout,
            progress=progress,
            progress_offset=offset,
            payload_total=size,
        )
    return result


def _mask_data(data: bytes, mask: bytes) -> bytes:
    """RFC 6455 client-side masking, vectorized with big-int XOR (pure stdlib)."""
    n = len(data)
    if n == 0:
        return b""
    pad = -n % 4
    key = int.from_bytes((mask * ((n + 3) // 4))[: n + pad], "big")
    xored = int.from_bytes(data + b"\x00" * pad, "big") ^ key
    return xored.to_bytes(n + pad, "big")[:n]


class _WsFrame:
    def __init__(self, opcode: int, payload: bytes) -> None:
        self.opcode = opcode
        self.payload = payload


class _WsTransport(Protocol):
    """The socket surface the WebSocket client needs (in tests: FakeSock)."""

    def recv(self, size: int, /) -> bytes: ...  # pragma: no cover - protocol stub

    def sendall(self, data: bytes, /) -> None: ...  # pragma: no cover

    def close(self) -> None: ...  # pragma: no cover


class _WsConnection:
    """Minimal RFC 6455 client: masked outgoing frames, text/binary/close incoming.
    No fragmentation support (this protocol only uses small control frames and
    payload frames sent whole)."""

    def __init__(self, sock: _WsTransport) -> None:
        self._sock = sock
        self._buf = b""

    def _read_http_head(self) -> str:
        while b"\r\n\r\n" not in self._buf:
            data = self._sock.recv(4096)
            if not data:
                raise ClientError(0, "websocket handshake: connection closed")
            self._buf += data
        head, _, self._buf = self._buf.partition(b"\r\n\r\n")
        return head.decode("latin-1")

    def recv_frame(self) -> _WsFrame:
        header = self._recv_exact(2)
        opcode = header[0] & 0x0F
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        payload = self._recv_exact(length)
        if opcode == 8:  # close
            raise ClientError(0, "websocket closed by server")
        return _WsFrame(opcode, payload)

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            data = self._sock.recv(65536)
            if not data:
                raise ClientError(0, "websocket closed mid-frame")
            self._buf += data
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        frame = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            frame.append(0x80 | n)
        elif n <= 0xFFFF:
            frame.append(0x80 | 126)
            frame += struct.pack(">H", n)
        else:
            frame.append(0x80 | 127)
            frame += struct.pack(">Q", n)
        frame += mask
        frame += _mask_data(payload, mask)
        self._sock.sendall(bytes(frame))

    def close(self) -> None:
        try:
            self.send_frame(8, b"")  # close frame
        except (ClientError, OSError):
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _ws_connect(base_url: str, path: str, *, token: str | None, timeout: float) -> _WsConnection:
    url = urllib.parse.urlsplit(base_url.rstrip("/") or base_url)
    secure = url.scheme == "https"
    host = url.hostname
    if not host:
        raise ClientError(0, f"invalid base URL {base_url!r}")
    port = url.port or (443 if secure else 80)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if secure:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        conn = _WsConnection(sock)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {url.netloc}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n" + (f"X-Api-Key: {token}\r\n" if token else "") + "\r\n"
        )
        sock.sendall(request.encode())
        status = conn._read_http_head()
        if " 101 " not in status:
            raise ClientError(0, f"websocket handshake failed: {status.splitlines()[0]}")
        return conn
    except OSError as exc:
        raise ClientError(0, f"cannot reach websocket {host}:{port}: {exc}") from exc


def upload_ws(
    base_url: str,
    fh,
    filename: str,
    size: int,
    sha256: str,
    chunk_size: int,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    rescan: bool = False,
    ephemeral: bool = False,
    engines: str = "",
    progress=None,
) -> dict:
    """WebSocket upload: 'start', then one 'chunk' header + one binary frame per
    slice, waiting for the server's ack. Resumes chunks the server already has."""
    if chunk_size <= 0:
        chunk_size = PROGRESS_CHUNK
    total = max(1, (size + chunk_size - 1) // chunk_size)
    conn = _ws_connect(base_url, "/file/upload/ws", token=token, timeout=timeout)
    try:
        conn.send_frame(
            1,
            json.dumps(
                {
                    "type": "start",
                    "sha256": sha256,
                    "total": total,
                    "name": filename,
                    "rescan": rescan,
                    "ephemeral": ephemeral,
                    "engines": engines,
                }
            ).encode(),
        )
        received: set[int] = set()
        while True:
            frame = conn.recv_frame()
            if frame.opcode != 1:
                raise ClientError(0, f"unexpected websocket frame type {frame.opcode}")
            ctrl = json.loads(frame.payload)
            kind = ctrl.get("type")
            if kind == "ready":
                received = {int(i) for i in ctrl.get("received", [])}
                received.discard(total - 1)  # resend the last chunk: it triggers assembly
                break
            if kind == "error":
                raise ClientError(0, str(ctrl.get("detail", "websocket upload failed")))
            raise ClientError(0, f"unexpected websocket control message {kind!r}")
        for index in range(total):
            if index in received:
                continue
            offset = index * chunk_size
            fh.seek(offset)
            chunk = fh.read(min(chunk_size, size - offset))
            conn.send_frame(
                1, json.dumps({"type": "chunk", "index": index, "size": len(chunk)}).encode()
            )
            conn.send_frame(2, chunk)
            ack = json.loads(conn.recv_frame().payload)
            if ack.get("type") == "error":
                raise ClientError(0, str(ack.get("detail", "websocket upload failed")))
            if ack.get("type") != "ack" or int(ack.get("index", -1)) != index:
                raise ClientError(0, f"unexpected websocket ack for chunk {index}")
            if progress:
                progress(min(offset + len(chunk), size), size)
        done = json.loads(conn.recv_frame().payload)
        if done.get("type") == "error":
            raise ClientError(0, str(done.get("detail", "websocket upload failed")))
        if done.get("type") != "done":
            raise ClientError(0, f"unexpected websocket control message {done.get('type')!r}")
        cached = bool(done.get("cached"))
        return {
            "sha256": done.get("sha256", sha256),
            "status": "done" if cached else "pending",
            "cached": cached,
        }
    finally:
        conn.close()


def post_url(
    base_url: str,
    url: str,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    body = urllib.parse.urlencode({"url": url}).encode()
    return _request(
        base_url,
        "/api/v2/urls",
        token=token,
        timeout=timeout,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def get_report(
    base_url: str,
    hash_value: str,
    *,
    token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    return _request(base_url, f"/api/v2/files/{hash_value}", token=token, timeout=timeout)
