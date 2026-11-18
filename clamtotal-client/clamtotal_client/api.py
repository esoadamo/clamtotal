"""Minimal stdlib-only HTTP client for the ClamTotal VT-style JSON API."""

import json
import urllib.error
import urllib.parse
import urllib.request
import uuid

DEFAULT_URL = "https://clamtotal.com"
DEFAULT_TIMEOUT = 60.0


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
    data: bytes | None = None,
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


PROGRESS_CHUNK = 1024 * 1024


class _ProgressBody:
    """Multipart request body that reports (bytes_sent, total) back as http.client
    streams the iterator chunk by chunk. total counts the multipart overhead too,
    so progress reaches 100% exactly when the last byte leaves the client."""

    def __init__(self, parts: list[bytes], progress) -> None:
        self._parts = parts
        self.total = sum(len(p) for p in parts)
        self._progress = progress

    def __iter__(self):
        sent = 0
        for part in self._parts:
            yield part
            sent += len(part)
            self._progress(sent, self.total)


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
    boundary = f"----clamtotal-client-{uuid.uuid4().hex}"
    parts = []
    for name, value in (("rescan", rescan), ("ephemeral", ephemeral)):
        if value:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n'
                "\r\ntrue\r\n".encode()
            )
    if engines:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="engines"\r\n'
            f"\r\n{engines}\r\n".encode()
        )
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
    )
    # the file itself goes out in 1 MB slices so the progress callback fires often
    parts.extend(
        content[i : i + PROGRESS_CHUNK] for i in range(0, max(len(content), 1), PROGRESS_CHUNK)
    )
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if progress is None:
        return _request(
            base_url, path, token=token, timeout=timeout, data=b"".join(parts), headers=headers
        )
    body = _ProgressBody(parts, progress)
    # urllib/http.client would fall back to chunked encoding for an iterator body;
    # the server accepts that, but an explicit Content-Length is more compatible
    headers["Content-Length"] = str(body.total)
    return _request(base_url, path, token=token, timeout=timeout, data=body, headers=headers)


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
