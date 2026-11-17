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
) -> dict:
    boundary = f"----clamtotal-client-{uuid.uuid4().hex}"
    parts = []
    for name, value in (("rescan", rescan), ("ephemeral", ephemeral)):
        if value:
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n'
                "\r\ntrue\r\n".encode()
            )
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
    )
    parts.append(content)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return _request(
        base_url,
        path,
        token=token,
        timeout=timeout,
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )


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
