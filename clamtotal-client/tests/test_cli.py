import email.message
import io
import json
import urllib.error

import pytest

from clamtotal_client import api, cli


class FakeResponse(io.BytesIO):
    pass


@pytest.fixture
def requests(monkeypatch):
    seen = []
    polls = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        body = req.data or b""
        if "/api/v2/files/" in req.full_url and "e" * 64 in req.full_url:
            polls.append(1)
            resp = (
                {"sha256": "e" * 64, "status": "pending"}
                if len(polls) < 2
                else {
                    "sha256": "e" * 64,
                    "status": "done",
                    "verdict": "infected",
                    "signature": "Eicar-Test-Signature",
                }
            )
            return FakeResponse(json.dumps(resp).encode())
        if req.full_url.endswith("/api/v2/files"):
            if b"eicar" in body:
                resp = {"sha256": "e" * 64, "md5": "m", "sha1": "s", "status": "pending"}
            else:
                resp = {"sha256": "a" * 64, "md5": "m", "sha1": "s", "status": "done"}
        elif "/api/v2/files/" in req.full_url:
            if "missing" in req.full_url:
                raise urllib.error.HTTPError(
                    req.full_url,
                    404,
                    "Not Found",
                    email.message.Message(),
                    FakeResponse(b'{"detail": "not found"}'),
                )
            resp = {
                "sha256": "a" * 64,
                "md5": "m",
                "sha1": "s",
                "sha512": "5",
                "crc32": "c",
                "file_name": "a.txt",
                "size": 3,
                "file_type": "text",
                "verdict": "infected",
                "status": "done",
                "signature": "Eicar-Test-Signature",
                "engines": ["clamav", "yara"],
                "urls": ["hxxp://evil[.]com"],
            }
        elif req.full_url.endswith("/api/v2/urls"):
            resp = {
                "id": "dXJs",
                "url": "http://evil.com",
                "verdict": "malicious",
                "categories": ["malware"],
            }
        else:
            raise AssertionError(f"unexpected url {req.full_url}")
        return FakeResponse(json.dumps(resp).encode())

    monkeypatch.setattr(api.urllib.request, "urlopen", fake_urlopen)
    return seen


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("CLAMTOTAL_URL", "CLAMTOTAL_TIMEOUT", "CLAMTOTAL_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def run(argv, monkeypatch, requests):
    return cli.main(argv)


def test_env_fallback_and_defaults(monkeypatch, requests):
    monkeypatch.setenv("CLAMTOTAL_URL", "http://env-server")
    monkeypatch.setenv("CLAMTOTAL_TIMEOUT", "5")
    monkeypatch.setenv("CLAMTOTAL_API_KEY", "secret")
    monkeypatch.setattr("sys.argv", ["clamtotal-client", "url", "http://evil.com"])
    assert run(None, monkeypatch, requests) == 2
    req = requests[0]
    assert req.full_url == "http://env-server/api/v2/urls"
    assert req.headers["X-api-key"] == "secret"


def test_args_override_env(monkeypatch, requests):
    monkeypatch.setenv("CLAMTOTAL_URL", "http://env-server")
    assert run(["--url", "http://arg-server", "url", "x.com"], monkeypatch, requests) == 2
    assert requests[0].full_url == "http://arg-server/api/v2/urls"


def test_scan_json_output(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("hi")
    assert run(["scan", "--json", str(f)], monkeypatch, requests) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["sha256"] == "a" * 64
    body = requests[0].data
    assert b'filename="clean.txt"' in body and b"hi" in body
    assert requests[0].headers["Content-type"].startswith("multipart/form-data; boundary=")


def test_scan_rescan_ephemeral_flags_in_body(monkeypatch, requests, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", "--rescan", "--ephemeral", str(f)], monkeypatch, requests)
    body = requests[0].data
    assert b'name="rescan"' in body and b'name="ephemeral"' in body
    assert b'name="engines"' not in body  # no selection -> all engines (default)


def test_scan_engines_selection_in_body(monkeypatch, requests, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", "--engines", "clamav,yara", str(f)], monkeypatch, requests)
    body = requests[0].data
    assert b'name="engines"' in body
    assert b"clamav,yara" in body


def test_scan_human_output_and_wait(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 0)
    code = run(["scan", "--wait", "5", str(f)], monkeypatch, requests)
    out = capsys.readouterr().out
    assert code == 2
    assert "sha256: " + "e" * 64 in out
    assert "verdict: infected  signature: Eicar-Test-Signature" in out
    assert len(requests) == 3  # POST + two polls


def test_scan_wait_cached_does_not_poll(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", "--wait", "5", str(f)], monkeypatch, requests)
    assert len(requests) == 1
    assert "status: cached" in capsys.readouterr().out


def test_scan_unreadable_file(monkeypatch, requests, capsys):
    assert run(["scan", "/no/such/file"], monkeypatch, requests) == 1
    assert "cannot read" in capsys.readouterr().err


def test_scan_server_error(monkeypatch, requests, capsys, tmp_path):
    def fail(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url,
            503,
            "Unavailable",
            email.message.Message(),
            FakeResponse(b'{"detail": "no engine"}'),
        )

    monkeypatch.setattr(api.urllib.request, "urlopen", fail)
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)], monkeypatch, requests) == 1
    assert "HTTP 503" in capsys.readouterr().err


def test_describe_human(monkeypatch, requests, capsys):
    assert run(["describe", "a" * 64], monkeypatch, requests) == 2
    out = capsys.readouterr().out
    assert "verdict:   infected" in out
    assert f"{'sha256:':<10} {'a' * 64}" in out
    assert "hxxp://evil[.]com" in out


def test_describe_json(monkeypatch, requests, capsys):
    assert run(["describe", "--json", "a" * 64], monkeypatch, requests) == 2
    assert json.loads(capsys.readouterr().out)["signature"] == "Eicar-Test-Signature"


def test_describe_not_found(monkeypatch, requests, capsys):
    assert run(["describe", "missing"], monkeypatch, requests) == 1
    assert "HTTP 404: not found" in capsys.readouterr().err


def test_url_human(monkeypatch, requests, capsys):
    assert run(["url", "evil.com"], monkeypatch, requests) == 2
    out = capsys.readouterr().out
    assert "verdict: malicious" in out and "category: malware" in out


def test_url_json(monkeypatch, requests, capsys):
    assert run(["url", "--json", "evil.com"], monkeypatch, requests) == 2
    assert json.loads(capsys.readouterr().out)["id"] == "dXJs"


def test_connection_error(monkeypatch, requests, capsys):
    import urllib.request

    def fail(req, timeout=None):
        raise urllib.error.URLError("conn refused")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    assert run(["url", "x.com"], monkeypatch, requests) == 1
    assert "cannot reach" in capsys.readouterr().err


def test_http_error_with_non_json_body(monkeypatch, requests):
    def fail(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 500, "Boom", email.message.Message(), FakeResponse(b"oops")
        )

    monkeypatch.setattr(api.urllib.request, "urlopen", fail)
    with pytest.raises(api.ClientError) as exc:
        api.get_report("http://s", "h")
    assert exc.value.status == 500
    assert exc.value.detail == "Boom"


def test_scan_wait_json(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 0)
    assert run(["scan", "--wait", "5", "--json", str(f)], monkeypatch, requests) == 2
    out = capsys.readouterr().out
    assert '"verdict": "infected"' in out


def test_empty_response_body(monkeypatch, requests):
    def empty(req, timeout=None):
        return FakeResponse(b"")

    monkeypatch.setattr(api.urllib.request, "urlopen", empty)
    assert api.get_report("http://s", "h") == {}
