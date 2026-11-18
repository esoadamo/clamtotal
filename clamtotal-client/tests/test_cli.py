import email.message
import io
import json
import struct
import urllib.error

import pytest

from clamtotal_client import api, cli


class FakeResponse(io.BytesIO):
    pass


CAPS = {
    "max_upload_size": 512 * 1024 * 1024,
    "chunked": False,
    "chunk_size": 0,
    "websocket": False,
    "ws_chunk_size": 0,
}


@pytest.fixture
def requests(monkeypatch):
    seen = []
    polls = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        body = req.data or b""
        if not isinstance(body, bytes):  # progress uploads stream an iterable body
            body = b"".join(body)
        if req.full_url.endswith("/api/v2/upload/capabilities"):
            return FakeResponse(
                json.dumps(
                    {
                        "max_upload_size": 512 * 1024 * 1024,
                        "chunk_size": 0,
                        "ws_chunk_size": 0,
                        "chunked": False,
                        "websocket": False,
                    }
                ).encode()
            )
        if "/api/v2/files/" in req.full_url:
            hash_value = req.full_url.rsplit("/", 1)[-1]
            if hash_value == "e" * 64:
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
            if hash_value == "a" * 64:
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
                    "urls": ["http://evil.com/payload.exe", "https://cdn.example.net/x"],
                }
                return FakeResponse(json.dumps(resp).encode())
            raise urllib.error.HTTPError(  # unknown hash: sample not on the server
                req.full_url,
                404,
                "Not Found",
                email.message.Message(),
                FakeResponse(b'{"detail": "not found"}'),
            )
        if req.full_url.endswith("/api/v2/files"):
            if b"eicar" in body:
                resp = {"sha256": "e" * 64, "md5": "m", "sha1": "s", "status": "pending"}
            else:
                resp = {"sha256": "a" * 64, "md5": "m", "sha1": "s", "status": "done"}
        elif "/file/upload/chunk" in req.full_url:
            resp = {"sha256": "a" * 64, "status": "done", "cached": True}
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
    for var in ("CLAMTOTAL_URL", "CLAMTOTAL_TIMEOUT", "CLAMTOTAL_API_KEY", "CLAMTOTAL_ENGINES"):
        monkeypatch.delenv(var, raising=False)


def req_body(req):
    data = req.data if req.data is not None else b""
    return b"".join(data) if not isinstance(data, bytes) else data


def upload_reqs(requests):
    """Only the upload POSTs (the scan REQUEST + HTTP chunks), not the caps probe."""
    return [r for r in requests if r.full_url.endswith(("/api/v2/files", "/file/upload/chunk"))]


def run(argv):
    return cli.main(argv)


def test_env_fallback_and_defaults(monkeypatch, requests):
    monkeypatch.setenv("CLAMTOTAL_URL", "http://env-server")
    monkeypatch.setenv("CLAMTOTAL_TIMEOUT", "5")
    monkeypatch.setenv("CLAMTOTAL_API_KEY", "secret")
    assert run(["url", "http://evil.com"]) == 2
    req = requests[0]
    assert req.full_url == "http://env-server/api/v2/urls"
    assert req.headers["X-api-key"] == "secret"


def test_args_override_env(monkeypatch, requests):
    monkeypatch.setenv("CLAMTOTAL_URL", "http://env-server")
    assert run(["--url", "http://arg-server", "url", "x.com"]) == 2
    assert requests[0].full_url == "http://arg-server/api/v2/urls"


def test_scan_json_output(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("hi")
    assert run(["scan", "--json", str(f)]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["sha256"] == "a" * 64
    assert out["verdict"] == "infected"
    body = req_body(upload_reqs(requests)[0])
    assert b'filename="clean.txt"' in body and b"hi" in body
    assert (
        upload_reqs(requests)[0]
        .headers["Content-type"]
        .startswith("multipart/form-data; boundary=")
    )


def test_scan_capabilities_probed_with_token(monkeypatch, requests, tmp_path):
    monkeypatch.setenv("CLAMTOTAL_API_KEY", "secret")
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", "--no-wait-result", str(f)]) == 0
    caps_req = requests[0]  # the pre-check GET may come before the probe
    if not caps_req.full_url.endswith("/api/v2/upload/capabilities"):
        caps_req = requests[1]
    assert caps_req.full_url == "https://clamtotal.com/api/v2/upload/capabilities"
    assert caps_req.headers["X-api-key"] == "secret"
    assert upload_reqs(requests)[0].full_url == "https://clamtotal.com/api/v2/files"


def test_scan_caps_404_falls_back_to_direct(monkeypatch, capsys, tmp_path):
    def fake_urlopen(req, timeout=None):
        if req.full_url.endswith("/api/v2/upload/capabilities"):
            raise urllib.error.HTTPError(
                req.full_url,
                404,
                "Not Found",
                email.message.Message(),
                FakeResponse(b'{"detail": "x"}'),
            )
        body = req.data or b""
        if not isinstance(body, bytes):
            body = b"".join(body)
        if req.full_url.endswith("/api/v2/files"):
            assert b'name="sha256"' not in body  # plain whole-file POST, not chunked
            return FakeResponse(json.dumps({"sha256": "a" * 64, "status": "pending"}).encode())
        if req.full_url.rsplit("/", 1)[-1] != "a" * 64:
            raise urllib.error.HTTPError(
                req.full_url,
                404,
                "Not Found",
                email.message.Message(),
                FakeResponse(b'{"detail": "not found"}'),
            )
        return FakeResponse(
            json.dumps(
                {"sha256": "a" * 64, "status": "done", "verdict": "clean", "engines": []}
            ).encode()
        )

    monkeypatch.setattr(api.urllib.request, "urlopen", fake_urlopen)
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 0


def test_scan_rescan_ephemeral_flags_in_body(monkeypatch, requests, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", "--rescan", "--ephemeral", str(f)])
    body = req_body(upload_reqs(requests)[0])
    assert b'name="rescan"' in body and b'name="ephemeral"' in body
    assert b'name="engines"' not in body  # no selection -> all engines (default)


def test_scan_engines_selection_in_body(monkeypatch, requests, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", "--engines", "clamav,yara", str(f)])
    body = req_body(upload_reqs(requests)[0])
    assert b'name="engines"' in body
    assert b"clamav,yara" in body


def test_scan_engines_env_fallback(monkeypatch, requests, tmp_path):
    monkeypatch.setenv("CLAMTOTAL_ENGINES", "yara")
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", str(f)])  # no flag: env var applies
    body = req_body(upload_reqs(requests)[0])
    assert b'name="engines"' in body and b"yara" in body
    run(["scan", "--engines", "domain-feed", str(f)])
    body = req_body(upload_reqs(requests)[1])  # explicit flag overrides the env var
    assert b"domain-feed" in body
    monkeypatch.delenv("CLAMTOTAL_ENGINES")
    run(["scan", str(f)])
    assert b'name="engines"' not in req_body(upload_reqs(requests)[2])  # unset -> all


def test_scan_human_output_and_wait(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 0)
    code = run(["scan", "--wait", "5", str(f)])
    out = capsys.readouterr().out
    assert code == 2
    assert "verdict: infected  signature: Eicar-Test-Signature" in out
    assert len(upload_reqs(requests)) == 1
    assert len(requests) == 5  # caps + pre-check + POST + two polls


def test_scan_waits_by_default_without_flag(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert run(["scan", str(f)]) == 2
    assert "verdict: infected" in capsys.readouterr().out


def test_scan_wait_timeout_still_pending(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 0)
    code = run(["scan", "--wait", "0", "--json", str(f)])
    captured = capsys.readouterr()
    assert code == 1  # pending: clean is unproven, so not 0
    assert json.loads(captured.out)["status"] == "pending"
    assert "still pending" in captured.err


def test_scan_no_wait_result_json(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    assert run(["scan", "--no-wait-result", "--json", str(f)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["sha256"] == "e" * 64 and out["status"] == "pending"


def test_report_exit_code_rules():
    def engine(name, status, verdict=""):
        return {"name": name, "status": status, "verdict": verdict, "signature": None}

    clean = engine("ClamAV", "done", "clean")
    clean2 = engine("YARA", "done", "clean")
    assert cli._report_exit_code(
        {"status": "done", "verdict": "clean", "engines": [clean, clean2]}
    ) == (0, [])
    assert cli._report_exit_code(
        {
            "status": "done",
            "verdict": "clean",
            "engines": [clean, engine("YARA", "done", "infected")],
        }
    ) == (2, [])
    assert cli._report_exit_code(
        {"status": "done", "verdict": "infected", "engines": [clean, clean2]}
    ) == (2, [])
    assert cli._report_exit_code(
        {"status": "done", "verdict": "clean", "engines": [clean, engine("YARA", "timed out")]}
    ) == (1, ["YARA"])
    assert cli._report_exit_code(
        {"status": "done", "verdict": "clean", "engines": [clean, engine("YARA", "scanning")]}
    ) == (1, ["YARA"])
    assert cli._report_exit_code(
        {"status": "done", "verdict": "clean", "engines": ["clamav", "yara"]}
    ) == (0, [])  # legacy servers: fall back to the overall verdict
    assert cli._report_exit_code({"status": "done", "verdict": "clean"}) == (0, [])
    assert cli._report_exit_code({"status": "pending", "verdict": "pending"}) == (1, [])


def _engine_report(monkeypatch, engines, verdict="clean", status="done"):
    def fake_urlopen(req, timeout=None):
        if not req.full_url.endswith("/api/v2/files") and "/api/v2/files/" not in req.full_url:
            return FakeResponse(
                json.dumps(
                    {
                        "max_upload_size": 100,
                        "chunked": False,
                        "chunk_size": 0,
                        "websocket": False,
                        "ws_chunk_size": 0,
                    }
                ).encode()
            )
        if not req.full_url.endswith("/api/v2/files"):
            return FakeResponse(
                json.dumps(
                    {"sha256": "a" * 64, "status": status, "verdict": verdict, "engines": engines}
                ).encode()
            )
        body = req.data if isinstance(req.data, bytes) else b"".join(req.data or [])
        del body
        return FakeResponse(json.dumps({"sha256": "a" * 64, "status": "pending"}).encode())

    monkeypatch.setattr(api.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)


def test_scan_exits_1_when_engine_timed_out(monkeypatch, capsys, tmp_path):
    _engine_report(
        monkeypatch,
        [
            {"name": "ClamAV", "status": "done", "verdict": "clean", "signature": None},
            {"name": "YARA", "status": "timed out"},
        ],
    )
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 1
    captured = capsys.readouterr()
    assert "verdict: clean" in captured.out
    assert "no clean verdict from: YARA" in captured.err


def test_scan_exits_2_when_any_engine_detects(monkeypatch, capsys, tmp_path):
    _engine_report(
        monkeypatch,
        [
            {"name": "ClamAV", "status": "done", "verdict": "clean", "signature": None},
            {"name": "YARA", "status": "done", "verdict": "infected", "signature": "Rule"},
        ],
    )
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 2
    out = capsys.readouterr().out
    assert "verdict:" in out


def test_scan_exits_0_when_all_engines_clean(monkeypatch, capsys, tmp_path):
    _engine_report(
        monkeypatch,
        [
            {"name": "ClamAV", "status": "done", "verdict": "clean", "signature": None},
            {"name": "YARA", "status": "done", "verdict": "clean", "signature": None},
        ],
    )
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 0
    assert "no clean verdict" not in capsys.readouterr().err


def test_scan_no_wait_result(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text("eicar")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    code = run(["scan", "--no-wait-result", str(f)])
    assert code == 0
    out = capsys.readouterr().out
    assert f"sha256: {'e' * 64}" in out and "status: pending" in out
    assert len(upload_reqs(requests)) == 1  # only the upload, no report poll


def test_scan_wait_cached_does_not_poll(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    run(["scan", "--wait", "5", str(f)])
    assert len(upload_reqs(requests)) == 1
    assert len(requests) == 4  # caps + pre-check + upload + one report fetch (done)
    assert "verdict: infected" in capsys.readouterr().out


def test_scan_upload_response_without_sha256(monkeypatch, requests, capsys, tmp_path):
    monkeypatch.setattr(api, "post_file", lambda *a, **k: {"status": "pending"})
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 1
    out = capsys.readouterr().out
    assert "status: pending" in out  # nothing waitable: show status, flag failure


def test_scan_unreadable_file(monkeypatch, requests, capsys):
    assert run(["scan", "/no/such/file"]) == 1
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
    assert run(["scan", str(f)]) == 1
    assert "HTTP 503" in capsys.readouterr().err


def test_scan_upload_oserror(monkeypatch, requests, capsys, tmp_path):
    def boom(*a, **k):
        raise OSError("disk on fire")

    monkeypatch.setattr(api, "post_file", boom)
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 1  # progress line is open: it must be closed
    err = capsys.readouterr().err
    assert "cannot read" in err and err.count("\n") == 2  # the progress line + error


def test_scan_skips_upload_when_report_known(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "known.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: "a" * 64)
    assert run(["scan", str(f)]) == 2
    captured = capsys.readouterr()
    assert "not re-uploading" in captured.err
    assert "verdict: infected" in captured.out
    assert upload_reqs(requests) == []  # the server already had the sample
    assert len(requests) == 2  # pre-check + the wait's report fetch, nothing sent


def test_scan_rescan_uploads_even_when_report_known(monkeypatch, requests, tmp_path):
    f = tmp_path / "known.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: "a" * 64)
    run(["scan", "--rescan", str(f)])
    assert len(upload_reqs(requests)) == 1
    assert b'name="rescan"' in req_body(upload_reqs(requests)[0])


def test_scan_skips_upload_when_scan_already_pending(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "pending.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: "e" * 64)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert run(["scan", str(f)]) == 2  # waits for the running scan, no upload
    assert upload_reqs(requests) == []
    # the pre-check consumed the first poll, the wait loop the second (done)
    assert len([r for r in requests if "/api/v2/files/" in r.full_url]) == 2


def test_describe_hash_flag(monkeypatch, requests, capsys):
    assert run(["describe", "--hash", "a" * 64]) == 2
    out = capsys.readouterr().out
    assert "verdict:   infected" in out
    assert requests[0].full_url.endswith("/api/v2/files/" + "a" * 64)


def test_describe_rescan_hash_without_file(monkeypatch, requests, capsys):
    assert run(["describe", "--rescan", "--hash", "a" * 64]) == 1
    assert "pass the sample file" in capsys.readouterr().err


def test_describe_no_target(monkeypatch, requests, capsys):
    assert run(["describe"]) == 1
    assert "needs a local file or --hash" in capsys.readouterr().err


def test_describe_file_known_skips_upload(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "known.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: "a" * 64)
    assert run(["describe", str(f)]) == 2
    out = capsys.readouterr().out
    assert "verdict:   infected" in out
    assert upload_reqs(requests) == []  # hash lookup only, no bytes sent


def test_describe_file_unknown_uploads_and_waits(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "fresh.txt"
    f.write_text("brand new sample")  # unknown hash -> the client must analyze it
    assert run(["describe", str(f)]) == 2
    assert len(upload_reqs(requests)) == 1
    out = capsys.readouterr().out
    assert "verdict:   infected" in out
    assert b'name="rescan"' not in req_body(upload_reqs(requests)[0])


def test_describe_file_rescan_rereads_and_uploads(monkeypatch, requests, tmp_path):
    f = tmp_path / "known.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: "a" * 64)
    assert run(["describe", "--rescan", str(f)]) == 2
    uploads = upload_reqs(requests)
    assert len(uploads) == 1
    assert b'name="rescan"' in req_body(uploads[0])


def test_describe_unfinished_engine_gets_note(monkeypatch, capsys):
    monkeypatch.setattr(
        api,
        "get_report",
        lambda *a, **k: {
            "sha256": "a" * 64,
            "status": "done",
            "verdict": "clean",
            "engines": [
                {"name": "ClamAV", "status": "done", "verdict": "clean"},
                {"name": "YARA", "status": "timed out"},
            ],
        },
    )
    assert run(["describe", "--hash", "a" * 64]) == 1
    assert "no clean verdict from: YARA" in capsys.readouterr().err


def test_describe_isfile_oserror_is_hash(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "weird.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli.os.path, "isfile", lambda p: (_ for _ in ()).throw(OSError("stat")))
    assert run(["describe", str(f)]) == 1  # not a usable file: hash lookup 404s
    assert upload_reqs(requests) == []


def test_describe_file_sha_oserror(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: (_ for _ in ()).throw(OSError("gone")))
    assert run(["describe", str(f)]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_scan_sha_oserror(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    monkeypatch.setattr(cli, "_sha256_file", lambda p: (_ for _ in ()).throw(OSError("gone")))
    assert run(["scan", str(f)]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_describe_upload_error_paths(monkeypatch, capsys, tmp_path):
    f = tmp_path / "new.txt"
    f.write_text("samples")
    monkeypatch.setattr(
        api,
        "get_capabilities",
        lambda *a, **k: (_ for _ in ()).throw(api.ClientError(404, "old server")),
    )
    monkeypatch.setattr(
        api, "get_report", lambda *a, **k: (_ for _ in ()).throw(api.ClientError(404, "not found"))
    )
    monkeypatch.setattr(cli.os.path, "getsize", lambda p: (_ for _ in ()).throw(OSError("io")))
    assert run(["describe", str(f)]) == 1
    assert "cannot read" in capsys.readouterr().err
    monkeypatch.setattr(cli.os.path, "getsize", lambda p: 7)
    monkeypatch.setattr(
        cli, "_upload", lambda *a, **k: (_ for _ in ()).throw(api.ClientError(0, "ws down"))
    )
    assert run(["describe", str(f)]) == 1
    assert "ws down" in capsys.readouterr().err
    monkeypatch.setattr(cli, "_upload", lambda *a, **k: {"sha256": "a" * 64})
    monkeypatch.setattr(
        api,
        "get_report",
        lambda *a, **k: {"sha256": "a" * 64, "status": "done", "verdict": "clean", "engines": []},
    )
    assert run(["describe", str(f)]) == 0  # caps 404 -> {}: direct upload fallback


def test_describe_pending_gets_note_and_exit_1(monkeypatch, capsys):
    monkeypatch.setattr(
        api,
        "get_report",
        lambda *a, **k: {
            "sha256": "e" * 64,
            "status": "pending",
            "verdict": "pending",
            "engines": [{"name": "ClamAV", "status": "scanning"}],
        },
    )
    assert run(["describe", "--hash", "e" * 64]) == 1
    captured = capsys.readouterr()
    assert "scan still pending" in captured.err
    assert "engines:   ClamAV" in captured.out


def test_describe_engines_dicts_show_names(monkeypatch, capsys):
    monkeypatch.setattr(
        api,
        "get_report",
        lambda *a, **k: {
            "sha256": "z" * 64,
            "md5": "m",
            "sha1": "s",
            "file_name": "z.bin",
            "size": 1,
            "file_type": "data",
            "verdict": "clean",
            "status": "done",
            "engines": [
                {"name": "ClamAV (clamd)", "status": "done", "verdict": "clean"},
                {"name": "YARA", "status": "done", "verdict": "clean"},
            ],
            "urls": [],
        },
    )
    assert run(["describe", "--hash", "z" * 64]) == 0
    out = capsys.readouterr().out
    assert "engines:   ClamAV (clamd), YARA" in out


def test_describe_human(monkeypatch, requests, capsys):
    assert run(["describe", "a" * 64]) == 2
    out = capsys.readouterr().out
    assert "verdict:   infected" in out
    assert f"{'sha256:':<10} {'a' * 64}" in out
    assert "hxxp://evil[.]com" in out


def test_describe_json(monkeypatch, requests, capsys):
    assert run(["describe", "--json", "a" * 64]) == 2
    assert json.loads(capsys.readouterr().out)["signature"] == "Eicar-Test-Signature"


def test_describe_not_found(monkeypatch, requests, capsys):
    assert run(["describe", "missing"]) == 1
    assert "HTTP 404: not found" in capsys.readouterr().err


def test_url_human(monkeypatch, requests, capsys):
    assert run(["url", "evil.com"]) == 2
    out = capsys.readouterr().out
    assert "verdict: malicious" in out and "category: malware" in out
    assert "url:     hxxp://evil[.]com" in out  # defanged in human output


def test_defang():
    assert cli._defang("http://evil.com/x?a=1") == "hxxp://evil[.]com/x?a=1"
    assert cli._defang("https://a.b.io/path") == "hxxps://a[.]b[.]io/path"
    assert cli._defang("no scheme here") == "no scheme here"


def test_url_json(monkeypatch, requests, capsys):
    assert run(["url", "--json", "evil.com"]) == 2
    assert json.loads(capsys.readouterr().out)["id"] == "dXJs"


def test_connection_error(monkeypatch, requests, capsys):
    import urllib.request

    def fail(req, timeout=None):
        raise urllib.error.URLError("conn refused")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    assert run(["url", "x.com"]) == 1
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
    assert run(["scan", "--wait", "5", "--json", str(f)]) == 2
    out = capsys.readouterr().out
    assert '"verdict": "infected"' in out


def test_scan_shows_upload_progress_by_default(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "big.dat"
    f.write_bytes(b"x" * (5 * 1024 * 1024))  # spans several 1 MB progress chunks
    assert run(["scan", str(f)]) == 2  # fake report is infected
    err = capsys.readouterr().err
    assert "uploading big.dat" in err
    assert "100%" in err  # reaches the end of the body
    assert "100% (5 MB of 5 MB)" in err


def test_scan_no_progress_hides_indicator(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", "--no-progress", str(f)]) == 2
    assert capsys.readouterr().err == ""


def test_scan_progress_indented_on_client_error(monkeypatch, requests, capsys, tmp_path):
    def fail(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 500, "Boom", email.message.Message(), FakeResponse(b"oops")
        )

    monkeypatch.setattr(api.urllib.request, "urlopen", fail)
    f = tmp_path / "c.txt"
    f.write_text("hi")
    assert run(["scan", str(f)]) == 1
    err = capsys.readouterr().err
    # the transport failed before sending any body: only the newline + error show
    assert "error: HTTP 500" in err and err.startswith("\nerror")


def test_fmt_bytes_units():
    assert cli._fmt_bytes(512) == "512 B"
    assert cli._fmt_bytes(2048) == "2 KB"
    assert cli._fmt_bytes(5 * 1024 * 1024 + 300_000) == "5.3 MB"


def test_fmt_eta():
    assert cli._fmt_eta(0) == "0s"
    assert cli._fmt_eta(42.9) == "42s"
    assert cli._fmt_eta(95) == "1m 35s"


def test_progress_printer_eta(monkeypatch, capsys):
    clock = iter([0.0, 1.0, 1.5])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))
    report = cli._progress_printer("/x/big.bin", "chunked")
    report(2 * 1024 * 1024, 4 * 1024 * 1024)
    err = capsys.readouterr().err
    assert "uploading (chunked) big.bin: 50% (2 MB of 4 MB)" in err
    assert "2 MB/s" in err and "eta 1s" in err
    report(4 * 1024 * 1024, 4 * 1024 * 1024)
    err = capsys.readouterr().err
    assert "100% (4 MB of 4 MB)" in err and "eta" not in err


def test_progress_printer_direct_label(monkeypatch, capsys):
    clock = iter([0.0, 0.1])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))
    report = cli._progress_printer("/x/a.exe", "direct")
    report(10, 10)
    err = capsys.readouterr().err
    assert "uploading a.exe: 100%" in err and "/s" not in err  # too fast to measure yet


def test_choose_transport():
    caps_ws = {"chunked": True, "chunk_size": 10, "websocket": True, "ws_chunk_size": 4}
    assert cli._choose_transport(10, caps_ws) == "direct"
    assert cli._choose_transport(11, caps_ws) == "websocket"
    assert (
        cli._choose_transport(
            11, {"chunked": True, "chunk_size": 10, "websocket": False, "ws_chunk_size": 0}
        )
        == "chunked"
    )
    assert (
        cli._choose_transport(
            11, {"chunked": False, "chunk_size": 10, "websocket": True, "ws_chunk_size": 4}
        )
        == "direct"
    )  # missing chunking caps: whole-file only
    assert (
        cli._choose_transport(
            11, {"chunked": True, "chunk_size": 10, "websocket": True, "ws_chunk_size": 0}
        )
        == "chunked"
    )


def test_sha256_file(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello" * (1024 * 1024 // 5))
    import hashlib

    assert cli._sha256_file(str(f)) == hashlib.sha256(b"hello" * (1024 * 1024 // 5)).hexdigest()


def test_empty_response_body(monkeypatch, requests):
    def empty(req, timeout=None):
        return FakeResponse(b"")

    monkeypatch.setattr(api.urllib.request, "urlopen", empty)
    assert api.get_report("http://s", "h") == {}


# ---------------------------------------------------------------- transports


def test_scan_uses_chunked_when_file_exceeds_chunk_size(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"hello")  # 5 bytes, chunk size 2 -> 3 chunks
    monkeypatch.setattr(
        api,
        "get_capabilities",
        lambda *a, **k: {
            "max_upload_size": 100,
            "chunked": True,
            "chunk_size": 2,
            "websocket": False,
            "ws_chunk_size": 0,
        },
    )
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert run(["scan", str(f)]) == 2
    chunks = upload_reqs(requests)
    assert len(chunks) == 3
    bodies = [req_body(r) for r in chunks]
    for body in bodies:
        assert b'name="sha256"' in body and b'name="index"' in body
        assert b'name="total"' in body and b'name="name"' in body
    assert b"he" in bodies[0] and b"ll" in bodies[1] and b"\r\no\r\n" in bodies[2]
    err = capsys.readouterr().err
    assert "uploading (chunked) big.txt" in err and "100% (5 B of 5 B)" in err


def test_scan_ws_failure_falls_back_to_chunked(monkeypatch, requests, capsys, tmp_path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"hello")

    def ws_fail(*a, **k):
        raise api.ClientError(0, "ws down")

    monkeypatch.setattr(api, "upload_ws", ws_fail)
    monkeypatch.setattr(
        api,
        "get_capabilities",
        lambda *a, **k: {
            "max_upload_size": 100,
            "chunked": True,
            "chunk_size": 2,
            "websocket": True,
            "ws_chunk_size": 2,
        },
    )
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert run(["scan", "--no-progress", str(f)]) == 2
    assert len(upload_reqs(requests)) == 3  # retried over HTTP chunks
    out = capsys.readouterr().out
    assert "verdict: infected" in out


# ------------------------------------------------------------- websocket api


def sframe(payload: bytes, opcode: int = 1) -> bytes:
    """Server->client frame: FIN, no mask (clients must accept unmasked input)."""
    n = len(payload)
    if n < 126:
        return bytes([0x80 | opcode, n]) + payload
    if n <= 0xFFFF:
        return bytes([0x80 | opcode, 126]) + struct.pack(">H", n) + payload
    return bytes([0x80 | opcode, 127]) + struct.pack(">Q", n) + payload


HANDSHAKE = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"


class FakeSock:
    """Scripted socket: each recv() pops the next scripted chunk; sendall collects."""

    def __init__(self, recv_script):
        self.script = list(recv_script)
        self.sent = b""
        self.closed = False

    def recv(self, n):
        return self.script.pop(0) if self.script else b""

    def sendall(self, data):
        self.sent += bytes(data)

    def close(self):
        self.closed = True


def client_frames(data: bytes):
    """Decode the client's masked frames -> [(opcode, payload)]. The handshake
    HTTP request (unmasked) comes first and is skipped."""
    _, _, data = data.partition(b"\r\n\r\n")
    frames, i = [], 0
    while i < len(data):
        opcode = data[i] & 0x0F
        length = data[i + 1] & 0x7F
        i += 2
        if length == 126:
            length = struct.unpack(">H", data[i : i + 2])[0]
            i += 2
        elif length == 127:
            length = struct.unpack(">Q", data[i : i + 8])[0]
            i += 8
        mask = data[i : i + 4]
        i += 4
        frames.append((opcode, api._mask_data(data[i : i + length], mask)))
        i += length
    return frames


def test_mask_data():
    mask = b"\x01\x02\x03\x04"
    data = bytes(range(256))
    manual = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    assert api._mask_data(data, mask) == manual
    assert api._mask_data(b"", mask) == b""
    assert api._mask_data(mask, mask) == b"\x00\x00\x00\x00"


def _ws_script(recv_frames):
    sock = FakeSock([HANDSHAKE] + [sframe(f) for f in recv_frames])
    return sock


def _patch_connect(monkeypatch, sock):
    monkeypatch.setattr(api.socket, "create_connection", lambda addr, timeout=None: sock)


def test_upload_ws_roundtrip(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"abcdefgh")
    import hashlib

    sha = hashlib.sha256(b"abcdefgh").hexdigest()
    recv = [
        json.dumps({"type": "ready", "received": []}).encode(),
        json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
        json.dumps({"type": "ack", "index": 1, "received": 2}).encode(),
        json.dumps({"type": "done", "sha256": sha, "cached": False}).encode(),
    ]
    sock = _ws_script(recv)
    _patch_connect(monkeypatch, sock)
    seen = []
    with open(f, "rb") as fh:
        result = api.upload_ws(
            "http://s",
            fh,
            "ws.bin",
            8,
            sha,
            4,
            token="k",
            timeout=5,
            progress=lambda sent, total: seen.append((sent, total)),
        )
    assert result == {"sha256": sha, "status": "pending", "cached": False}
    frames = client_frames(sock.sent)
    start = json.loads(frames[0][1])
    assert start["type"] == "start" and start["total"] == 2 and start["sha256"] == sha
    assert frames[0][0] == 1
    assert json.loads(frames[1][1]) == {"type": "chunk", "index": 0, "size": 4}
    assert frames[2][0] == 2 and frames[2][1] == b"abcd"
    assert json.loads(frames[3][1]) == {"type": "chunk", "index": 1, "size": 4}
    assert frames[4][0] == 2 and frames[4][1] == b"efgh"
    assert frames[-1][0] == 8  # close frame
    assert seen == [(4, 8), (8, 8)]
    assert sock.closed


def test_upload_ws_resumes_missing_chunks_only(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"abcdefgh")
    sha = "0" * 64
    recv = [
        json.dumps({"type": "ready", "received": [0]}).encode(),
        json.dumps({"type": "ack", "index": 1, "received": 2}).encode(),
        json.dumps({"type": "done", "sha256": sha, "cached": True}).encode(),
    ]
    sock = _ws_script(recv)
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh:
        result = api.upload_ws("http://s", fh, "ws.bin", 8, sha, 4)
    assert result == {"sha256": sha, "status": "done", "cached": True}
    frames = client_frames(sock.sent)
    assert len(frames) == 4  # start + one chunk header + one frame + close
    assert frames[2][1] == b"efgh"


def test_upload_ws_resends_last_chunk_when_all_received(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    recv = [
        json.dumps({"type": "ready", "received": [0]}).encode(),  # everything already there
        json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
        json.dumps({"type": "done", "sha256": "0" * 64, "cached": True}).encode(),
    ]
    sock = _ws_script(recv)
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert client_frames(sock.sent)[2][1] == b"ab"  # last chunk re-sent -> assembly


def test_upload_ws_default_chunk_size(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    recv = [
        json.dumps({"type": "ready", "received": []}).encode(),
        json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
        json.dumps({"type": "done", "sha256": "0" * 64, "cached": False}).encode(),
    ]
    sock = _ws_script(recv)
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 0)  # 0 -> default chunking
    assert json.loads(client_frames(sock.sent)[0][1])["total"] == 1


def test_ws_handshake_refused(monkeypatch):
    sock = FakeSock([b"HTTP/1.1 403 Forbidden\r\n\r\n"])
    _patch_connect(monkeypatch, sock)
    with open("/dev/null", "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "x", 0, "0" * 64, 4)
    assert "handshake failed" in str(exc.value)


def test_ws_handshake_connection_closed(monkeypatch):
    sock = FakeSock([])
    _patch_connect(monkeypatch, sock)
    with open("/dev/null", "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "x", 0, "0" * 64, 4)
    assert "connection closed" in str(exc.value)


def test_ws_connect_oserror(monkeypatch):
    def boom(addr, timeout=None):
        raise OSError("refused")

    monkeypatch.setattr(api.socket, "create_connection", boom)
    with pytest.raises(api.ClientError) as exc:
        api._ws_connect("http://s", "/file/upload/ws", token=None, timeout=1)
    assert "cannot reach websocket" in str(exc.value)


def test_ws_connect_https(monkeypatch):
    ctx = {}

    class Sock(FakeSock):
        pass

    def fake_wrap(self=None, server_hostname=None):
        ctx["host"] = server_hostname
        return Sock([])

    import types

    fake_ctx = types.SimpleNamespace(wrap_socket=fake_wrap)
    monkeypatch.setattr(api.socket, "create_connection", lambda addr, timeout=None: FakeSock([]))
    monkeypatch.setattr(api.ssl, "create_default_context", lambda: fake_ctx)
    with pytest.raises(api.ClientError):  # handshake read fails on the empty socket
        api._ws_connect("https://s:8443", "/file/upload/ws", token="t", timeout=1)
    assert ctx["host"] == "s"


def test_ws_connect_invalid_base_url():
    with pytest.raises(api.ClientError) as exc:
        api._ws_connect("not-a-url", "/file/upload/ws", token=None, timeout=1)
    assert "invalid base URL" in str(exc.value)


def test_upload_ws_ready_error(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    sock = _ws_script(
        [json.dumps({"type": "error", "detail": "websocket upload disabled"}).encode()]
    )
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert "websocket upload disabled" in str(exc.value)


def test_upload_ws_unexpected_binary_frame_before_ready(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    sock = FakeSock([HANDSHAKE, sframe(b"x", opcode=2)])
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert "unexpected websocket frame type" in str(exc.value)


def test_upload_ws_unexpected_control_before_ready(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    sock = _ws_script([json.dumps({"type": "progress"}).encode()])
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert "unexpected websocket control message" in str(exc.value)


def test_upload_ws_error_after_chunks(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"abcd")
    cases = [
        (
            [
                json.dumps({"type": "ready", "received": []}).encode(),
                json.dumps({"type": "error", "detail": "assemble failed"}).encode(),
            ],
            "assemble failed",
        ),
        (
            [
                json.dumps({"type": "ready", "received": []}).encode(),
                json.dumps({"type": "ack", "index": 5, "received": 1}).encode(),
            ],
            "unexpected websocket ack",
        ),
        (
            [
                json.dumps({"type": "ready", "received": []}).encode(),
                json.dumps({"type": "ready", "received": []}).encode(),
            ],
            "unexpected websocket ack",
        ),
        (
            [
                json.dumps({"type": "ready", "received": []}).encode(),
                json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
                json.dumps({"type": "progress"}).encode(),
            ],
            "unexpected websocket control message",
        ),
        (
            [
                json.dumps({"type": "ready", "received": []}).encode(),
                json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
                json.dumps({"type": "error", "detail": "quota exceeded"}).encode(),
            ],
            "quota exceeded",
        ),
    ]
    for recv, needle in cases:
        sock = _ws_script(recv)
        _patch_connect(monkeypatch, sock)
        with open(f, "rb") as fh, pytest.raises(api.ClientError) as exc:
            api.upload_ws("http://s", fh, "ws.bin", 4, "0" * 64, 4)
        assert needle in str(exc.value)


def test_ws_recv_126_length(monkeypatch, tmp_path):
    """Control frames of 126..65535 payload bytes use the 16-bit length path."""
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    ready = json.dumps({"type": "ready", "received": [], "pad": "x" * 300}).encode()
    recv = [
        ready,
        json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
        json.dumps({"type": "done", "sha256": "0" * 64, "cached": False}).encode(),
    ]
    sock = _ws_script(recv)
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert len(client_frames(sock.sent)) == 4


def test_ws_recv_close_frame(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    sock = FakeSock([HANDSHAKE, sframe(b"", opcode=8)])
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert "closed by server" in str(exc.value)


def test_ws_recv_exhausted_mid_frame(monkeypatch, tmp_path):
    f = tmp_path / "ws.bin"
    f.write_bytes(b"ab")
    sock = FakeSock([HANDSHAKE, sframe(b'{"type":"rea')[:9]])  # truncated frame
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh, pytest.raises(api.ClientError) as exc:
        api.upload_ws("http://s", fh, "ws.bin", 2, "0" * 64, 4)
    assert "closed mid-frame" in str(exc.value)


def test_ws_extended_lengths(monkeypatch, tmp_path):
    """126/127 length paths both for sending (big frame) and receiving (big ctrl)."""
    payload = bytes(70000)
    f = tmp_path / "ws.bin"
    f.write_bytes(payload)
    big_ready = json.dumps({"type": "ready", "received": [], "pad": "x" * 70000}).encode()
    recv = [
        big_ready,
        json.dumps({"type": "ack", "index": 0, "received": 1}).encode(),
        json.dumps({"type": "done", "sha256": "0" * 64, "cached": False}).encode(),
    ]
    sock = _ws_script(recv)
    _patch_connect(monkeypatch, sock)
    with open(f, "rb") as fh:
        api.upload_ws("http://s", fh, "ws.bin", len(payload), "0" * 64, len(payload))
    frames = client_frames(sock.sent)
    assert frames[2][0] == 2 and frames[2][1] == payload  # > 65535 -> 127 length path


def test_ws_close_swallows_failures(monkeypatch):
    class BrokenSock(FakeSock):
        def sendall(self, data):
            raise OSError("gone")

        def close(self):
            raise OSError("already dead")

    sock = BrokenSock([])
    conn = api._WsConnection(sock)
    conn.close()  # must not raise on either failure
    assert sock.closed is False  # close() raised before the flag flip
