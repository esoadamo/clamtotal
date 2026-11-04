"""Static checks on the container build/run files so CI-level breakage is caught by unit tests."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_containerfile_installs_uv():
    cf = (ROOT / "Containerfile").read_text()
    assert "COPY --from=ghcr.io/astral-sh/uv" in cf


def test_containerfile_signature_semantics():
    cf = (ROOT / "Containerfile").read_text()
    # fangfrisch must be called via the venv binary (not on PATH in the image)
    assert "/app/.venv/bin/fangfrisch" in cf
    # AIRGAPPED=true bakes signatures at BUILD time...
    assert re.search(r'AIRGAPPED" = "true" \]; then .*update-signatures\.sh', cf, re.S)
    # ...and the default build must NOT download signatures
    default_branch = re.search(r'else echo "default build[^"]*"', cf)
    assert default_branch and "update-signatures" not in default_branch.group(0)


def test_entrypoint_first_launch_bootstrap():
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "/data/.signatures-initialized" in ep  # marker: download once on first launch
    assert "update-signatures.sh" in ep
    assert "CLAM_AUTOUPDATE" in ep  # opt-out for airgapped images


def test_scripts_resolve_fangfrisch_from_venv():
    s = (ROOT / "scripts/update-signatures.sh").read_text()
    assert "/app/.venv/bin/fangfrisch" in s


def test_fangfrisch_db_not_inside_clamav_dbdir():
    # clamd loads every file in /var/lib/clamav as a signature DB; a sqlite fangfrisch.db
    # there makes clamd fail with "Malformed database" and the container never starts
    conf = (ROOT / "container" / "fangfrisch.conf").read_text()
    m = re.search(r"db_url\s*=\s*(\S+)", conf)
    assert m
    assert "/var/lib/clamav" not in m.group(1)
    cf = (ROOT / "Containerfile").read_text()
    assert "mkdir -p /var/lib/fangfrisch" in cf  # dir must exist before fangfrisch initdb
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "rm -f /var/lib/clamav/fangfrisch.db" in ep  # self-heal broken containers


def test_clamd_uses_tcp_only_no_local_socket():
    # rootless podman: /var/run/clamav is not writable, so clamd dies on LocalSocket;
    # the app only needs TCP INSTREAM on 3310
    cf = (ROOT / "Containerfile").read_text()
    assert "LocalSocket disabled" in cf
    assert "TCPSocket 3310" in cf and "TCPAddr 0.0.0.0" in cf


def test_github_actions_pinned_by_sha():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line in wf.read_text().splitlines():
            line = line.strip()
            if line.startswith("uses:"):
                assert re.fullmatch(r"uses: [^@\s]+@[0-9a-f]{40}( .*)?", line), (
                    f"{wf.name}: not pinned by hash: {line}"
                )


def test_containerignore_present_and_covers_secrets():
    ci = (ROOT / ".containerignore").read_text()
    for pattern in [".env*", "*.pem", "*.key", "*secret*", ".git"]:
        assert pattern in ci, pattern
