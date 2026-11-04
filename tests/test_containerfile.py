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
    assert "update-signatures.sh" in ep
    assert "CLAM_AUTOUPDATE" in ep  # opt-out for airgapped images
    # bootstrap is gated on ACTUAL db files in /var/lib/clamav, not a marker file:
    # a marker that survives a failed download made every later start skip the
    # bootstrap and clamd died with 'No supported database files found'
    assert ".signatures-initialized" not in ep
    assert "sig_db_files" in ep and "! sig_db_files" in ep


def test_scripts_resolve_fangfrisch_from_venv():
    s = (ROOT / "scripts/update-signatures.sh").read_text()
    assert "/app/.venv/bin/fangfrisch" in s


def test_signature_scripts_fail_gracefully_offline():
    # no-DNS environments: keep existing signatures, print one line, no stack trace
    s = (ROOT / "scripts/update-signatures.sh").read_text()
    assert "fangfrisch refresh failed (offline?)" in s
    assert "tail -n 1 /tmp/fangfrisch.log" in s
    assert "update-unofficial-sigs.sh" not in s  # extremeshok repo ships no sig files anymore


def test_extremeshok_script_removed_repo_has_no_sig_files():
    # extremeshok/clamav-unofficial-sigs no longer ships signature files in the repo
    # (verified: 0 *.db/*.ndb/... on master and recent tags), so cloning it can only
    # ever install 0 files — the script was removed
    assert not (ROOT / "scripts" / "update-unofficial-sigs.sh").exists()
    cf = (ROOT / "Containerfile").read_text()
    assert "update-unofficial-sigs.sh" not in cf


def test_entrypoint_bootstraps_signatures_before_clamd():
    # clamd refuses to start when /var/lib/clamav has no supported database files
    # ('No supported database files found'), so the first-launch bootstrap must run first
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert ep.index("update-signatures.sh") < ep.index("clamd &")
    assert "zPING" in ep and "PONG" in ep  # readiness = real clamd PING, not just TCP connect
    cf = (ROOT / "Containerfile").read_text()
    assert (
        "NotifyClamd disabled" in cf
    )  # bootstrap runs before clamd, so freshclam must not notify it


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
    prefixes = re.findall(r"^\s*prefix\s*=\s*(\S+)", conf, re.M)
    assert prefixes and all("sanesecurity.net" not in p for p in prefixes)  # dead host
    assert any("mirror.seichter.de/sanesecurity" in p for p in prefixes)  # current upstream mirror


def test_entrypoint_runs_alembic_migrations():
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "alembic upgrade head" in ep  # otherwise the container starts with no tables


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


def test_zizmor_is_own_job_in_tests_workflow():
    # zizmor is its own job inside tests.yml (no separate workflow file);
    # the upstream zizmor GitHub Action is broken at v1.32.0 (empty ZIZMOR_VERSION
    # build arg), so we run the PyPI binary via uvx instead
    assert not (ROOT / ".github" / "workflows" / "zizmor.yml").exists()
    t = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    assert "  zizmor:\n" in t
    assert "uvx zizmor==1.32.0 --offline .github/workflows/" in t
    # the container image must not build unless zizmor passes too
    assert "needs: [test, zizmor, sast, sca]" in t


def test_compose_persists_clamav_signature_db():
    # /var/lib/clamav must be a volume, otherwise a restart loses the downloaded
    # signatures and clamd fails with 'No supported database files found'
    compose = (ROOT / "compose.yaml").read_text()
    assert "clamav-db:/var/lib/clamav" in compose
    assert "clamav-db:" in compose.split("volumes:")[1]


def test_containerignore_present_and_covers_secrets():
    ci = (ROOT / ".containerignore").read_text()
    for pattern in [".env*", "*.pem", "*.key", "*secret*", ".git"]:
        assert pattern in ci, pattern
