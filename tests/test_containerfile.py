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
    # first-init download failure must be FATAL (container refuses to start)
    assert "refusing to start" in ep and "exit 1" in ep


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
    # the web UI must start only after clamd is ready: PONG wait before uvicorn
    assert ep.index("PONG") < ep.index("uvicorn")
    # and the PONG wait must be fatal on timeout (set -e + non-zero exit)
    assert 'sys.exit("clamd did not answer PING' in ep
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


def test_yara_rules_autoupdate_wiring():
    cf = (ROOT / "Containerfile").read_text()
    ep = (ROOT / "container-entrypoint.sh").read_text()
    script = (ROOT / "scripts" / "update-yara-rules.sh").read_text()
    assert (ROOT / "scripts" / "update-yara-rules.sh").exists()
    assert (ROOT / "container" / "yara-rules-sources.conf").exists()
    # script + sources config are baked into the image and the script is executable
    assert "COPY scripts/update-yara-rules.sh" in cf
    assert "COPY container/yara-rules-sources.conf" in cf
    assert "chmod +x" in cf and "update-yara-rules.sh" in cf.split("chmod +x")[1].split("\n")[0]
    # bundled rules are copied recursively so app/rules/ subdirs land in /rules too
    assert "cp -r /app/app/rules/. /rules/" in cf
    # entrypoint: bootstrap + periodic loop, gated on CLAM_AUTOUPDATE like the ClamAV updates
    assert ep.count("update-yara-rules.sh") >= 2
    assert "CLAM_AUTOUPDATE" in ep
    # the update script touches the stamp file so the app hot-reloads rules
    assert ".rules-stamp" in script
    # airgapped builds bake third-party YARA rules at build time too
    assert re.search(r'AIRGAPPED" = "true" \]; then .*update-yara-rules\.sh', cf, re.S)


def test_yara_rules_sources_are_license_permitted():
    conf = (ROOT / "container" / "yara-rules-sources.conf").read_text()
    entries = [
        line.split("|")
        for line in conf.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(entries) >= 3
    names = set()
    for name, url, branch, subdir in entries:
        assert name and url.startswith("https://github.com/") and branch and subdir
        names.add(name)
    # verified permissive licenses: MIT (ReversingLabs), DRL 1.1 (signature-base), BSD-2 (ditekshen)
    assert {"reversinglabs", "signature-base", "ditekshen"} <= names
    low = conf.lower()
    assert "mit" in low and "bsd" in low and "drl" in low
    # no Elastic License 2.0 (SaaS restriction) or other non-permissive ACTIVE sources
    # (the commented yara-forge opt-in may mention them in its license warning)
    active = "\n".join(
        line for line in conf.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ).lower()
    assert "elastic" not in active and "protections-artifacts" not in active


def test_yara_forge_is_commented_optin_and_sources_config_is_mountable():
    conf = (ROOT / "container" / "yara-rules-sources.conf").read_text()
    # YARA Forge ships rules as release zips (not in the git repo) and its packages mix
    # upstream licenses (GPL-3.0 tool, Elastic License 2.0 inside) -> documented as a
    # commented opt-in with the license warning, not an active source
    assert "# yara-forge-core|" in conf
    assert "releases/latest/download/yara-forge-rules-core.zip" in conf
    assert "Elastic License 2.0" in conf
    # the updater supports zip release assets (curl download + python zipfile extract)
    script = (ROOT / "scripts" / "update-yara-rules.sh").read_text()
    assert "*.zip" in script and "zipfile" in script and "curl" in script
    # users can override the sources list via a compose mount, same pattern as fangfrisch
    compose = (ROOT / "compose.yaml").read_text()
    assert "./yara-rules-sources.conf:/etc/yara-rules-sources.conf:ro" in compose
    assert "YARA_RULES_SOURCES" in (ROOT / "README.md").read_text()


def test_compose_persists_yara_rules():
    # /rules must be a volume so auto-downloaded third-party rules survive restarts
    compose = (ROOT / "compose.yaml").read_text()
    assert "yara-rules:/rules" in compose
    assert "yara-rules:" in compose.split("volumes:")[1]


def test_clamd_stream_max_length_synced_with_app_limit():
    # clamd's default StreamMaxLength (100M) would reject uploads the app allows
    # (MAX_UPLOAD_SIZE default 512M) — the entrypoint must sync them
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "StreamMaxLength ${MAX_UPLOAD_SIZE}" in ep
    assert "MAX_UPLOAD_SIZE:-536870912" in ep


def test_containerignore_present_and_covers_secrets():
    ci = (ROOT / ".containerignore").read_text()
    for pattern in [".env*", "*.pem", "*.key", "*secret*", ".git"]:
        assert pattern in ci, pattern
