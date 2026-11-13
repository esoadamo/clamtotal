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


def test_yara_rules_script_prunes_inactive_sources():
    # rule sets disabled in the sources conf must be removed from the persistent
    # volume too, or they keep being compiled and eat the memory budget
    s = (ROOT / "scripts/update-yara-rules.sh").read_text()
    assert "pruned inactive rule set" in s and "active_names" in s


def test_entrypoint_worker_count_configurable_capped_and_memory_logged():
    ep = (ROOT / "container-entrypoint.sh").read_text()
    # worker count overridable and capped: each worker loads the full YARA rule set,
    # so uncapped nproc*2 workers OOM-kill each other on small VMs
    assert "UVICORN_WORKERS" in ep
    assert (
        'workers="${UVICORN_WORKERS:-2}"' in ep
    )  # default 2: each worker loads the YARA rule set into its own RAM
    # memory visibility at startup so OOM kills ("Child process died", no traceback)
    # can be confirmed from the container logs
    assert "memory.max" in ep and "MemTotal" in ep
    # parent must not SIGKILL a worker mid-scan: raise the healthcheck ping timeout
    assert "--timeout-worker-healthcheck" in ep and "UVICORN_WORKER_HEALTHCHECK_TIMEOUT" in ep


def test_entrypoint_starts_yara_daemon():
    ep = (ROOT / "container-entrypoint.sh").read_text()
    cf = (ROOT / "Containerfile").read_text()
    # the rule set is compiled ONCE in a daemon process; workers query it via socket
    assert "app.yara_daemon" in ep and "YARA_SOCKET" in ep
    assert "YARA_SOCKET=/tmp/yara.sock" in cf
    # the web UI starts only after the daemon answers PING (same pattern as clamd)
    assert "yara daemon did not answer PING" in ep


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


def test_clamd_unix_socket_in_tmp_plus_tcp():
    # LocalSocket lives in /tmp (writable by the clamav user even under rootless podman,
    # where /var/run/clamav is not) so the app can use FD_PASS for large files; TCP 3310
    # stays available for INSTREAM
    cf = (ROOT / "Containerfile").read_text()
    assert "LocalSocket /tmp/clamd.sock" in cf
    assert "CLAMD_SOCKET=/tmp/clamd.sock" in cf
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
    names = set()
    for name, url, branch, subdir in entries:
        assert name and url.startswith("https://github.com/") and branch and subdir
        names.add(name)
    # verified permissive licenses: MIT (ReversingLabs), DRL 1.1 (signature-base), BSD-2 (ditekshen)
    # signature-base is the biggest memory consumer, so it ships as a commented opt-in
    assert {"reversinglabs", "ditekshen"} <= names
    assert "signature-base|https://github.com/Neo23x0/signature-base.git" in conf
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


def test_domain_feed_wiring():
    cf = (ROOT / "Containerfile").read_text()
    ep = (ROOT / "container-entrypoint.sh").read_text()
    script = (ROOT / "scripts" / "update-domain-feed.sh").read_text()
    conf = (ROOT / "container" / "domain-feed-sources.conf").read_text()
    assert (ROOT / "scripts" / "update-domain-feed.sh").exists()
    assert "COPY scripts/update-domain-feed.sh" in cf
    assert "COPY container/domain-feed-sources.conf" in cf
    assert "DOMAIN_FEED_DIR=/data/domain-feed" in cf
    assert "DOMAIN_FEED_SOCKET=/tmp/domain-feed.sock" in cf
    assert "update-domain-feed.sh" in cf.split("chmod +x")[1].split("&&")[0]
    # entrypoint: bootstrap + periodic loop, gated on CLAM_AUTOUPDATE like the ClamAV updates
    assert ep.count("update-domain-feed.sh") >= 2
    assert "CLAM_AUTOUPDATE" in ep
    # the update script touches the stamp file so the feed daemon hot-reloads the lists
    assert ".feed-stamp" in script
    # URLhaus ships commented out: it needs a user-provided API key, substituted by
    # the script from URLHAUS_AUTH_KEY (or baked into a mounted sources conf)
    assert (
        "# urlhaus|malware|https://urlhaus-api.abuse.ch/v2/files/exports/<URLHAUS_AUTH_KEY>/hostfile.txt"
        in conf
    )
    assert "<URLHAUS_AUTH_KEY>" in script and "URLHAUS_AUTH_KEY" in script
    # active default sources carry a category (malware / gambling / ads)
    assert (
        "hagezi-tif|malware|https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.txt"
        in conf
    )
    assert "|gambling|" in conf
    assert "stevenblack|ads|" in conf  # StevenBlack is an ads/tracking list, not malware
    # airgapped builds bake the feed at build time too
    assert re.search(r'AIRGAPPED" = "true" \]; then .*update-domain-feed\.sh', cf, re.S)
    # compose documents the sources-conf mount and the URLHAUS_AUTH_KEY env var
    compose = (ROOT / "compose.yaml").read_text()
    assert "./domain-feed-sources.conf:/etc/domain-feed-sources.conf:ro" in compose
    assert "URLHAUS_AUTH_KEY" in compose


def test_domain_feed_daemon_wiring():
    # the feed runs as its own daemon (like the yara daemon) over a Unix socket, backed
    # by its OWN database (feed.db in the feed dir, not the app DB)
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "app.feed_daemon" in ep and "DOMAIN_FEED_SOCKET" in ep
    assert '--db "$DOMAIN_FEED_DIR/feed.db"' in ep
    # the web UI starts only after the daemon answers PING (same pattern as clamd/yara),
    # but a dead feed daemon is non-fatal (file scanning still works, URL checks 503)
    assert "domain feed daemon did not answer PING" in ep
    assert ep.index("app.feed_daemon") < ep.index("exec /app/.venv/bin/uvicorn")
    assert "feed.db" in (ROOT / "app" / "domain_feed.py").read_text()  # separate DB file


def test_compose_persists_yara_rules():
    # /rules must be a volume so auto-downloaded third-party rules survive restarts
    compose = (ROOT / "compose.yaml").read_text()
    assert "yara-rules:/rules" in compose
    assert "yara-rules:" in compose.split("volumes:")[1]


def test_clamd_stream_max_length_synced_with_stream_scan_max_size():
    # clamd's INSTREAM cap must track STREAM_SCAN_MAX_SIZE, which defaults to
    # MAX_UPLOAD_SIZE (512M) so all uploads use INSTREAM and clamd never reads
    # app-owned files; larger-than-cap files would use file-based SCAN instead
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "StreamMaxLength ${STREAM_SCAN_MAX_SIZE}" in ep
    assert "STREAM_SCAN_MAX_SIZE:-${MAX_UPLOAD_SIZE:-536870912}" in ep


def test_app_version_stamped_at_build_time():
    cf = (ROOT / "Containerfile").read_text()
    assert "date -u +%y%m%d.%H%M%S > /app/.build-version" in cf
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "APP_VERSION" in ep and "/app/.build-version" in ep


def test_entrypoint_uses_prebuilt_venv_no_runtime_sync():
    # the image already contains all packages (uv sync at build); 'uv run' at runtime
    # would try to sync from the network — use the venv binaries directly
    ep = (ROOT / "container-entrypoint.sh").read_text()
    assert "/app/.venv/bin/uvicorn" in ep
    assert "/app/.venv/bin/alembic" in ep
    # no actual 'uv run ...' command lines (comments may mention it)
    assert not [
        line for line in ep.splitlines() if line.strip().startswith(("uv run ", "exec uv run "))
    ]


def test_ci_runs_integration_test_between_build_and_publish():
    wf = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    # order: local build (no push) -> boot image + EICAR upload -> publish to GHCR
    build = wf.index("Build image locally")
    it = wf.index("Integration test")
    publish = wf.index("Publish image to GHCR")
    assert build < it < publish
    assert "push: false" in wf and "load: true" in wf  # first build stays local
    assert "bash tests/integration/eicar-smoke.sh clamtotal:it" in wf


def test_integration_smoke_assets():
    script = (ROOT / "tests" / "integration" / "eicar-smoke.sh").read_text()
    # minimal sigs + no downloads => instant start; EICAR upload must be detected
    assert "CLAM_AUTOUPDATE=false" in script
    assert "/api/v2/files" in script
    assert "infected" in script and "eicar" in script.lower()
    hdb = (ROOT / "tests" / "integration" / "signatures" / "eicar.hdb").read_text().strip()
    assert hdb == "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature"


def test_containerignore_present_and_covers_secrets():
    ci = (ROOT / ".containerignore").read_text()
    for pattern in [".env*", "*.pem", "*.key", "*secret*", ".git"]:
        assert pattern in ci, pattern


def test_airgapped_autoupdate_default_and_baked_feed():
    cf = (ROOT / "Containerfile").read_text()
    ep = (ROOT / "container-entrypoint.sh").read_text()
    # The image must NOT hardcode CLAM_AUTOUPDATE=true in ENV: image env always
    # beats the entrypoint's airgapped default, so airgapped containers kept
    # trying to download signatures/YARA rules/feed with no network.
    env_block = "\n".join(
        line
        for line in cf.split("RUN apt-get")[0].splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "CLAM_AUTOUPDATE" not in env_block
    # airgapped marker: baked by the build, resolved to CLAM_AUTOUPDATE=false by
    # the entrypoint unless the user overrides it
    assert "/app/.airgapped" in cf and "/app/.airgapped" in ep
    # the baked domain feed must live OUTSIDE /data: the runtime volume shadows
    # anything baked there, and the entrypoint seeds the feed dir from it
    assert "/var/lib/clamtotal/domain-feed" in cf
    assert "/var/lib/clamtotal/domain-feed" in ep
