# syntax=docker/dockerfile:1
# ClamTotal — Podman/Docker image with ClamAV daemon (clamd) + signature autoupdater.
# Build:  podman build -t clamtotal .
# Run:    podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data -v ./my-rules:/rules:ro clamtotal
#
# Fully airgapped deployments: build with --build-arg AIRGAPPED=true so all signatures
# (official + unofficial) are BAKED INTO the image at build time; at runtime the
# autoupdater is disabled (CLAM_AUTOUPDATE=false). Default builds download signatures
# on first container launch instead.
ARG AIRGAPPED=false
FROM python:3.12-slim-bookworm

# uv is not in the base image — install the official binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    CLAM_MODE=daemon \
    DATABASE_URL=sqlite:////data/clamtotal.db \
    UPLOAD_DIR=/data/uploads \
    YARA_RULES_DIR=/rules \
    CLAM_AUTOUPDATE=true

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         clamav clamav-daemon clamav-freshclam curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --group signatures
COPY . .
RUN uv sync --frozen --no-dev --no-install-project --group signatures

# Unofficial signature DBs (SaneSecurity etc., includes YARA rules) via fangfrisch.
COPY container/fangfrisch.conf /etc/fangfrisch.conf
COPY scripts/update-signatures.sh /usr/local/bin/
# Third-party YARA rule sets for the local YARA engine (license-permitted sources only).
COPY scripts/update-yara-rules.sh /usr/local/bin/
COPY container/yara-rules-sources.conf /etc/yara-rules-sources.conf
# fangfrisch is installed in the uv venv, not on PATH — call it via the venv binary.
# Signature semantics: by default NOTHING is downloaded at build time (signatures are
# fetched on first container launch, see container-entrypoint.sh). AIRGAPPED=true bakes
# signatures into the image at build time instead.
RUN chmod +x /usr/local/bin/update-signatures.sh /usr/local/bin/update-yara-rules.sh \
    && mkdir -p /var/lib/fangfrisch \
    && /app/.venv/bin/fangfrisch --conf /etc/fangfrisch.conf initdb \
    && if [ "$AIRGAPPED" = "true" ]; then CLAM_AUTOUPDATE=true update-signatures.sh; \
         YARA_RULES_DIR=/rules update-yara-rules.sh || true; \
         else echo "default build: signatures are downloaded on first container launch"; fi

# Expose clamd on TCP 3310 inside the container (INSTREAM protocol).
RUN sed -i \
      -e 's/^#\{0,1\}\(TCPSocket 3310\)/\1/' \
      -e 's/^#\{0,1\}\(TCPAddr .*\)/TCPAddr 0.0.0.0/' \
      -e 's/^#\{0,1\}\(LocalSocket .*\)/# LocalSocket disabled — TCP INSTREAM only (app connects via TCP 3310)/' \
      /etc/clamav/clamd.conf \
    && sed -i \
      -e 's/^#\{0,1\}\(NotifyClamd .*\)/# NotifyClamd disabled — bootstrap downloads run before clamd starts/' \
      /etc/clamav/freshclam.conf \
    && { grep -q '^TCPSocket 3310' /etc/clamav/clamd.conf || echo 'TCPSocket 3310' >> /etc/clamav/clamd.conf; } \
    && { grep -q '^TCPAddr 0.0.0.0' /etc/clamav/clamd.conf || echo 'TCPAddr 0.0.0.0' >> /etc/clamav/clamd.conf; }

# Bundled public YARA rules (recursive, so app/rules/ subdirs work too); mount your
# own public rules over /rules. Auto-downloaded third-party rules land in
# /rules/third_party at container start (CLAM_AUTOUPDATE=true).
RUN mkdir -p /rules && cp -r /app/app/rules/. /rules/

COPY container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod +x /usr/local/bin/container-entrypoint.sh \
    && date -u +%y%m%d.%H%M%S > /app/.build-version  # build timestamp shown as the app version

EXPOSE 8000
VOLUME ["/data", "/rules"]
ENTRYPOINT ["container-entrypoint.sh"]
