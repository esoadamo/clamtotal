# syntax=docker/dockerfile:1
# ClamTotal — Podman/Docker image with ClamAV daemon (clamd) + signature autoupdater.
# Build:  podman build -t clamtotal .
# Run:    podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data -v ./my-rules:/rules:ro clamtotal
#
# Fully airgapped builds: build with --build-arg AIRGAPPED=true (skips all signature
# downloads at build time) and bake your own signatures into /var/lib/clamav, e.g.
#   podman build --build-arg AIRGAPPED=true -t clamtotal .
# and at runtime set CLAM_AUTOUPDATE=false.
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
COPY scripts/update-signatures.sh scripts/update-unofficial-sigs.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/update-signatures.sh /usr/local/bin/update-unofficial-sigs.sh \
    && fangfrisch --conf /etc/fangfrisch.conf initdb \
    && if [ "$AIRGAPPED" != "true" ]; then CLAM_AUTOUPDATE=true update-signatures.sh; \
         else echo "AIRGAPPED build: skipping signature downloads — bake signatures into /var/lib/clamav"; fi

# Expose clamd on TCP 3310 inside the container (INSTREAM protocol).
RUN sed -i \
      -e 's/^#\{0,1\}\(TCPSocket 3310\)/\1/' \
      -e 's/^#\{0,1\}\(TCPAddr .*\)/TCPAddr 0.0.0.0/' \
      /etc/clamav/clamd.conf \
    && { grep -q '^TCPSocket 3310' /etc/clamav/clamd.conf || echo 'TCPSocket 3310' >> /etc/clamav/clamd.conf; } \
    && { grep -q '^TCPAddr 0.0.0.0' /etc/clamav/clamd.conf || echo 'TCPAddr 0.0.0.0' >> /etc/clamav/clamd.conf; }

# Bundled public YARA rules; mount your own public rules over /rules.
RUN mkdir -p /rules && cp /app/app/rules/*.yar /rules/

COPY container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod +x /usr/local/bin/container-entrypoint.sh

EXPOSE 8000
VOLUME ["/data", "/rules"]
ENTRYPOINT ["container-entrypoint.sh"]
