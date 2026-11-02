# syntax=docker/dockerfile:1
# ClamTotal — Podman/Docker image with ClamAV daemon (clamd) baked in.
# Build:  podman build -t clamtotal .
# Run:    podman run -p 127.0.0.1:8000:8000 -v clamtotal-data:/data clamtotal
FROM python:3.12-slim-bookworm

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    CLAM_MODE=daemon \
    DATABASE_URL=sqlite:////data/clamtotal.db \
    UPLOAD_DIR=/data/uploads

RUN apt-get update \
    && apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY . .
RUN uv sync --frozen --no-dev

# Refresh signatures at image build time. For a fully airgapped build, disable
# this line and bake your own signature files into /var/lib/clamav instead.
RUN freshclam --quiet || echo "freshclam failed at build time; bake signatures into /var/lib/clamav"

# Expose clamd on TCP 3310 inside the container (INSTREAM protocol).
RUN sed -i \
      -e 's/^#\(TCPSocket 3310\)/\1/' \
      -e 's/^#\(TCPAddr .*\)/TCPAddr 0.0.0.0/' \
      /etc/clamav/clamd.conf \
    && grep -q '^TCPSocket 3310' /etc/clamav/clamd.conf

COPY container-entrypoint.sh /usr/local/bin/container-entrypoint.sh
RUN chmod +x /usr/local/bin/container-entrypoint.sh

EXPOSE 8000
VOLUME ["/data"]
ENTRYPOINT ["container-entrypoint.sh"]
