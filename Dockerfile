# syntax=docker/dockerfile:1.7
# One image, two roles: `chimera serve` (honeypot) and `chimera-responder` (Blue Team).

FROM python:3.12-slim-bookworm AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Optional: behind a TLS-inspecting corporate proxy, pass its CA with
#   docker build --secret id=ca,src=/path/to/ca.pem .
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    python -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip && /opt/venv/bin/pip install .

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="Project Chimera" \
      org.opencontainers.image.description="Deception-driven MCP honeypot with Blue Team containment" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CHIMERA_DATA_DIR=/data RESPONDER_DATA_DIR=/data
RUN groupadd --system --gid 10001 chimera \
 && useradd --system --uid 10001 --gid chimera --home-dir /nonexistent --shell /usr/sbin/nologin chimera \
 && mkdir -p /data && chown chimera:chimera /data \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /root/.cache
COPY --from=build /opt/venv /opt/venv
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000 9000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;p=os.environ.get('HEALTH_PORT','8000');urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz',timeout=2)"]
ENTRYPOINT ["chimera"]
CMD ["serve"]
