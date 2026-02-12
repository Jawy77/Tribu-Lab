# =============================================================================
# 🦞 OpenClaw Bot — Hardened Dockerfile
# Búnker DevSecOps Workshop — Comunidad Claude Anthropic Colombia
# =============================================================================
# Security features:
#   - Multi-stage build (reduce attack surface)
#   - Non-root user
#   - Read-only filesystem
#   - No new privileges
#   - Minimal base image
#   - Health check
# =============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Instalar dependencias del sistema para compilación
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime (Hardened) ──────────────────────────────────
FROM python:3.12-slim AS runtime

# Metadata
LABEL maintainer="Mantishield <security@mantishield.com>"
LABEL description="OpenClaw Bot — Hardened for Búnker DevSecOps"
LABEL workshop="Comunidad Claude Anthropic Colombia"

# Crear usuario no-root
RUN groupadd -r openclaw && \
    useradd -r -g openclaw -d /app -s /sbin/nologin openclaw

# Copiar solo las dependencias compiladas
COPY --from=builder /install /usr/local

# Instalar solo lo mínimo necesario en runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove

# Directorio de la app
WORKDIR /app

# Copiar código de la aplicación
COPY --chown=openclaw:openclaw . .

# Directorio para datos temporales (writable)
RUN mkdir -p /app/tmp /app/logs && \
    chown -R openclaw:openclaw /app/tmp /app/logs

# Configurar DNS (necesario para descargar modelos)
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf.override

# Cambiar a usuario no-root
USER openclaw

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Usar tini como init (PID 1 correcto, signal handling)
ENTRYPOINT ["tini", "--"]

# Ejecutar la aplicación
CMD ["python", "-m", "openclaw.main"]

# ── Security Labels ──────────────────────────────────────────────
# Estas labels documentan la postura de seguridad del container
LABEL security.read-only-rootfs="true"
LABEL security.no-new-privileges="true"
LABEL security.non-root-user="openclaw"
