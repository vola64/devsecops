# ─── Stage 1 : Builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Métadonnées OCI pour la traçabilité
LABEL org.opencontainers.image.title="DevSecOps API"
LABEL org.opencontainers.image.description="API FastAPI sécurisée - Pipeline CI/CD DevSecOps"
LABEL org.opencontainers.image.vendor="DevSecOps Project"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /build

# Installation des dépendances de build uniquement
COPY requirements.txt .
RUN pip install --upgrade pip --no-cache-dir \
    && pip install --no-cache-dir --user -r requirements.txt


# ─── Stage 2 : Runtime sécurisé ──────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Métadonnées OCI enrichies (remplies par le pipeline CI/CD)
LABEL org.opencontainers.image.title="DevSecOps API"
LABEL org.opencontainers.image.description="API FastAPI sécurisée - Pipeline CI/CD DevSecOps"
LABEL org.opencontainers.image.created=""
LABEL org.opencontainers.image.revision=""
LABEL org.opencontainers.image.version=""

# Variables d'environnement de sécurité
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_VERSION=1.0.0

WORKDIR /app

# Copier les dépendances depuis le builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Créer un utilisateur non-root (principe du moindre privilège)
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# Copier le code source avec les bonnes permissions
COPY --chown=appuser:appgroup src/ /app/

# Passer à l'utilisateur non-root
USER appuser

# Exposer le port applicatif
EXPOSE 8000

# Health check intégré dans l'image
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Point d'entrée avec uvicorn en mode production
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-access-log"]
