# =============================================================================
# DOCKERFILE - WPScan WPVuln Enricher (Python)
# Build multi-stage pour une image finale minimale et sécurisée (0 CVE)
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: Tests et préparation
# Image Chainguard Python - maintenue avec 0 CVE connues
# https://images.chainguard.dev/directory/image/python/overview
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /work

# Copier les dépendances
COPY requirements.txt ./

# Installer les dépendances dans un virtualenv
RUN python -m venv /work/venv && \
    /work/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY main.py parser.py ./

# -----------------------------------------------------------------------------
# STAGE 2: Image d'exécution
# Image Chainguard Python - minimale avec 0 CVE
# https://images.chainguard.dev/directory/image/python/overview
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest

# Labels OCI standard pour la traçabilité
LABEL org.opencontainers.image.title="WPScan WPVuln Enricher"
LABEL org.opencontainers.image.description="secureCodeBox hook to enrich WPScan findings with WPVulnerability data"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/venantvr-security/python-wpscan-wpvuln-enricher"
LABEL org.opencontainers.image.licenses="MIT"

# Labels custom pour la version de l'API
LABEL com.wpvulnerability.api-version="2024-01"
LABEL com.wpvulnerability.api-docs="https://www.wpvulnerability.net/api/plugins/"

# Copier l'application et le virtualenv complet
COPY --from=builder /work/main.py /app/main.py
COPY --from=builder /work/parser.py /app/parser.py
COPY --from=builder /work/venv /app/venv

# secureCodeBox passe les URLs comme arguments de ligne de commande:
#   argv[1] = URL raw results (download)
#   argv[2] = URL findings (download)
#   argv[3] = URL raw results (upload) - pour ReadAndWrite
#   argv[4] = URL findings (upload) - pour ReadAndWrite
ENV PATH="/app/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Point d'entrée - utilise le python du venv
ENTRYPOINT ["python", "/app/main.py"]
