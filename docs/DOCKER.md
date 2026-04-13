# Docker - Aide-mémoire

## Build de l'image

```bash
# Build standard
docker build -t python-wpscan-wpvuln-enricher:latest .

# Build avec tag de version
docker build -t python-wpscan-wpvuln-enricher:1.0.0 .

# Build sans cache (recompilation complète)
docker build --no-cache -t python-wpscan-wpvuln-enricher:latest .

# Build multi-plateforme (pour registry)
docker buildx build --platform linux/amd64,linux/arm64 -t python-wpscan-wpvuln-enricher:latest .
```

## Exécution locale

```bash
# Exécution avec sortie sur stdout (recommandé)
docker run --rm \
  -v $(pwd)/examples/wpscan-findings.json:/tmp/findings.json:ro \
  -e READ_FILE=/tmp/findings.json \
  -e WRITE_FILE="" \
  python-wpscan-wpvuln-enricher:latest

# Exécution avec sortie dans un fichier local
# Note: L'image distroless utilise l'utilisateur nonroot
# Le dossier de sortie doit être accessible en écriture
docker run --rm \
  -v $(pwd)/examples/wpscan-findings.json:/tmp/input.json:ro \
  -v $(pwd)/output:/tmp/output \
  -e READ_FILE=/tmp/input.json \
  -e WRITE_FILE=/tmp/output/enriched.json \
  python-wpscan-wpvuln-enricher:latest

# Alternative: utiliser --user pour forcer root (moins sécurisé)
docker run --rm --user root \
  -v $(pwd)/examples:/data \
  -e READ_FILE=/data/wpscan-findings.json \
  -e WRITE_FILE=/data/enriched.json \
  python-wpscan-wpvuln-enricher:latest
```

## Inspection de l'image

```bash
# Voir les labels (version, API version)
docker inspect python-wpscan-wpvuln-enricher:latest --format='{{json .Config.Labels}}' | jq

# Voir la taille de l'image
docker images python-wpscan-wpvuln-enricher

# Voir les layers
docker history python-wpscan-wpvuln-enricher:latest

# Scanner les vulnérabilités (avec Trivy)
trivy image python-wpscan-wpvuln-enricher:latest

# Scanner les vulnérabilités (avec Docker Scout)
docker scout cves python-wpscan-wpvuln-enricher:latest
```

## Publication sur un registry

```bash
# Tag pour GitHub Container Registry
docker tag python-wpscan-wpvuln-enricher:latest ghcr.io/venantvr-security/python-wpscan-wpvuln-enricher:latest
docker tag python-wpscan-wpvuln-enricher:latest ghcr.io/venantvr-security/python-wpscan-wpvuln-enricher:1.0.0

# Login GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Push
docker push ghcr.io/venantvr-security/python-wpscan-wpvuln-enricher:latest
docker push ghcr.io/venantvr-security/python-wpscan-wpvuln-enricher:1.0.0
```

## Nettoyage

```bash
# Supprimer l'image
docker rmi python-wpscan-wpvuln-enricher:latest

# Supprimer les images non utilisées
docker image prune

# Supprimer tout le cache de build
docker builder prune -a
```

## Debugging

```bash
# Voir les logs d'un container
docker logs <container_id>

# Exécuter une commande dans un container running
docker exec -it <container_id> /bin/sh

# Copier un fichier depuis/vers un container
docker cp <container_id>:/tmp/findings.json ./output.json
docker cp ./input.json <container_id>:/tmp/findings.json
```

## Variables d'environnement

| Variable | Description | Valeur par défaut |
|----------|-------------|-------------------|
| `READ_FILE` | Chemin du fichier JSON d'entrée | `/tmp/findings.json` |
| `WRITE_FILE` | Chemin du fichier JSON de sortie | `/tmp/findings.json` |

## Exemple complet

```bash
# 1. Build
docker build -t python-wpscan-wpvuln-enricher:latest .

# 2. Créer un fichier de test
cat > /tmp/test-findings.json << 'EOF'
[
  {
    "id": "test-1",
    "name": "Plugin: updraftplus",
    "category": "WordPress Plugin",
    "location": "https://example.com",
    "attributes": {"slug": "updraftplus"}
  }
]
EOF

# 3. Exécuter (sortie sur stdout)
docker run --rm \
  -v /tmp/test-findings.json:/tmp/findings.json:ro \
  -e WRITE_FILE="" \
  python-wpscan-wpvuln-enricher:latest

# 4. Exécuter avec sortie fichier
mkdir -p /tmp/output
docker run --rm \
  -v /tmp/test-findings.json:/tmp/input.json:ro \
  -v /tmp/output:/tmp/output \
  -e READ_FILE=/tmp/input.json \
  -e WRITE_FILE=/tmp/output/enriched.json \
  python-wpscan-wpvuln-enricher:latest

cat /tmp/output/enriched.json
```

## Développement local (sans Docker)

```bash
# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer les tests
pytest -v main_test.py

# Exécuter le programme
export READ_FILE=./examples/wpscan-findings.json
export WRITE_FILE=./output/enriched.json
python main.py
```
