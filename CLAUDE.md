# Instructions pour Claude

## Langue et style

- **Toujours utiliser les accents français** dans tous les fichiers : é, è, ê, ë, à, â, ù, û, ô, î, ï, ç
- Exemples : créer, déployer, opérateur, résumé, terminé, préchargement, vérification, prérequis
- **Pas de diagrammes ASCII** - utiliser Mermaid pour les diagrammes

## Documentation

- Utiliser **Mermaid** pour les diagrammes dans les fichiers Markdown
- Types de diagrammes préférés :
  - `flowchart TD` pour les workflows
  - `sequenceDiagram` pour les flux de données
  - `graph LR` pour les architectures

## Projets liés

Ce projet fait partie d'un écosystème de sécurité WordPress :

| Projet | Description | Repo |
|--------|-------------|------|
| **secureCodeBox** | Configuration K8s et scripts d'installation | `secureCodeBox/` |
| **go-wpscan-wpvuln-enricher** | Enricher Go - Parser + Hook | `go-wpscan-wpvuln-enricher/` |
| **python-wpscan-wpvuln-enricher** | Enricher Python (ce repo) - Version alternative | `python-wpscan-wpvuln-enricher/` |
| **vuejs.secureCodeBox.Dashboard** | Dashboard Vue.js pour visualiser les scans | `vuejs.secureCodeBox.Dashboard/` |

## Ce projet

Enricher WPScan écrit en Python avec deux modes :
- **Parser** : Convertit les résultats WPScan en findings secureCodeBox
- **Hook** : Enrichit les findings avec les vulnérabilités de WPVulnerability.net

### Fichiers principaux

- `parser.py` : Parser WPScan → findings
- `enricher.py` : Hook d'enrichissement vulnérabilités
- `Dockerfile` : Image Docker pour secureCodeBox

### Mode secureCodeBox

Le parser/hook reçoit les URLs presignées MinIO en arguments :
- `argv[1]` : URL de téléchargement des résultats bruts
- `argv[2]` : URL d'upload des findings

### Build

```bash
docker build -t ghcr.io/venantvr-security/python-wpscan-wpvuln-enricher:latest .
```
