#!/bin/bash
#
# save-transcript.sh - Extrait les réponses de Claude avant compaction
# Hook: PreCompact
#

set -e

# Lire le JSON d'entrée depuis stdin
INPUT=$(cat)

# Extraire les champs du JSON
TRANSCRIPT_PATH=$(echo "$INPUT" | grep -oP '"transcript_path"\s*:\s*"\K[^"]+')
SESSION_ID=$(echo "$INPUT" | grep -oP '"session_id"\s*:\s*"\K[^"]+')

# Répertoire de sauvegarde
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/../logs"
mkdir -p "$BACKUP_DIR"

# Nom du fichier avec timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/claude-responses-${TIMESTAMP}-${SESSION_ID:0:8}.md"

if [[ ! -f "$TRANSCRIPT_PATH" ]]; then
    echo "[PreCompact] Transcript non trouvé: $TRANSCRIPT_PATH" >&2
    exit 0
fi

# Extraire les réponses avec le script Python
python3 "${SCRIPT_DIR}/extract-responses.py" "$TRANSCRIPT_PATH" "$BACKUP_FILE"

exit 0
