#!/bin/bash
#
# save-transcript.sh - Sauvegarde la discussion avant compaction
# Hook: PreCompact
#

set -e

# Lire le JSON d'entrée depuis stdin
INPUT=$(cat)

# Extraire les champs du JSON (sans jq)
TRANSCRIPT_PATH=$(echo "$INPUT" | grep -oP '"transcript_path"\s*:\s*"\K[^"]+')
SESSION_ID=$(echo "$INPUT" | grep -oP '"session_id"\s*:\s*"\K[^"]+')

# Répertoire de sauvegarde (relatif au script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/../logs"
mkdir -p "$BACKUP_DIR"

# Nom du fichier avec timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/conversation-${TIMESTAMP}-${SESSION_ID:0:8}.jsonl"

# Copier le transcript
if [[ -f "$TRANSCRIPT_PATH" ]]; then
    cp "$TRANSCRIPT_PATH" "$BACKUP_FILE"
    echo "[PreCompact] Sauvegardé: $BACKUP_FILE" >&2
else
    echo "[PreCompact] Transcript non trouvé: $TRANSCRIPT_PATH" >&2
fi

exit 0
