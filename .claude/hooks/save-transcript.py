#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
save-transcript.py - Extrait les réponses de Claude avant compaction
Hook: PreCompact

Reçoit sur stdin:
{
    "transcript_path": "/path/to/transcript.jsonl",
    "session_id": "abc123",
    "trigger": "auto|manual"
}
"""
from __future__ import annotations

import json
import sys
import os
from datetime import datetime
from pathlib import Path


def extract_responses(transcript_path: str) -> list:
    """Extrait les réponses textuelles du transcript."""
    responses = []

    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                # Messages assistant dans le format Claude Code
                if msg.get("type") == "assistant":
                    message = msg.get("message", {})
                    content = message.get("content", [])
                    text_parts = []
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text_parts.append(item.get("text", ""))
                    if text_parts:
                        responses.append("\n".join(text_parts))
            except json.JSONDecodeError:
                continue

    return responses


def write_markdown(responses: list, output_path: str) -> None:
    """Écrit les réponses en markdown."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Réponses Claude - Session {timestamp}\n\n")
        for i, resp in enumerate(responses, 1):
            f.write(f"---\n\n## Réponse {i}\n\n{resp}\n\n")


def main():
    # Lire le JSON d'entrée depuis stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"[PreCompact] Erreur JSON stdin: {e}", file=sys.stderr)
        sys.exit(0)

    transcript_path = input_data.get("transcript_path")
    session_id = input_data.get("session_id", "unknown")

    if not transcript_path or not os.path.isfile(transcript_path):
        print(f"[PreCompact] Transcript non trouvé: {transcript_path}", file=sys.stderr)
        sys.exit(0)

    # Répertoire de sauvegarde
    script_dir = Path(__file__).parent
    backup_dir = script_dir.parent / "logs"
    backup_dir.mkdir(exist_ok=True)

    # Nom du fichier avec timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_short = session_id[:8] if len(session_id) >= 8 else session_id
    backup_file = backup_dir / f"claude-responses-{timestamp}-{session_short}.md"

    # Extraire et sauvegarder
    responses = extract_responses(transcript_path)
    write_markdown(responses, str(backup_file))

    print(f"[PreCompact] {len(responses)} réponses extraites -> {backup_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
