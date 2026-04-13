#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract-responses.py - Extrait les réponses textuelles de Claude d'un transcript
Usage: python3 extract-responses.py <transcript.jsonl> <output.md>
"""

import json
import sys
from datetime import datetime

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 extract-responses.py <transcript.jsonl> <output.md>", file=sys.stderr)
        sys.exit(1)

    transcript_path = sys.argv[1]
    output_path = sys.argv[2]

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
                        if isinstance(item, dict):
                            # Extraire le texte (pas le thinking)
                            if item.get("type") == "text":
                                text_parts.append(item.get("text", ""))
                    if text_parts:
                        responses.append("\n".join(text_parts))
            except json.JSONDecodeError:
                continue

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Réponses Claude - Session " + timestamp + "\n\n")
        for i, resp in enumerate(responses, 1):
            f.write("---\n\n## Réponse " + str(i) + "\n\n" + resp + "\n\n")

    count = len(responses)
    print("[PreCompact] " + str(count) + " réponses extraites -> " + output_path, file=sys.stderr)

if __name__ == "__main__":
    main()
