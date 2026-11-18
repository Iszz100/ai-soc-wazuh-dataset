#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$HOME/ai-soc-wazuh-dataset}"
KEEP_DAYS="${KEEP_DAYS:-14}"

cd "$PROJECT_DIR"

echo "===== OLD RUN DIRECTORIES ====="

find runs -maxdepth 1 -type d -name 'run-*' \
    -mtime +"$KEEP_DAYS" -print

echo ""
echo "Dry-run only. No evidence has been deleted."
echo "Review evidence before manually deleting anything."
