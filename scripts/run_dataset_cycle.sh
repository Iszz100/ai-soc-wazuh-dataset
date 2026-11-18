#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$HOME/ai-soc-wazuh-dataset}"
CONFIG="${CONFIG:-configs/orchestrator.json}"
LOG_DIR="$PROJECT_DIR/logs/chapter8"
DRY_RUN="${DRY_RUN:-0}"

mkdir -p "$LOG_DIR"
cd "$PROJECT_DIR"

START_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[$START_TIME] Starting dataset cycle" | tee -a "$LOG_DIR/run_dataset_cycle.log"

source venv/bin/activate 2>/dev/null || true

ARGS=(--config "$CONFIG")

if [[ "$DRY_RUN" == "1" ]]; then
    ARGS+=(--dry-run)
fi

python scripts/orchestrator.py "${ARGS[@]}" \
    2>> "$LOG_DIR/orchestrator.stderr.log" \
    | tee -a "$LOG_DIR/orchestrator.stdout.log"

END_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[$END_TIME] Finished dataset cycle" | tee -a "$LOG_DIR/run_dataset_cycle.log"
