#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import requests

def read_text(path):
    p = Path(path)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434/api/generate"
    )
    parser.add_argument("--model", default="qwen3:4b")
    parser.add_argument(
        "--prompt",
        default="prompts/final_soc_report.prompt.txt"
    )
    parser.add_argument(
        "--quality-report",
        default="reports/final/dataset_quality_report.md"
    )
    parser.add_argument(
        "--model-report",
        default="reports/final/model_baseline_report.md"
    )
    parser.add_argument(
        "--dataset-card",
        default="datasets/final/DATASET_CARD.json"
    )
    parser.add_argument(
        "--output",
        default="reports/final/AI_ASSISTED_SOC_REPORT.md"
    )
    args = parser.parse_args()

    prompt = read_text(args.prompt)

    final_prompt = f"""
{prompt}

DATASET CARD:
{read_text(args.dataset_card)[:8000]}

QUALITY REPORT:
{read_text(args.quality_report)[:8000]}

MODEL REPORT:
{read_text(args.model_report)[:8000]}

Buat laporan final berdasarkan bukti tersebut.
"""

    response = requests.post(
        args.ollama_url,
        json={
            "model": args.model,
            "prompt": final_prompt,
            "stream": False
        },
        timeout=600
    )

    response.raise_for_status()
    result = response.json().get("response", "").strip()

    if not result:
        raise SystemExit("Ollama returned empty response")

    Path(args.output).write_text(
        "# AI-Assisted SOC Report\n\n"
        f"> Local model: `{args.model}`\n\n"
        + result + "\n",
        encoding="utf-8"
    )

    print("[OK] AI SOC report generated:", args.output)

if __name__ == "__main__":
    main()
