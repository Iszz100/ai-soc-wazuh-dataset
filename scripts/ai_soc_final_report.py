#!/usr/bin/env python3
import argparse
from pathlib import Path

import requests


def read_text(path):
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"File tidak ditemukan: {path}")
    return p.read_text(encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser(
        description="Generate AI-assisted SOC report using Ollama"
    )
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
    quality_report = read_text(args.quality_report)
    model_report = read_text(args.model_report)
    dataset_card = read_text(args.dataset_card)

    final_prompt = f"""
{prompt}

DATASET_CARD:
{dataset_card[:8000]}

QUALITY_REPORT:
{quality_report[:8000]}

MODEL_REPORT:
{model_report[:8000]}

Buat laporan final berbasis data di atas.
/no_think
"""

    final_prompt = final_prompt.replace("/no_think", "")

    response = requests.post(
        args.ollama_url,
        json={
            "model": args.model,
            "prompt": final_prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0.2,
                "num_predict": 2500
            }
        },
        timeout=(15, 900)
    )
    response.raise_for_status()

    result = response.json()
    report = result.get("response", "").strip()

    # Buang bagian thinking jika masih muncul di response.
    if "</think>" in report:
        report = report.rsplit("</think>", 1)[-1].strip()

    report = report.replace("<think>", "").strip()

    required_sections = [
        f"## {i}." for i in range(1, 9)
    ]

    missing_sections = [
        section for section in required_sections
        if section not in report
    ]

    if missing_sections:
        raise SystemExit(
            f"ERROR: Laporan belum lengkap. "
            f"Bagian hilang: {missing_sections}"
        )

    if not report:
        print("Ollama response metadata:")
        print({
            "done": result.get("done"),
            "done_reason": result.get("done_reason"),
            "response_chars": len(result.get("response", "")),
            "thinking_chars": len(result.get("thinking", "")),
            "eval_count": result.get("eval_count")
        })
        raise SystemExit("ERROR: Output final Ollama masih kosong.")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report + "\n", encoding="utf-8")

    print("AI-assisted SOC report written to:", output)
    print("Characters:", len(report))


if __name__ == "__main__":
    main()
