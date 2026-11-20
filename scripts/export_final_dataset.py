#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

import pandas as pd


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def write_jsonl(path, rows):
    with Path(path).open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True
        ).strip()
    except Exception:
        return "unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="datasets/final/dataset_final.jsonl")
    parser.add_argument("--output-dir", default="datasets/final")
    parser.add_argument("--version", default="v0.1.0")
    args = parser.parse_args()

    rows = read_jsonl(args.input)

    if not rows:
        raise SystemExit("Dataset final kosong. Export dibatalkan.")

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(rows)

    jsonl_out = out / "dataset.jsonl"
    csv_out = out / "dataset.csv"
    parquet_out = out / "dataset.parquet"
    schema_out = out / "schema.json"
    card_out = out / "DATASET_CARD.json"
    readme_out = out / "README_dataset.md"

    write_jsonl(jsonl_out, rows)
    df.to_csv(csv_out, index=False)
    df.to_parquet(parquet_out, index=False, engine="pyarrow")

    fields = {}

    for row in rows:
        for key, value in row.items():
            fields.setdefault(key, set()).add(
                type(value).__name__ if value is not None else "null"
            )

    schema = {
        "dataset_name": "ai-soc-wazuh-dataset",
        "version": args.version,
        "record_count": len(rows),
        "fields": {
            k: sorted(v) for k, v in sorted(fields.items())
        }
    }

    schema_out.write_text(
        json.dumps(schema, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    labels = Counter(r.get("binary_label", "unlabeled") for r in rows)
    classes = Counter(r.get("multi_class_label", "unknown") for r in rows)

    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    card = {
        "dataset_name": "ai-soc-wazuh-dataset",
        "version": args.version,
        "generated_at": generated,
        "git_commit": git_commit(),
        "purpose": "Educational defensive AI SOC dataset",
        "record_count": len(rows),
        "sources": [
            "Ground Truth JSONL",
            "Wazuh Dashboard CSV export",
            "Wazuh archive sample when available"
        ],
        "binary_label_distribution": dict(labels),
        "multi_class_distribution": dict(classes),
        "intended_use": [
            "Defensive AI SOC research",
            "Security event classification",
            "Educational lab analysis"
        ],
        "not_for": [
            "Attacking public systems",
            "Offensive malware generation",
            "Production deployment without validation"
        ],
        "known_limitations": [
            "Lab-generated dataset",
            "Some Dashboard exports omit IP and port fields",
            "Some correlations require analyst review",
            "Unmatched alerts remain unlabeled",
            "Class balance depends on scenario mix"
        ]
    }

    card_out.write_text(
        json.dumps(card, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    readme = f"""# AI SOC Wazuh Dataset

## Version
{args.version}

## Generated
{generated}

## Git Commit
{card['git_commit']}

## Records
{len(rows)}

## Source
- Ground Truth JSONL
- Wazuh Dashboard export
- Archive sample when available
- Correlation and preprocessing pipeline

## Binary Label Distribution
{json.dumps(dict(labels), indent=2)}

## Multi-class Distribution
{json.dumps(dict(classes), indent=2)}

## Files
- dataset.jsonl: LLM and streaming pipeline
- dataset.csv: exploration and spreadsheet
- dataset.parquet: efficient analytics
- schema.json: field contract
- DATASET_CARD.json: dataset metadata

## Ethical Use
Educational, defensive research, and legal lab use only.

## Known Limitations
- Some events do not contain IP or port information.
- Unmatched alerts remain unlabeled.
- Low-confidence correlations require analyst review.

## Leakage Warning
Do not use run_id, scenario_id, payload_id, expected_label,
label, binary_label, or multi_class_label as direct training features.
"""

    readme_out.write_text(readme, encoding="utf-8")

    print(json.dumps({
        "records": len(df),
        "jsonl": str(jsonl_out),
        "csv": str(csv_out),
        "parquet": str(parquet_out),
        "schema": str(schema_out),
        "dataset_card": str(card_out),
        "readme": str(readme_out)
    }, indent=2))


if __name__ == "__main__":
    main()
