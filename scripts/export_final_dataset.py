#!/usr/bin/env python3
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True
        ).strip()
    except Exception:
        return "unknown"


def read_jsonl(path):
    rows = []

    with Path(path).open(
        "r", encoding="utf-8", errors="replace"
    ) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    return rows


def infer_schema(rows):
    fields = {}

    for row in rows:
        for key, value in row.items():
            fields.setdefault(key, set()).add(
                type(value).__name__
            )

    return {
        "fields": {
            key: sorted(list(types))
            for key, types in sorted(fields.items())
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="Export final AI SOC dataset"
    )

    parser.add_argument(
        "--input",
        default="datasets/final/dataset_final.jsonl"
    )
    parser.add_argument(
        "--output-dir",
        default="datasets/final"
    )
    parser.add_argument(
        "--version",
        default="v0.1.0"
    )

    args = parser.parse_args()

    rows = read_jsonl(args.input)

    if not rows:
        raise SystemExit("ERROR: Dataset kosong.")

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(rows)

    jsonl_out = outdir / "dataset.jsonl"
    csv_out = outdir / "dataset.csv"
    parquet_out = outdir / "dataset.parquet"
    schema_out = outdir / "schema.json"
    readme_out = outdir / "README_dataset.md"
    card_out = outdir / "DATASET_CARD.json"

    df.to_json(
        jsonl_out,
        orient="records",
        lines=True,
        force_ascii=False
    )

    df.to_csv(csv_out, index=False)
    df.to_parquet(parquet_out, index=False)

    generated = now_utc()
    commit = git_commit()

    schema = infer_schema(rows)
    schema["dataset_version"] = args.version
    schema["generated_at"] = generated
    schema["git_commit"] = commit

    schema_out.write_text(
        json.dumps(schema, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    label_dist = {
        str(k): int(v)
        for k, v in df["binary_label"].value_counts(
            dropna=False
        ).items()
    }

    class_dist = {
        str(k): int(v)
        for k, v in df["multi_class_label"].value_counts(
            dropna=False
        ).items()
    }

    card = {
        "dataset_name": "ai-soc-wazuh-dataset",
        "version": args.version,
        "generated_at": generated,
        "git_commit": commit,
        "source": "Wazuh lab evidence pack + ground truth",
        "total_records": len(df),
        "label_distribution": label_dist,
        "multi_class_distribution": class_dist,
        "formats": {
            "jsonl": str(jsonl_out),
            "csv": str(csv_out),
            "parquet": str(parquet_out),
            "schema": str(schema_out)
        },
        "intended_use": [
            "AI SOC training",
            "ML baseline",
            "LLM-assisted SOC experiment",
            "CEH/SOC lab portfolio"
        ],
        "not_for": [
            "attacking public systems",
            "training offensive malware generation",
            "production deployment without validation"
        ],
        "known_limitations": [
            "lab-generated dataset",
            "only six records have ground truth labels",
            "no successful ground truth to Wazuh correlation",
            "sanitized IP and sensitive fields",
            "class balance depends on scenario mix"
        ],
        "license": "CC BY 4.0"
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
{commit}

## Source
Dataset dibuat dari evidence pack lab Wazuh:
- Ground truth JSONL
- Wazuh alerts
- Archive sample
- Script execution log
- Correlation pipeline

## Files
- `dataset.jsonl` untuk LLM dan pipeline streaming
- `dataset.csv` untuk eksplorasi cepat
- `dataset.parquet` untuk efisiensi analitik
- `schema.json` untuk struktur field
- `DATASET_CARD.json` untuk metadata dataset

## Label Distribution
{json.dumps(label_dist, indent=2, ensure_ascii=False)}

## Multi-Class Distribution
{json.dumps(class_dist, indent=2, ensure_ascii=False)}

## Ethical Use
Dataset ini hanya untuk edukasi, riset defensif,
AI SOC, dan lab legal. Tidak untuk menyerang sistem publik.

## Known Limitations
- Dataset berasal dari lab tertutup.
- Hanya enam record memiliki Ground Truth.
- Belum ada korelasi Ground Truth dan Wazuh yang berhasil.
- Distribusi kelas belum mewakili lingkungan produksi.
- Data perlu review sebelum publikasi eksternal.

## Leakage Warning
Jangan gunakan `run_id`, `scenario_id`, `payload_id`,
`expected_label`, `label`, `binary_label`, atau
`multi_class_label` sebagai fitur input training langsung.
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
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
