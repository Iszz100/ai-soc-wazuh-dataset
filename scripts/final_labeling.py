#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

VALID_BINARY = {"benign", "malicious", "unlabeled"}

VALID_ATTACK_TYPES = {
    "benign",
    "recon",
    "auth_attack",
    "web_attack",
    "privilege_event",
    "fim_event",
    "suspicious_command",
    "network_anomaly",
    "unknown"
}


def read_jsonl(path):
    rows = []
    p = Path(path)

    if not p.exists():
        return rows

    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    return rows


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def final_label(row):
    label = row.get("label", "unlabeled")
    attack_type = row.get("attack_type", "unknown")

    if label not in VALID_BINARY:
        if attack_type == "benign":
            label = "benign"
        elif attack_type in VALID_ATTACK_TYPES and attack_type not in (
            "unknown", "benign"
        ):
            label = "malicious"
        else:
            label = "unlabeled"

    if attack_type not in VALID_ATTACK_TYPES:
        attack_type = "unknown"

    confidence = float(row.get("confidence", 0.0))

    if row.get("correlation_status") == "matched_alert":
        source = "ground_truth_correlated"
    elif row.get("correlation_status") == "ground_truth_without_alert":
        source = "ground_truth_only"
    elif row.get("correlation_status") == "alert_without_ground_truth":
        source = "wazuh_alert_only"
    else:
        source = row.get("ground_truth_source", "unknown")

    row["binary_label"] = label
    row["multi_class_label"] = attack_type
    row["source_of_truth"] = source
    row["confidence"] = confidence

    return row


def main():
    parser = argparse.ArgumentParser(
        description="Finalize labels for AI SOC dataset"
    )
    parser.add_argument(
        "--input",
        default="datasets/final/dataset_features.jsonl"
    )
    parser.add_argument(
        "--output",
        default="datasets/final/dataset_final.jsonl"
    )
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    labeled = [final_label(row) for row in rows]

    write_jsonl(args.output, labeled)

    print(json.dumps({
        "input_records": len(rows),
        "output_records": len(labeled),
        "output": args.output
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
