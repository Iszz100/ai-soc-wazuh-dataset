#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

VALID_BINARY = {"benign", "malicious", "unlabeled"}

VALID_ATTACK_TYPES = {
    "benign", "recon", "auth_attack", "web_attack",
    "privilege_event", "fim_event", "suspicious_command",
    "network_anomaly", "unknown"
}


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def final_label(row):
    label = row.get("label", "unlabeled")
    attack = row.get("attack_type", "unknown")

    if attack not in VALID_ATTACK_TYPES:
        attack = "unknown"

    if label not in VALID_BINARY:
        if attack == "benign":
            label = "benign"
        elif attack != "unknown":
            label = "malicious"
        else:
            label = "unlabeled"

    status = row.get("correlation_status")

    source = {
        "matched_alert": "ground_truth_correlated",
        "ground_truth_without_alert": "ground_truth_only",
        "alert_without_ground_truth": "wazuh_alert_only"
    }.get(status, row.get("ground_truth_source", "unknown"))

    try:
        confidence = float(row.get("confidence", 0.0))
    except (ValueError, TypeError):
        confidence = 0.0

    row["binary_label"] = label
    row["multi_class_label"] = attack
    row["source_of_truth"] = source
    row["confidence"] = confidence

    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="datasets/final/dataset_features.jsonl")
    parser.add_argument("--output", default="datasets/final/dataset_final.jsonl")
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    labeled = [final_label(row) for row in rows]

    write_jsonl(args.output, labeled)

    print(json.dumps({
        "input_records": len(rows),
        "output_records": len(labeled),
        "output": args.output
    }, indent=2))


if __name__ == "__main__":
    main()
