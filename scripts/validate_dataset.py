#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from pathlib import Path


REQUIRED = [
    "event_id",
    "timestamp",
    "agent_id",
    "agent_name",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "destination_user",
    "rule_id",
    "rule_level",
    "rule_description",
    "rule_groups",
    "raw_event",
    "scenario_id",
    "attack_type",
    "mitre_tactic",
    "mitre_technique",
    "label",
    "confidence",
    "ground_truth_source",
    "correlation_status"
]

LABELS = {"benign", "malicious", "unlabeled"}
STATUSES = {"matched", "unmatched", "ambiguous"}


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default="datasets/correlated_alerts.jsonl"
    )

    args = parser.parse_args()

    path = Path(args.input)

    if not path.exists():
        parser.error(f"Dataset not found: {path}")

    rows = []
    errors = []

    with path.open(encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                errors.append(f"Line {number}: Invalid JSON")

    ids = []
    labels = Counter()
    statuses = Counter()

    for index, row in enumerate(rows, 1):

        missing = [
            field for field in REQUIRED
            if field not in row
        ]

        if missing:
            errors.append(
                f"Record {index}: Missing {missing}"
            )
            continue

        ids.append(row["event_id"])

        if row["label"] not in LABELS:
            errors.append(
                f"Record {index}: Invalid label"
            )

        if row["correlation_status"] not in STATUSES:
            errors.append(
                f"Record {index}: Invalid correlation status"
            )

        confidence = row["confidence"]

        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not 0 <= confidence <= 1
        ):
            errors.append(
                f"Record {index}: Invalid confidence"
            )

        if not isinstance(row["rule_groups"], list):
            errors.append(
                f"Record {index}: rule_groups must be a list"
            )

        if row["correlation_status"] == "matched":
            if not row.get("ground_truth_run_id"):
                errors.append(
                    f"Record {index}: Missing Ground Truth run ID"
                )

            if row["label"] == "unlabeled":
                errors.append(
                    f"Record {index}: Matched event is unlabeled"
                )

        if row["correlation_status"] != "matched":
            if row["label"] != "unlabeled":
                errors.append(
                    f"Record {index}: Unmatched event has a label"
                )

        labels[row["label"]] += 1
        statuses[row["correlation_status"]] += 1

    duplicates = [
        event_id
        for event_id, count in Counter(ids).items()
        if count > 1
    ]

    if duplicates:
        errors.append(
            f"Duplicate event IDs: {duplicates}"
        )

    print("\n=== DATASET QUALITY REPORT ===")
    print("Total records:", len(rows))
    print("Unique event IDs:", len(set(ids)))
    print("Label distribution:", dict(labels))
    print("Correlation status:", dict(statuses))
    print("Validation errors:", len(errors))

    if errors:
        print("\nValidation: FAILED")

        for error in errors:
            print("-", error)

    else:
        print("\nValidation: PASSED")


if __name__ == "__main__":
    main()
