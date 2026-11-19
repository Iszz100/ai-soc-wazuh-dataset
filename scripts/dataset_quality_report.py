#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path

LEAKAGE_FIELDS = [
    "expected_label",
    "label",
    "binary_label",
    "multi_class_label",
    "scenario_id",
    "run_id",
    "payload_id"
]

def read_jsonl(path):
    rows = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def duplicate_count(rows):
    seen = set()
    duplicates = 0

    for row in rows:
        key = (
            row.get("timestamp"),
            row.get("agent_name"),
            row.get("rule_id"),
            row.get("full_log")
        )
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)

    return duplicates

def missing_count(rows, field):
    return sum(
        row.get(field) in (None, "", "unknown")
        for row in rows
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="datasets/final/dataset_final.jsonl"
    )
    parser.add_argument(
        "--report-json",
        default="reports/chapter9/dataset_quality_report.json"
    )
    parser.add_argument(
        "--report-md",
        default="reports/chapter9/dataset-quality-report.md"
    )
    args = parser.parse_args()

    rows = read_jsonl(args.input)

    labels = Counter(r.get("binary_label", "unknown") for r in rows)
    classes = Counter(r.get("multi_class_label", "unknown") for r in rows)
    correlations = Counter(
        r.get("correlation_status", "unknown") for r in rows
    )
    sources = Counter(
        r.get("source_of_truth", "unknown") for r in rows
    )
    scenarios = Counter(
        r.get("scenario_id", "unknown") for r in rows
    )

    ids = [r.get("event_id") for r in rows]

    missing = {
        field: missing_count(rows, field)
        for field in [
            "timestamp", "agent_name", "rule_id",
            "full_log", "binary_label",
            "multi_class_label", "confidence"
        ]
    }

    report = {
        "dataset": args.input,
        "total_records": len(rows),
        "unique_event_ids": len(set(ids)),
        "duplicate_count": duplicate_count(rows),
        "label_distribution": dict(labels),
        "multi_class_distribution": dict(classes),
        "correlation_distribution": dict(correlations),
        "source_of_truth_distribution": dict(sources),
        "scenario_distribution": dict(scenarios),
        "missing": missing,
        "leakage_warning": [
            f"{field} must not be used as a direct model input"
            for field in LEAKAGE_FIELDS
        ],
        "known_limitations": [
            "Only six records have Ground Truth labels.",
            "No successful Ground Truth-to-Wazuh correlation.",
            "Class imbalance is significant.",
            "Unlabeled alerts require analyst review.",
            "Dataset requires additional controlled experiments."
        ]
    }

    out_json = Path(args.report_json)
    out_md = Path(args.report_md)

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    lines = [
        "# Dataset Quality Report",
        "",
        f"- Dataset: `{args.input}`",
        f"- Total records: {len(rows)}",
        f"- Unique IDs: {len(set(ids))}",
        f"- Duplicate count: {report['duplicate_count']}",
        "",
        "## Label Distribution"
    ]

    for k, v in labels.items():
        lines.append(f"- {k}: {v}")

    lines += ["", "## Multi-Class Distribution"]

    for k, v in classes.items():
        lines.append(f"- {k}: {v}")

    lines += ["", "## Correlation Status"]

    for k, v in correlations.items():
        lines.append(f"- {k}: {v}")

    lines += ["", "## Source of Truth"]

    for k, v in sources.items():
        lines.append(f"- {k}: {v}")

    lines += ["", "## Scenario Distribution"]

    for k, v in scenarios.items():
        lines.append(f"- {k}: {v}")

    lines += ["", "## Missing Values"]

    for k, v in missing.items():
        lines.append(f"- {k}: {v}")

    lines += ["", "## Leakage Warning"]

    for item in report["leakage_warning"]:
        lines.append(f"- {item}")

    lines += ["", "## Known Limitations"]

    for item in report["known_limitations"]:
        lines.append(f"- {item}")

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "records": len(rows),
        "duplicates": report["duplicate_count"],
        "json_report": str(out_json),
        "markdown_report": str(out_md)
    }, indent=2))

if __name__ == "__main__":
    main()
