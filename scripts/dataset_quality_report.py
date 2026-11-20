#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from collections import Counter

LEAKAGE_FIELDS = {
    "expected_label", "label", "binary_label",
    "multi_class_label", "scenario_id",
    "run_id", "payload_id"
}

def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]

def git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="datasets/final/dataset_final.jsonl")
    parser.add_argument("--archive-records", type=int, default=0)
    parser.add_argument("--report-json", default="reports/chapter9/dataset_quality_report.json")
    parser.add_argument("--report-md", default="reports/chapter9/dataset_quality_report.md")
    args = parser.parse_args()

    rows = read_jsonl(args.input)

    if not rows:
        raise SystemExit("Dataset kosong")

    labels = Counter(r.get("binary_label", "unlabeled") for r in rows)
    classes = Counter(r.get("multi_class_label", "unknown") for r in rows)
    scenarios = Counter(r.get("scenario_id", "unknown") for r in rows)
    statuses = Counter(r.get("correlation_status", "unknown") for r in rows)
    sources = Counter(r.get("source_of_truth", "unknown") for r in rows)

    required = [
        "timestamp", "agent_name", "rule_id",
        "full_log", "binary_label", "multi_class_label"
    ]

    missing = {
        field: sum(
            r.get(field) in (None, "", "unknown")
            for r in rows
        )
        for field in required
    }

    seen = set()
    duplicates = 0

    for r in rows:
        key = (
            r.get("timestamp"),
            r.get("agent_name"),
            r.get("rule_id"),
            r.get("full_log")
        )
        if key in seen:
            duplicates += 1
        seen.add(key)

    present = sorted(
        LEAKAGE_FIELDS.intersection(
            key for r in rows for key in r
        )
    )

    benign = labels.get("benign", 0)
    malicious = labels.get("malicious", 0)

    imbalance = (
        max(benign, malicious) / min(benign, malicious)
        if benign and malicious else None
    )

    low_confidence = sum(
        r.get("correlation_status") == "matched_alert"
        and float(r.get("confidence", 0)) <= 0.5
        for r in rows
    )

    unmatched = statuses.get("alert_without_ground_truth", 0)
    gt_only = statuses.get("ground_truth_without_alert", 0)
    unlabeled = labels.get("unlabeled", 0)

    limitations = []

    if unmatched:
        limitations.append(
            f"{unmatched} alerts belum memiliki ground truth; "
            "belum tentu semuanya false positive."
        )

    if gt_only:
        limitations.append(
            f"{gt_only} ground truth tidak memiliki alert Wazuh yang cocok; "
            "perlu pemeriksaan detection gap."
        )

    if low_confidence:
        limitations.append(
            f"{low_confidence} korelasi memiliki confidence rendah "
            "dan memerlukan review analis."
        )

    if imbalance is not None and imbalance > 3:
        limitations.append(
            f"Class imbalance sebesar {imbalance:.1f}:1."
        )

    if unlabeled:
        limitations.append(
            f"{unlabeled} record masih unlabeled."
        )

    if args.archive_records == 0:
        limitations.append(
            "Archive sample tidak tersedia pada run ini."
        )

    report = {
        "dataset": args.input,
        "record_count": len(rows),
        "binary_label_distribution": dict(labels),
        "multi_class_distribution": dict(classes),
        "scenario_distribution": dict(scenarios),
        "correlation_status": dict(statuses),
        "source_of_truth_distribution": dict(sources),
        "class_imbalance_ratio": imbalance,
        "duplicate_count": duplicates,
        "missing_values": missing,
        "alerts_without_ground_truth": unmatched,
        "ground_truth_without_alert": gt_only,
        "unlabeled_records": unlabeled,
        "low_confidence_correlations": low_confidence,
        "archive_records": args.archive_records,
        "leakage_fields_present": present,
        "leakage_warning": (
            "Exclude run_id, scenario_id, payload_id, expected_label, "
            "label, binary_label and multi_class_label from model input. "
            "Label fields remain available as prediction targets."
        ),
        "known_limitations": limitations,
        "reproducibility": {
            "git_commit": git_commit(),
            "dataset_sha256": sha256(args.input)
        },
        "quality_status": (
            "review_required"
            if unlabeled or low_confidence or unmatched or gt_only
            or duplicates
            else "pass"
        )
    }

    out = Path(args.report_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    md = [
        "# AI SOC Dataset Quality Report",
        "",
        f"- Dataset: `{args.input}`",
        f"- Total records: {len(rows)}",
        f"- Quality status: **{report['quality_status']}**",
        f"- Duplicate records: {duplicates}",
        f"- Class imbalance ratio: {imbalance}",
        "",
        "## Binary Label Distribution"
    ]

    md.extend(f"- {k}: {v}" for k, v in labels.items())

    md += ["", "## Multi-Class Distribution"]
    md.extend(f"- {k}: {v}" for k, v in classes.items())

    md += ["", "## Scenario Distribution"]
    md.extend(f"- {k}: {v}" for k, v in scenarios.items())

    md += ["", "## Correlation Status"]
    md.extend(f"- {k}: {v}" for k, v in statuses.items())

    md += ["", "## Source of Truth"]
    md.extend(f"- {k}: {v}" for k, v in sources.items())

    md += [
        "",
        "## Data Quality",
        f"- Missing values: `{json.dumps(missing)}`",
        f"- Low-confidence correlations: {low_confidence}",
        f"- Archive records: {args.archive_records}",
        f"- Leakage fields: `{present}`",
        "",
        "## Leakage Warning",
        report["leakage_warning"],
        "",
        "## Known Limitations"
    ]

    md.extend(f"- {item}" for item in limitations)

    md += [
        "",
        "## Reproducibility",
        f"- Git commit: `{report['reproducibility']['git_commit']}`",
        f"- SHA256: `{report['reproducibility']['dataset_sha256']}`",
        "",
        "Validasi mencatat kondisi dataset sebenarnya. "
        "Unlabeled dan low-confidence tidak boleh dianggap sebagai "
        "label yang sudah terverifikasi."
    ]

    Path(args.report_md).write_text(
        "\n".join(md) + "\n",
        encoding="utf-8"
    )

    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
