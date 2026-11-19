#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def fmt(value):
    if value is None:
        return "N/A"
    if isinstance(value, (int, float)):
        return f"{value:.4f}"
    return str(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="reports/final/model_baseline_report.json"
    )
    parser.add_argument(
        "--output",
        default="reports/final/model_baseline_report.md"
    )
    args = parser.parse_args()

    data = json.loads(
        Path(args.input).read_text(encoding="utf-8")
    )

    lines = [
        "# Model Baseline Report",
        "",
        f"- Dataset: `{data.get('dataset')}`",
        f"- Records used: {data.get('records_used')}",
        "",
        "## Label Distribution"
    ]

    for key, value in data.get("label_distribution", {}).items():
        lines.append(f"- {key}: {value}")

    lines += ["", "## Supervised Models"]

    for name, result in data.get("supervised_models", {}).items():
        lines += ["", f"### {name}", ""]

        if result.get("status") != "trained":
            lines.append(f"- Status: {result.get('status')}")
            lines.append(f"- Reason: {result.get('reason', '-')}")
            continue

        lines += [
            f"- Train records: {result.get('train_records')}",
            f"- Test records: {result.get('test_records')}",
            f"- FPR: {fmt(result.get('false_positive_rate'))}",
            f"- FNR: {fmt(result.get('false_negative_rate'))}",
            f"- Confusion matrix: `{result.get('confusion_matrix')}`",
            "",
            "| Class | Precision | Recall | F1-score | Support |",
            "|---|---:|---:|---:|---:|"
        ]

        report = result.get("classification_report", {})

        for cls in ["benign", "malicious"]:
            r = report.get(cls, {})
            lines.append(
                f"| {cls} | {fmt(r.get('precision'))} | "
                f"{fmt(r.get('recall'))} | "
                f"{fmt(r.get('f1-score'))} | "
                f"{r.get('support', 0)} |"
            )

    iso = data.get("isolation_forest", {})
    lines += ["", "## Isolation Forest"]

    for key, value in iso.items():
        lines.append(f"- {key}: {value}")

    rb = data.get("rule_based_baseline", {})
    lines += [
        "",
        "## Rule-Based Baseline",
        f"- Status: {rb.get('status')}",
        f"- Rule: `{rb.get('rule')}`",
        f"- FPR: {fmt(rb.get('false_positive_rate'))}",
        f"- FNR: {fmt(rb.get('false_negative_rate'))}",
        f"- Confusion matrix: `{rb.get('confusion_matrix', '-')}`",
        "",
        "## Critical Notes",
        "- Do not interpret accuracy alone.",
        "- False negatives are important in SOC detection.",
        "- False positives increase analyst workload.",
        "- Compare ML models with rule-based baseline.",
        "- Small datasets demonstrate pipeline execution, "
        "not production performance.",
        "- Skipped models are not evidence of successful training."
    ]

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("Report written:", output)


if __name__ == "__main__":
    main()
