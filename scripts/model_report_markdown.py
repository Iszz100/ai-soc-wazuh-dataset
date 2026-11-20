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

    data = json.loads(Path(args.input).read_text())
    lines = [
        "# Model Baseline Report",
        "",
        f"- Dataset: `{data.get('dataset')}`",
        f"- Dataset records: {data.get('dataset_records')}",
        f"- Labeled records: {data.get('records_used')}",
        "",
        "## Label Distribution"
    ]

    for k, v in data.get("label_distribution", {}).items():
        lines.append(f"- {k}: {v}")

    sup = data.get("supervised_models", {})

    lines += [
        "",
        "## Supervised Models",
        f"- Status: {sup.get('status')}"
    ]

    if sup.get("status") == "skipped":
        lines.append(f"- Reason: {sup.get('reason')}")

    for name, result in sup.get("models", {}).items():
        lines += [
            "",
            f"### {name}",
            f"- Status: {result.get('status')}",
            f"- Train records: {result.get('train_records')}",
            f"- Test records: {result.get('test_records')}",
            f"- False Positive Rate: {fmt(result.get('false_positive_rate'))}",
            f"- False Negative Rate: {fmt(result.get('false_negative_rate'))}",
            f"- Confusion Matrix: `{result.get('confusion_matrix')}`"
        ]

    iso = data.get("isolation_forest", {})

    lines += [
        "",
        "## Isolation Forest",
        f"- Status: {iso.get('status')}",
        f"- Records: {iso.get('records')}",
        f"- Anomalies: {iso.get('anomaly_count')}",
        f"- Normal: {iso.get('normal_count')}",
        f"- Score minimum: {fmt(iso.get('score_min'))}",
        f"- Score maximum: {fmt(iso.get('score_max'))}",
        f"- Note: {iso.get('note')}"
    ]

    rule = data.get("rule_based_baseline", {})

    lines += [
        "",
        "## Rule-Based Baseline",
        f"- Status: {rule.get('status')}",
        f"- Rule: {rule.get('rule')}",
        f"- Confusion Matrix: `{rule.get('confusion_matrix')}`",
        f"- False Positive Rate: {fmt(rule.get('false_positive_rate'))}",
        f"- False Negative Rate: {fmt(rule.get('false_negative_rate'))}",
        "",
        "| Class | Precision | Recall | F1-score | Support |",
        "|---|---:|---:|---:|---:|"
    ]

    for cls in ["benign", "malicious"]:
        r = rule.get("classification_report", {}).get(cls, {})
        lines.append(
            f"| {cls} | {fmt(r.get('precision'))} | "
            f"{fmt(r.get('recall'))} | "
            f"{fmt(r.get('f1-score'))} | "
            f"{r.get('support', 0)} |"
        )

    lines += [
        "",
        "## Evaluation Notes",
        "- Dataset kecil dan distribusi kelas belum seimbang.",
        "- Supervised model belum dapat dievaluasi karena jumlah benign tidak mencukupi.",
        "- Isolation Forest merupakan anomaly detection baseline, bukan classifier final.",
        "- Rule-based baseline hanya pembanding sederhana.",
        "- Hasil belum dapat digunakan sebagai bukti kesiapan produksi.",
        "",
        "## Conclusion",
        "Eksperimen baseline berhasil dijalankan. "
        "Pengembangan selanjutnya membutuhkan lebih banyak data benign, "
        "label terverifikasi, dan evaluasi ulang."
    ]

    Path(args.output).write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    print("[OK] Model report:", args.output)

if __name__ == "__main__":
    main()
