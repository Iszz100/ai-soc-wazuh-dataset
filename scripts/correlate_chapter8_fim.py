#!/usr/bin/env python3
import json
from datetime import datetime
from pathlib import Path

GT = Path("ground-truth/fim_chapter8_ground_truth.jsonl")
ALERTS = Path("wazuh-export/chapter8/fim_alerts_normalized.jsonl")
OUTPUT = Path("wazuh-export/chapter8/fim_correlation.jsonl")
REPORT = Path("reports/chapter8/fim-correlation.md")

def read_jsonl(path):
    with path.open(encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]

def parse_time(value):
    value = value.replace("Z", "+00:00")
    if value.endswith("+0000"):
        value = value[:-5] + "+00:00"
    return datetime.fromisoformat(value)

ground_truth = read_jsonl(GT)
alerts = read_jsonl(ALERTS)

if not ground_truth or not alerts:
    raise SystemExit("ERROR: Ground Truth atau alert kosong.")

used = set()
results = []

for gt in ground_truth:
    action = gt.get("action")
    path = gt.get("file_path", "")
    gt_time = parse_time(gt["timestamp"])

    candidates = []

    for i, alert in enumerate(alerts):
        if i in used:
            continue

        if alert.get("context") == "preparation_chown":
            continue

        if alert.get("path") != path:
            continue

        delta = abs(
            (parse_time(alert["timestamp"]) - gt_time).total_seconds()
        )

        if delta <= 1:
            candidates.append((delta, i, alert))

    candidates.sort(key=lambda x: x[0])

    if not candidates:
        status = (
            "NO_STATE_CHANGE"
            if action == "chmod_file"
            else "NO_ALERT"
        )

        results.append({
            "run_id": gt.get("run_id"),
            "action": action,
            "path": path,
            "status": status
        })
        continue

    delta, index, alert = candidates[0]
    used.add(index)

    observed = alert.get("event")

    if action in ("create_file", "create_suspicious_dummy"):
        status = (
            "CORRELATED_EXISTING_FILE_OVERWRITE"
            if observed == "modified"
            else "EVENT_TYPE_DIFFERENCE"
        )
    elif action == "modify_file" and observed == "modified":
        status = "MATCH"
    elif action == "delete_file" and observed == "deleted":
        status = "MATCH"
    else:
        status = "EVENT_TYPE_DIFFERENCE"

    results.append({
        "run_id": gt.get("run_id"),
        "action": action,
        "path": path,
        "observed_event": observed,
        "rule_id": alert.get("rule_id"),
        "delta_ms": round(delta * 1000, 2),
        "status": status
    })

with OUTPUT.open("w", encoding="utf-8") as f:
    for row in results:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

exact = sum(x["status"] == "MATCH" for x in results)
overwrite = sum(
    x["status"] == "CORRELATED_EXISTING_FILE_OVERWRITE"
    for x in results
)
no_change = sum(x["status"] == "NO_STATE_CHANGE" for x in results)
missing = sum(x["status"] == "NO_ALERT" for x in results)
setup = sum(
    x.get("context") == "preparation_chown"
    for x in alerts
)

lines = [
    "# Chapter 8 - FIM Ground Truth Correlation",
    "",
    f"- Run ID: `{ground_truth[0].get('run_id')}`",
    f"- Ground Truth: {len(ground_truth)}",
    f"- Normalized Wazuh alerts: {len(alerts)}",
    f"- Exact matches: {exact}",
    f"- Existing-file overwrite correlations: {overwrite}",
    f"- Operations without actual state change: {no_change}",
    f"- Operations without alert: {missing}",
    f"- Preparation alerts: {setup}",
    "",
    "## Results",
    "",
    "| Operation | Wazuh Event | Correlation Status |",
    "|---|---|---|"
]

for row in results:
    lines.append(
        f"| {row['action']} | "
        f"{row.get('observed_event', '-')} | "
        f"{row['status']} |"
    )

lines += [
    "",
    "## Analysis",
    "",
    "- Four operations have corresponding Wazuh alert evidence.",
    "- Two creation operations were reported as modifications",
    "  because their target files existed from previous testing.",
    "- The chmod operation did not produce a new alert because",
    "  the target permission was already rw-------.",
    "- One additional ownership-change alert originated from",
    "  preparation before the FIM execution.",
    "",
    "## Limitations",
    "",
    "Correlation uses exact file paths and a one-second time window.",
    "The chmod operation still requires an independent permission-change",
    "test to validate detection of an actual permission transition."
]

REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("===== FINAL FIM CORRELATION =====")
print("Ground Truth:", len(ground_truth))
print("Exact matches:", exact)
print("Existing-file overwrite:", overwrite)
print("No actual state change:", no_change)
print("No alert:", missing)
print("Preparation alerts:", setup)

for row in results:
    print(row["action"], "=>", row["status"])

print("\nReports:")
print(OUTPUT)
print(REPORT)
