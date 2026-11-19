#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


def read_jsonl(path):
    rows = []
    p = Path(path)
    if not p.exists():
        return rows

    with p.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def parse_time(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def stable_id(prefix, *parts):
    text = "|".join(str(p) for p in parts)
    return prefix + hashlib.sha256(text.encode()).hexdigest()[:16]


def extract_first_ip(text):
    if not text:
        return None
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))
    return m.group(0) if m else None


def normalize_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    full_log = alert.get("full_log", "")
    raw = json.dumps(alert, ensure_ascii=False)

    source_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or data.get("source_ip")
        or extract_first_ip(full_log)
        or extract_first_ip(raw)
    )

    mitre = rule.get("mitre", {})
    return {
        "event_id": stable_id(
            "evt-", alert.get("timestamp"),
            agent.get("name"), rule.get("id"), full_log[:200]
        ),
        "timestamp": alert.get("timestamp"),
        "agent_name": agent.get("name", "unknown"),
        "source_ip": source_ip,
        "destination_ip": (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("destination_ip")
        ),
        "rule_id": str(rule.get("id", "")),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description", ""),
        "rule_groups": rule.get("groups", []),
        "rule_mitre_id": mitre.get("id", []),
        "location": alert.get("location", ""),
        "full_log": full_log,
        "raw_alert": raw
    }


def text_contains_any(text, values):
    return any(v and str(v) in text for v in values)


def correlate(gt_rows, alert_rows, window_seconds):
    normalized = []

    for raw in alert_rows:
        alert = normalize_alert(raw)
        alert["_dt"] = parse_time(alert["timestamp"])
        normalized.append(alert)

    final_rows = []
    matched_ids = set()

    for gt in gt_rows:
        gt_time = parse_time(
            gt.get("timestamp")
            or gt.get("start_time")
            or gt.get("created_at")
        )
        if not gt_time:
            continue

        start = gt_time - timedelta(seconds=window_seconds)
        end = gt_time + timedelta(seconds=window_seconds)

        targets = [
            gt.get("target_host"),
            gt.get("target"),
            gt.get("target_ip"),
            gt.get("target_web"),
            gt.get("payload_id"),
            gt.get("scenario_id"),
            gt.get("run_id")
        ]

        candidates = []

        for alert in normalized:
            adt = alert.get("_dt")
            if not adt or not start <= adt <= end:
                continue

            text = json.dumps(
                {k: v for k, v in alert.items() if k != "_dt"},
                ensure_ascii=False
            )
            score = 0

            if text_contains_any(text, targets):
                score += 2
            if gt.get("attack_type") and gt["attack_type"] in text:
                score += 2
            if gt.get("scenario_id") and gt["scenario_id"] in text:
                score += 3
            if (
                gt.get("payload_id")
                and gt["payload_id"] != "none"
                and gt["payload_id"] in text
            ):
                score += 3

            if score > 0:
                candidates.append((score, alert))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            best_score, best = candidates[0]
            matched_ids.add(best["event_id"])

            final_rows.append({
                "event_id": stable_id(
                    "final-", gt.get("run_id"),
                    gt.get("scenario_id"), best["event_id"]
                ),
                "timestamp": best["timestamp"],
                "agent_name": best["agent_name"],
                "source_ip": best["source_ip"],
                "destination_ip": best["destination_ip"],
                "rule_id": best["rule_id"],
                "rule_level": best["rule_level"],
                "rule_description": best["rule_description"],
                "full_log": best["full_log"],
                "scenario_id": gt.get("scenario_id", "unknown"),
                "run_id": gt.get("run_id", "unknown"),
                "attack_type": gt.get("attack_type", "unknown"),
                "mitre_tactic": gt.get("mitre_tactic", "unknown"),
                "mitre_technique": gt.get("mitre_technique", "unknown"),
                "label": gt.get("expected_label", "unlabeled"),
                "confidence": 1.0 if best_score >= 5 else 0.8,
                "ground_truth_source": "ground_truth_correlated",
                "correlation_status": "matched_alert",
                "raw_alert": best["raw_alert"]
            })
        else:
            final_rows.append({
                "event_id": stable_id(
                    "final-", gt.get("run_id"),
                    gt.get("scenario_id"), gt_time.isoformat()
                ),
                "timestamp": gt_time.isoformat(),
                "agent_name": "unknown",
                "source_ip": None,
                "destination_ip": gt.get("target_host") or gt.get("target_ip"),
                "rule_id": None,
                "rule_level": None,
                "rule_description": None,
                "full_log": json.dumps(gt, ensure_ascii=False),
                "scenario_id": gt.get("scenario_id", "unknown"),
                "run_id": gt.get("run_id", "unknown"),
                "attack_type": gt.get("attack_type", "unknown"),
                "mitre_tactic": gt.get("mitre_tactic", "unknown"),
                "mitre_technique": gt.get("mitre_technique", "unknown"),
                "label": gt.get("expected_label", "unlabeled"),
                "confidence": 1.0,
                "ground_truth_source": "ground_truth_only",
                "correlation_status": "ground_truth_without_alert",
                "raw_alert": None
            })

    for alert in normalized:
        if alert["event_id"] not in matched_ids:
            final_rows.append({
                "event_id": stable_id("final-unmatched-", alert["event_id"]),
                "timestamp": alert["timestamp"],
                "agent_name": alert["agent_name"],
                "source_ip": alert["source_ip"],
                "destination_ip": alert["destination_ip"],
                "rule_id": alert["rule_id"],
                "rule_level": alert["rule_level"],
                "rule_description": alert["rule_description"],
                "full_log": alert["full_log"],
                "scenario_id": "unmatched",
                "run_id": "unknown",
                "attack_type": "unknown",
                "mitre_tactic": "unknown",
                "mitre_technique": "unknown",
                "label": "unlabeled",
                "confidence": 0.0,
                "ground_truth_source": "wazuh_alert_only",
                "correlation_status": "alert_without_ground_truth",
                "raw_alert": alert["raw_alert"]
            })

    return final_rows


def main():
    parser = argparse.ArgumentParser(
        description="Correlate ground truth and Wazuh alerts"
    )
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument(
        "--output",
        default="datasets/final/correlated_dataset.jsonl"
    )
    parser.add_argument("--window-seconds", type=int, default=180)
    args = parser.parse_args()

    gt = read_jsonl(args.ground_truth)
    alerts = read_jsonl(args.alerts)
    results = correlate(gt, alerts, args.window_seconds)
    write_jsonl(args.output, results)

    from collections import Counter
    print(json.dumps({
        "ground_truth_records": len(gt),
        "alert_records": len(alerts),
        "final_records": len(results),
        "correlation_status": dict(
            Counter(r["correlation_status"] for r in results)
        ),
        "output": args.output
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
