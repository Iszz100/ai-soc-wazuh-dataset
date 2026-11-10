#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def read_jsonl(path):
    rows = []

    with Path(path).open(
        "r", encoding="utf-8"
    ) as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}:{line_number}: {exc}"
                )

    return rows


def parse_timestamp(value):
    if not value:
        raise ValueError("Missing timestamp")

    dt = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if dt.tzinfo is None:
        raise ValueError("Timestamp must include timezone")

    return dt.astimezone(timezone.utc)


def find_matches(alert, ground_truth, rules):
    matches = []

    for gt in ground_truth:
        scenario_id = gt.get("scenario_id")
        config = rules.get("scenarios", {}).get(scenario_id)

        if not config:
            continue

        try:
            alert_time = parse_timestamp(alert.get("timestamp"))
            gt_time = parse_timestamp(gt.get("timestamp"))
        except (ValueError, TypeError):
            continue

        delta = (alert_time - gt_time).total_seconds()

        if delta < 0 or delta > config["window_seconds"]:
            continue

        if str(alert.get("agent_id")) != str(
            config["target_agent_id"]
        ):
            continue

        rule_id = str(alert.get("rule_id"))

        if rule_id not in config["allowed_rule_ids"]:
            continue

        if alert.get("destination_user") != config["target_user"]:
            continue

        source_ip = alert.get("source_ip")

        if source_ip:
            if source_ip != config["source_ip"]:
                continue
        else:
            if rule_id not in config.get(
                "allow_missing_source_ip_rule_ids", []
            ):
                continue

        matches.append((gt, config, delta))

    return matches


def correlate(alerts, ground_truth, rules):
    results = []

    for original in alerts:
        alert = dict(original)

        matches = find_matches(
            alert,
            ground_truth,
            rules
        )

        if len(matches) == 1:
            gt, config, delta = matches[0]

            alert.update({
                "scenario_id": gt["scenario_id"],
                "attack_type": gt["attack_type"],
                "mitre_tactic": gt["mitre_tactic"],
                "mitre_technique": gt["mitre_technique"],
                "label": gt["expected_label"],
                "confidence": config["confidence"],
                "ground_truth_source": (
                    "ground-truth/ground_truth.jsonl"
                ),
                "ground_truth_run_id": gt["run_id"],
                "correlation_status": "matched",
                "correlation_delta_seconds": round(delta, 3)
            })

        elif len(matches) > 1:
            alert["correlation_status"] = "ambiguous"

        else:
            alert["correlation_status"] = "unmatched"

        results.append(alert)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Correlate Wazuh alerts with Ground Truth"
    )

    parser.add_argument(
        "--alerts",
        default="datasets/normalized_alerts.jsonl"
    )

    parser.add_argument(
        "--ground-truth",
        default="ground-truth/ground_truth.jsonl"
    )

    parser.add_argument(
        "--rules",
        default="configs/correlation_rules.json"
    )

    parser.add_argument(
        "--output",
        default="datasets/correlated_alerts.jsonl"
    )

    args = parser.parse_args()

    alerts = read_jsonl(args.alerts)
    ground_truth = read_jsonl(args.ground_truth)

    with open(args.rules, encoding="utf-8") as f:
        rules = json.load(f)

    results = correlate(
        alerts,
        ground_truth,
        rules
    )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as f:
        for row in results:
            f.write(
                json.dumps(row, ensure_ascii=False) + "\n"
            )

    statuses = Counter(
        row.get("correlation_status")
        for row in results
    )

    labels = Counter(
        row.get("label")
        for row in results
    )

    print(json.dumps({
        "total_alerts": len(results),
        "correlation_status": dict(statuses),
        "label_distribution": dict(labels),
        "output": str(output)
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
