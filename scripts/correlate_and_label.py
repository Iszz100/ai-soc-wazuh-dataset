#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import Counter


def read_jsonl(path):
    rows = []
    if not path or not Path(path).exists():
        return rows

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                if line.strip():
                    rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
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
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def stable_id(*parts):
    value = "|".join(str(x) for x in parts)
    return hashlib.sha256(value.encode()).hexdigest()[:20]


def normalize_alert(a, source):
    rule = a.get("rule") or {}
    agent = a.get("agent") or {}
    data = a.get("data") or {}

    if not isinstance(rule, dict):
        rule = {}
    if not isinstance(agent, dict):
        agent = {}
    if not isinstance(data, dict):
        data = {}

    mitre = rule.get("mitre") or {}
    if not isinstance(mitre, dict):
        mitre = {}

    full_log = a.get("full_log") or a.get("raw_event") or ""

    rule_id = str(rule.get("id") or a.get("rule_id") or "")
    description = (
        rule.get("description")
        or a.get("rule_description")
        or ""
    )

    return {
        "event_id": "evt-" + stable_id(
            a.get("timestamp"),
            agent.get("name") or a.get("agent_name"),
            rule_id,
            full_log
        ),
        "timestamp": a.get("timestamp"),
        "agent_name": agent.get("name") or a.get("agent_name") or "unknown",
        "source_ip": (
            data.get("srcip")
            or data.get("src_ip")
            or a.get("source_ip")
        ),
        "destination_ip": (
            data.get("dstip")
            or data.get("dst_ip")
            or a.get("destination_ip")
        ),
        "destination_port": (
            data.get("dstport")
            or data.get("dst_port")
            or a.get("destination_port")
        ),
        "rule_id": rule_id or None,
        "rule_level": rule.get("level", a.get("rule_level")),
        "rule_description": description,
        "rule_groups": rule.get("groups") or [],
        "rule_mitre_id": mitre.get("id", []),
        "location": a.get("location", ""),
        "full_log": full_log,
        "event_source": source
    }


def semantic_match(attack_type, alert):
    rid = str(alert.get("rule_id") or "")
    text = (
        str(alert.get("rule_description") or "")
        + " "
        + str(alert.get("full_log") or "")
        + " "
        + " ".join(alert.get("rule_groups") or [])
    ).lower()

    hints = {
        "auth_attack": {
            "ids": {"5710", "5503", "5712"},
            "words": [
                "sshd:",
                "pam: user login failed",
                "brute force",
                "authentication failed",
                "login failed"
            ]
        },
        "recon": {
            "ids": set(),
            "words": ["port scan", "nmap", "network scan", "reconnaissance"]
        },
        "web_attack": {
            "ids": set(),
            "words": [
                "sql injection", "cross site scripting",
                "path traversal", "command injection",
                "web attack", "web input"
            ]
        },
        "fim_event": {
            "ids": {"550"},
            "words": [
                "syscheck", "file integrity",
                "file modified", "file added", "file deleted"
            ]
        },
        "suspicious_command": {
            "ids": {"110050"},
            "words": ["suspicious command"]
        }
    }

    rule = hints.get(attack_type, {"ids": set(), "words": []})

    return (
        rid in rule["ids"]
        or any(word in text for word in rule["words"])
    )


def correlate(gt_rows, alert_rows, window):
    events = [
        normalize_alert(a, "wazuh_alert")
        for a in alert_rows
    ]

    results = []
    matched_counts = Counter()

    for alert in events:
        alert_time = parse_time(alert.get("timestamp"))
        candidates = []

        for index, gt in enumerate(gt_rows):
            start = parse_time(
                gt.get("execution_start_time")
                or gt.get("start_time")
                or gt.get("timestamp")
            )

            end = parse_time(
                gt.get("execution_end_time")
                or gt.get("end_time")
                or gt.get("timestamp")
            )

            if not start or not alert_time:
                continue

            end = end or start

            if not (
                start - timedelta(seconds=window)
                <= alert_time
                <= end + timedelta(seconds=window)
            ):
                continue

            attack = gt.get("attack_type", "unknown")

            semantic = semantic_match(attack, alert)

            scenario_match = (
                alert.get("scenario_id") == gt.get("scenario_id")
            )

            payload = gt.get("payload_id")
            payload_match = (
                payload not in (None, "", "none", "from_scenario")
                and payload in json.dumps(alert, ensure_ascii=False)
            )

            target = gt.get("target_host") or gt.get("target_ip")
            target_match = (
                bool(target)
                and (
                    alert.get("destination_ip") == target
                    or str(target) in str(alert.get("full_log") or "")
                )
            )

            # Reject an explicit destination IP mismatch.
            if (
                target
                and alert.get("destination_ip")
                and alert["destination_ip"] != target
            ):
                continue

            source_match = bool(
                gt.get("source_ip")
                and gt.get("source_ip") == alert.get("source_ip")
            )

            port = gt.get("target_port")
            port_match = (
                port not in (None, "", "mixed")
                and str(port) == str(alert.get("destination_port"))
            )

            if not (semantic or scenario_match or payload_match):
                continue

            delta = abs((alert_time - start).total_seconds())

            score = (
                2
                + (2 if semantic else 0)
                + (2 if target_match else 0)
                + (1 if source_match else 0)
                + (1 if port_match else 0)
                + (3 if scenario_match else 0)
                + (3 if payload_match else 0)
            )

            if score >= 4:
                candidates.append({
                    "index": index,
                    "gt": gt,
                    "score": score,
                    "delta": delta,
                    "semantic": semantic,
                    "target": target_match,
                    "scenario": scenario_match,
                    "payload": payload_match,
                    "source": source_match,
                    "port": port_match
                })

        if candidates:
            candidates.sort(
                key=lambda x: (-x["score"], x["delta"])
            )

            best = candidates[0]
            gt = best["gt"]

            # Confidence reflects the actual available evidence.
            confidence = (
                1.0 if best["scenario"] or best["payload"]
                else 0.8 if best["target"]
                else 0.5
            )

            evidence = ["time_window"]

            for key, name in [
                ("semantic", "rule_semantic_match"),
                ("target", "target_ip_match"),
                ("scenario", "scenario_id_match"),
                ("payload", "payload_id_match"),
                ("source", "source_ip_match"),
                ("port", "destination_port_match")
            ]:
                if best[key]:
                    evidence.append(name)

            missing = [
                name for key, name in [
                    ("target", "target_ip"),
                    ("source", "source_ip"),
                    ("port", "destination_port"),
                    ("scenario", "scenario_id"),
                    ("payload", "payload_id"),
                ]
                if not best[key]
            ]

            row = dict(alert)
            row.update({
                "run_id": gt.get("run_id", "unknown"),
                "scenario_id": gt.get("scenario_id", "unknown"),
                "attack_type": gt.get("attack_type", "unknown"),
                "mitre_tactic": gt.get("mitre_tactic", "unknown"),
                "mitre_technique": gt.get("mitre_technique", "unknown"),
                "label": gt.get("expected_label", "unlabeled"),
                "confidence": confidence,
                "ground_truth_source": "ground_truth_correlated",
                "correlation_status": "matched_alert",
                "correlation_evidence": evidence,
                "correlation_missing_fields": missing
            })

            results.append(row)
            matched_counts[best["index"]] += 1

        else:
            alert.update({
                "scenario_id": "unmatched",
                "run_id": "unknown",
                "attack_type": "unknown",
                "mitre_tactic": "unknown",
                "mitre_technique": "unknown",
                "label": "unlabeled",
                "confidence": 0.0,
                "ground_truth_source": "wazuh_alert_only",
                "correlation_status": "alert_without_ground_truth",
                "correlation_evidence": [],
                "correlation_missing_fields": ["ground_truth_link"]
            })

            results.append(alert)

    for index, gt in enumerate(gt_rows):
        if matched_counts[index]:
            continue

        timestamp = (
            gt.get("execution_start_time")
            or gt.get("timestamp")
        )

        results.append({
            "event_id": "gt-" + stable_id(
                gt.get("run_id"),
                gt.get("scenario_id"),
                timestamp
            ),
            "timestamp": timestamp,
            "agent_name": "unknown",
            "source_ip": None,
            "destination_ip": (
                gt.get("target_host") or gt.get("target_ip")
            ),
            "destination_port": gt.get("target_port"),
            "rule_id": None,
            "rule_level": None,
            "rule_description": None,
            "rule_groups": [],
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
            "correlation_evidence": ["ground_truth_record"],
            "correlation_missing_fields": []
        })

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--archives")
    parser.add_argument("--output", default="datasets/final/correlated_dataset.jsonl")
    parser.add_argument("--window-seconds", type=int, default=180)
    args = parser.parse_args()

    gt = read_jsonl(args.ground_truth)
    alerts = read_jsonl(args.alerts)
    archives = read_jsonl(args.archives)

    combined = alerts + archives

    result = correlate(gt, combined, args.window_seconds)

    write_jsonl(args.output, result)

    print(json.dumps({
        "ground_truth_records": len(gt),
        "alert_records": len(alerts),
        "archive_records": len(archives),
        "final_records": len(result),
        "correlation_status": dict(Counter(
            r["correlation_status"] for r in result
        )),
        "output": args.output
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
