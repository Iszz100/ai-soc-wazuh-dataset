#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path


def get_nested(obj, path, default=None):
    cur = obj

    for part in path.split("."):
        if not isinstance(cur, dict):
            return default

        cur = cur.get(part)

        if cur is None:
            return default

    return cur


def make_event_id(record):
    base = "|".join([
        str(record.get("timestamp", "")),
        str(record.get("agent_id", "")),
        str(record.get("rule_id", "")),
        str(record.get("raw_event", ""))[:200]
    ])

    return "evt-" + hashlib.sha256(
        base.encode()
    ).hexdigest()[:16]


def normalize(alert):
    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    rule = alert.get("rule") or {}

    if not isinstance(data, dict):
        data = {}

    if not isinstance(agent, dict):
        agent = {}

    if not isinstance(rule, dict):
        rule = {}

    rule_level = rule.get("level")

    try:
        rule_level = (
            int(rule_level)
            if rule_level is not None
            else None
        )
    except (ValueError, TypeError):
        rule_level = None

    rule_groups = rule.get("groups", [])

    if not isinstance(rule_groups, list):
        rule_groups = []

    record = {
        "event_id": "",
        "timestamp": alert.get("timestamp"),

        "agent_id": str(agent.get("id", "unknown")),
        "agent_name": agent.get("name", "unknown"),

        "source_ip": (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("src")
            or data.get("source_ip")
        ),

        "source_port": (
            data.get("srcport")
            or data.get("src_port")
        ),

        "destination_ip": (
            data.get("dstip")
            or data.get("dst_ip")
            or data.get("destination_ip")
        ),

        "destination_port": (
            data.get("dstport")
            or data.get("dst_port")
        ),

        "destination_user": (
            data.get("dstuser")
            or data.get("dst_user")
            or data.get("user")
        ),

        "rule_id": str(rule.get("id", "")),
        "rule_level": rule_level,
        "rule_description": rule.get("description", ""),
        "rule_groups": rule_groups,

        "raw_event": alert.get(
            "full_log",
            json.dumps(alert, ensure_ascii=False)
        ),

        "scenario_id": "unmatched",
        "attack_type": "unknown",
        "mitre_tactic": "unknown",
        "mitre_technique": "unknown",

        "label": "unlabeled",
        "confidence": 0.0,
        "ground_truth_source": "none"
    }

    record["event_id"] = make_event_id(record)

    return record


def main():
    parser = argparse.ArgumentParser(
        description="Normalize Wazuh alerts JSONL"
    )

    parser.add_argument("--input", required=True)

    parser.add_argument(
        "--output",
        default="datasets/normalized_alerts.jsonl"
    )

    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        parser.error(f"Input file not found: {in_path}")

    out_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    total = 0
    written = 0
    invalid = 0

    with in_path.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as fin, out_path.open(
        "w",
        encoding="utf-8"
    ) as fout:

        for line in fin:
            total += 1
            line = line.strip()

            if not line:
                continue

            try:
                alert = json.loads(line)

                if not isinstance(alert, dict):
                    invalid += 1
                    continue

            except json.JSONDecodeError:
                invalid += 1
                continue

            record = normalize(alert)

            fout.write(
                json.dumps(record, ensure_ascii=False) + "\n"
            )

            written += 1

    print(json.dumps({
        "input": str(in_path),
        "output": str(out_path),
        "total_lines": total,
        "written_records": written,
        "invalid_records": invalid
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
