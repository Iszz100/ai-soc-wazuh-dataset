#!/usr/bin/env python3

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_timestamp(value):
    if not value:
        return now_utc()

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if dt.tzinfo is None:
            raise ValueError("Timestamp must include timezone")

        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def main():
    parser = argparse.ArgumentParser(
        description="Write one ground truth event as JSONL"
    )

    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--attack-type", required=True)
    parser.add_argument("--mitre-tactic", required=True)
    parser.add_argument("--mitre-technique", required=True)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--payload-id", default="none")
    parser.add_argument("--intensity", required=True)

    parser.add_argument(
        "--timestamp",
        type=normalize_timestamp,
        default=None
    )

    parser.add_argument("--source-ip", default=None)
    parser.add_argument("--details", default="")

    parser.add_argument(
        "--expected-label",
        required=True,
        choices=["benign", "malicious"]
    )

    parser.add_argument(
        "--success-status",
        required=True,
        choices=["success", "failed", "timeout", "partial", "unknown"]
    )

    parser.add_argument(
        "--output",
        default="ground-truth/ground_truth.jsonl"
    )

    args = parser.parse_args()

    record = {
        "timestamp": args.timestamp or now_utc(),
        "scenario_id": args.scenario_id,
        "run_id": "run-" + uuid.uuid4().hex[:12],
        "attack_type": args.attack_type,
        "mitre_tactic": args.mitre_tactic,
        "mitre_technique": args.mitre_technique,
        "target_host": args.target_host,
        "target_port": args.target_port,
        "tool": args.tool,
        "payload_id": args.payload_id,
        "intensity": args.intensity,
        "expected_label": args.expected_label,
        "success_status": args.success_status,
        "source_ip": args.source_ip,
        "details": args.details
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(json.dumps(record, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
