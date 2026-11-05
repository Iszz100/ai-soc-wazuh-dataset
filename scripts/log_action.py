#!/usr/bin/env python3

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

parser = argparse.ArgumentParser()
parser.add_argument("--action", required=True)
parser.add_argument("--source", default="192.168.56.1")
parser.add_argument("--target", default="192.168.56.100")
parser.add_argument("--label", default="normal")
parser.add_argument("--details", default="")

args = parser.parse_args()

now = datetime.now(timezone.utc)

record = {
    "timestamp_utc": now.isoformat(timespec="seconds"),
    "timestamp_local": now.astimezone(
        ZoneInfo("Asia/Jakarta")
    ).isoformat(timespec="seconds"),
    "scenario": "baseline",
    "label": args.label,
    "action": args.action,
    "source_ip": args.source,
    "target_ip": args.target,
    "details": args.details
}

output = Path("ground-truth/baseline-actions.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("a", encoding="utf-8") as f:
    f.write(json.dumps(record, ensure_ascii=False) + "\n")

print(json.dumps(record, indent=2))
print(f"Saved to {output}")
