#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SENSITIVE_PATTERNS = [
    (
        re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s,;&]+"),
        r"\1=<MASKED_PASSWORD>"
    ),
    (
        re.compile(r"(?i)(token|api_key|apikey|secret)\s*[:=]\s*[^\s,;&]+"),
        r"\1=<MASKED_SECRET>"
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
            re.S
        ),
        "<MASKED_PRIVATE_KEY>"
    )
]


def read_jsonl(path):
    rows = []
    p = Path(path)

    if not p.exists():
        return rows

    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return rows


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def normalize_timestamp(value):
    if not value:
        return None

    v = str(value).replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def mask_ip(ip):
    if not ip:
        return None

    ip = str(ip)
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", ip)

    if not m:
        return ip

    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.X"


def sanitize_text(text):
    if text is None:
        return ""

    text = str(text)

    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)

    text = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        lambda m: mask_ip(m.group(0)),
        text
    )

    return text


def row_fingerprint(row):
    key = {
        "timestamp": row.get("timestamp"),
        "agent_name": row.get("agent_name"),
        "rule_id": row.get("rule_id"),
        "scenario_id": row.get("scenario_id"),
        "full_log": row.get("full_log", "")[:300]
    }

    raw = json.dumps(key, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def clean_row(row):
    cleaned = dict(row)

    cleaned["timestamp"] = normalize_timestamp(
        cleaned.get("timestamp")
    )
    cleaned["agent_name"] = cleaned.get("agent_name") or "unknown"
    cleaned["source_ip"] = mask_ip(cleaned.get("source_ip"))
    cleaned["destination_ip"] = mask_ip(
        cleaned.get("destination_ip")
    )

    try:
        cleaned["rule_level"] = (
            int(cleaned["rule_level"])
            if cleaned.get("rule_level") is not None
            else None
        )
    except (ValueError, TypeError):
        cleaned["rule_level"] = None

    cleaned["rule_id"] = str(cleaned.get("rule_id") or "")
    cleaned["rule_description"] = sanitize_text(
        cleaned.get("rule_description")
    )
    cleaned["full_log"] = sanitize_text(cleaned.get("full_log"))

    cleaned["scenario_id"] = cleaned.get("scenario_id") or "unknown"
    cleaned["attack_type"] = cleaned.get("attack_type") or "unknown"
    cleaned["mitre_tactic"] = cleaned.get("mitre_tactic") or "unknown"
    cleaned["mitre_technique"] = (
        cleaned.get("mitre_technique") or "unknown"
    )
    cleaned["label"] = cleaned.get("label") or "unlabeled"

    try:
        cleaned["confidence"] = float(
            cleaned.get("confidence", 0.0)
        )
    except (ValueError, TypeError):
        cleaned["confidence"] = 0.0

    cleaned.pop("raw_alert", None)

    return cleaned


def main():
    parser = argparse.ArgumentParser(
        description="Clean AI SOC dataset"
    )
    parser.add_argument(
        "--input",
        default="datasets/final/correlated_dataset.jsonl"
    )
    parser.add_argument(
        "--output",
        default="datasets/final/dataset_clean.jsonl"
    )
    parser.add_argument("--dedup", action="store_true")
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    cleaned_rows = []
    seen = set()
    duplicates = 0

    for row in rows:
        cleaned = clean_row(row)
        fingerprint = row_fingerprint(cleaned)

        if args.dedup and fingerprint in seen:
            duplicates += 1
            continue

        seen.add(fingerprint)
        cleaned_rows.append(cleaned)

    write_jsonl(args.output, cleaned_rows)

    print(json.dumps({
        "input_records": len(rows),
        "output_records": len(cleaned_rows),
        "duplicates_removed": duplicates,
        "output": args.output
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
