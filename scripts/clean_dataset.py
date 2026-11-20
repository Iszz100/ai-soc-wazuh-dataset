#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path
from datetime import datetime, timezone

PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s,;&]+"),
     r"\1=<MASKED_PASSWORD>"),
    (re.compile(r"(?i)(token|api_key|apikey|secret)\s*[:=]\s*[^\s,;&]+"),
     r"\1=<MASKED_SECRET>"),
    (re.compile(
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
        re.S
    ), "<MASKED_PRIVATE_KEY>")
]


def read_jsonl(path):
    rows = []
    with Path(path).open(encoding="utf-8", errors="replace") as f:
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


def normalize_timestamp(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def mask_ip(value):
    if not value:
        return None
    return re.sub(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b",
        r"\1.X",
        str(value)
    )


def sanitize_text(value):
    if value is None:
        return None

    text = str(value)

    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)

    return mask_ip(text)


def fingerprint(row):
    value = {
        key: row.get(key)
        for key in ["timestamp", "agent_name", "rule_id", "full_log"]
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True).encode()
    ).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="datasets/final/correlated_dataset.jsonl")
    parser.add_argument("--output", default="datasets/final/dataset_clean.jsonl")
    parser.add_argument("--dedup", action="store_true")
    args = parser.parse_args()

    rows = read_jsonl(args.input)
    cleaned_rows = []
    seen = set()
    duplicates = 0

    for original in rows:
        row = dict(original)

        row["timestamp"] = normalize_timestamp(row.get("timestamp"))

        for key in ["source_ip", "destination_ip"]:
            row[key] = mask_ip(row.get(key))

        for key in [
            "full_log", "rule_description", "location", "raw_event"
        ]:
            if isinstance(row.get(key), str):
                row[key] = sanitize_text(row[key])

        for key, value in list(row.items()):
            if value == "":
                row[key] = None

        row.pop("raw_alert", None)

        if row.get("rule_level") is not None:
            try:
                row["rule_level"] = int(row["rule_level"])
            except (ValueError, TypeError):
                row["rule_level"] = None

        if args.dedup:
            fp = fingerprint(row)
            if fp in seen:
                duplicates += 1
                continue
            seen.add(fp)

        cleaned_rows.append(row)

    write_jsonl(args.output, cleaned_rows)

    print(json.dumps({
        "input_records": len(rows),
        "output_records": len(cleaned_rows),
        "duplicates_removed": duplicates,
        "output": args.output
    }, indent=2))


if __name__ == "__main__":
    main()
