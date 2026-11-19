#!/usr/bin/env python3
import argparse
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


def read_jsonl(path):
    rows = []
    p = Path(path)
    if not p.exists():
        return rows

    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)
    ent = 0.0

    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)

    return round(ent, 4)


def minute_bucket(timestamp):
    if not timestamp:
        return "unknown"

    try:
        dt = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
        return dt.strftime("%Y-%m-%dT%H:%MZ")
    except Exception:
        return "unknown"


def extract_status_code(text):
    if not text:
        return None

    m = re.search(
        r"\b(status|status_code)[=: ]+(\d{3})\b",
        str(text),
        re.I
    )
    if m:
        return int(m.group(2))

    return None


def user_agent_category(text):
    if not text:
        return "unknown"

    t = text.lower()

    if "curl" in t:
        return "curl"
    if "python" in t or "requests" in t:
        return "python_requests"
    if "mozilla" in t:
        return "browser"
    if "bot" in t:
        return "bot"

    return "other"


def main():
    parser = argparse.ArgumentParser(
        description="Add engineered features to AI SOC dataset"
    )
    parser.add_argument(
        "--input",
        default="datasets/final/dataset_clean.jsonl"
    )
    parser.add_argument(
        "--output",
        default="datasets/final/dataset_features.jsonl"
    )
    args = parser.parse_args()

    rows = read_jsonl(args.input)

    count_per_source_ip = Counter(
        r.get("source_ip") or "unknown" for r in rows
    )
    count_per_agent = Counter(
        r.get("agent_name") or "unknown" for r in rows
    )
    count_per_rule = Counter(
        r.get("rule_id") or "unknown" for r in rows
    )
    count_per_minute = Counter(
        minute_bucket(r.get("timestamp")) for r in rows
    )

    enriched = []

    for r in rows:
        row = dict(r)

        full_log = row.get("full_log", "")
        source_ip = row.get("source_ip") or "unknown"
        agent_name = row.get("agent_name") or "unknown"
        rule_id = row.get("rule_id") or "unknown"
        bucket = minute_bucket(row.get("timestamp"))

        row["feature_full_log_length"] = len(full_log)
        row["feature_full_log_entropy"] = entropy(full_log)
        row["feature_event_count_source_ip"] = (
            count_per_source_ip[source_ip]
        )
        row["feature_event_count_agent"] = (
            count_per_agent[agent_name]
        )
        row["feature_event_count_rule"] = (
            count_per_rule[rule_id]
        )
        row["feature_event_count_minute"] = (
            count_per_minute[bucket]
        )
        row["feature_minute_bucket"] = bucket
        row["feature_status_code"] = extract_status_code(full_log)
        row["feature_user_agent_category"] = (
            user_agent_category(full_log)
        )

        try:
            row["feature_rule_level"] = (
                int(row["rule_level"])
                if row.get("rule_level") is not None
                else 0
            )
        except (ValueError, TypeError):
            row["feature_rule_level"] = 0

        row["feature_is_high_severity"] = (
            1 if row["feature_rule_level"] >= 10 else 0
        )
        row["feature_has_mitre"] = (
            0 if row.get("mitre_tactic") in
            (None, "", "unknown", "none") else 1
        )

        enriched.append(row)

    write_jsonl(args.output, enriched)

    print(json.dumps({
        "input_records": len(rows),
        "output_records": len(enriched),
        "output": args.output
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
