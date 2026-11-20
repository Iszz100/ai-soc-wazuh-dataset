#!/usr/bin/env python3
import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path
from datetime import datetime


def read_jsonl(path):
    with Path(path).open(encoding="utf-8", errors="replace") as f:
        return [
            json.loads(line)
            for line in f
            if line.strip()
        ]


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)

    return -sum(
        (n / total) * math.log2(n / total)
        for n in counts.values()
    )


def minute_bucket(timestamp):
    if not timestamp:
        return "unknown"
    try:
        return datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        ).strftime("%Y-%m-%dT%H:%M")
    except ValueError:
        return "unknown"


def extract_status_code(text):
    if not text:
        return None

    match = re.search(
        r"\b(status|status_code)[=: ]+(\d{3})\b",
        str(text),
        re.I
    )
    return int(match.group(2)) if match else None


def user_agent_category(text):
    t = str(text or "").lower()

    if "curl" in t:
        return "curl"
    if "python" in t or "requests" in t:
        return "python_requests"
    if "mozilla" in t:
        return "browser"
    if "bot" in t:
        return "bot"

    return "other" if t else "unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="datasets/final/dataset_clean.jsonl")
    parser.add_argument("--output", default="datasets/final/dataset_features.jsonl")
    args = parser.parse_args()

    rows = read_jsonl(args.input)

    count_ip = Counter(r.get("source_ip") or "unknown" for r in rows)
    count_agent = Counter(r.get("agent_name") or "unknown" for r in rows)
    count_rule = Counter(r.get("rule_id") or "unknown" for r in rows)

    buckets = [minute_bucket(r.get("timestamp")) for r in rows]
    count_minute = Counter(buckets)

    enriched = []

    for row in rows:
        row = dict(row)

        full_log = row.get("full_log") or ""
        source_ip = row.get("source_ip") or "unknown"
        agent = row.get("agent_name") or "unknown"
        rule_id = row.get("rule_id") or "unknown"
        bucket = minute_bucket(row.get("timestamp"))

        row["feature_full_log_length"] = len(full_log)
        row["feature_full_log_entropy"] = entropy(full_log)
        row["feature_event_count_source_ip"] = count_ip[source_ip]
        row["feature_event_count_agent"] = count_agent[agent]
        row["feature_event_count_rule"] = count_rule[rule_id]
        row["feature_event_count_minute"] = count_minute[bucket]
        row["feature_minute_bucket"] = bucket
        row["feature_status_code"] = extract_status_code(full_log)
        row["feature_user_agent_category"] = user_agent_category(full_log)

        try:
            row["feature_rule_level"] = int(row.get("rule_level") or 0)
        except (ValueError, TypeError):
            row["feature_rule_level"] = 0

        row["feature_is_high_severity"] = int(
            row["feature_rule_level"] >= 10
        )

        mitre = row.get("mitre_tactic")
        row["feature_has_mitre"] = int(
            mitre not in (None, "", "unknown", "none")
        )

        enriched.append(row)

    write_jsonl(args.output, enriched)

    print(json.dumps({
        "input_records": len(rows),
        "output_records": len(enriched),
        "output": args.output
    }, indent=2))


if __name__ == "__main__":
    main()
