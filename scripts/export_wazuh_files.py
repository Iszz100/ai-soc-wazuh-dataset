#!/usr/bin/env python3
import argparse
from pathlib import Path


def tail_file(src, dst, max_lines):
    src = Path(src)
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)

    if not src.exists():
        dst.write_text("", encoding="utf-8")
        return 0

    with src.open("r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    selected = lines[-max_lines:]
    dst.write_text("".join(selected), encoding="utf-8")
    return len(selected)


def main():
    parser = argparse.ArgumentParser(
        description="Export Wazuh alert/archive files into run evidence"
    )
    parser.add_argument("--run-dir", required=True)
    parser.add_argument(
        "--alerts",
        default="/var/ossec/logs/alerts/alerts.json"
    )
    parser.add_argument(
        "--archives",
        default="/var/ossec/logs/archives/archives.json"
    )
    parser.add_argument("--max-lines", type=int, default=5000)
    args = parser.parse_args()

    if args.max_lines < 1:
        raise SystemExit("ERROR: max-lines harus minimal 1")

    run_dir = Path(args.run_dir)

    alert_count = tail_file(
        args.alerts,
        run_dir / "wazuh_alerts.jsonl",
        args.max_lines
    )

    archive_count = tail_file(
        args.archives,
        run_dir / "wazuh_archives_sample.jsonl",
        args.max_lines
    )

    print({
        "run_dir": str(run_dir),
        "alert_lines": alert_count,
        "archive_lines": archive_count
    })


if __name__ == "__main__":
    main()
