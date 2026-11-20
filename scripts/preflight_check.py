#!/usr/bin/env python3
import argparse
import ipaddress
import json
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def ping(host):
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            text=True,
            capture_output=True
        )
        return proc.returncode == 0
    except (FileNotFoundError, OSError):
        return False

def tcp_check(host, port, timeout=3):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="configs/orchestrator.json"
    )
    parser.add_argument(
        "--output",
        default="reports/chapter8/preflight.json"
    )
    args = parser.parse_args()

    config = load_json(args.config)
    lab = config["lab"]

    target_ip = lab["target_ip"]
    manager = lab["wazuh_server"]
    network = ipaddress.ip_network(lab["lab_cidr"], strict=False)

    parsed = urlparse(lab["target_web"])
    web_host = parsed.hostname
    web_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    target = ipaddress.ip_address(target_ip)

    checks = {
        "target_in_lab_cidr": (
            target in network and target.is_private
        ),
        "target_ping": ping(target_ip),
        "wazuh_ping": ping(manager),
        "target_ssh_22": tcp_check(target_ip, 22),
        "target_web": tcp_check(web_host, web_port)
    }

    status = "pass" if all(checks.values()) else "fail"

    report = {
        "status": status,
        "checks": checks,
        "note": "Dashboard export workflow; no Wazuh API authentication."
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(json.dumps(report, indent=2, ensure_ascii=False))

    if status != "pass":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
