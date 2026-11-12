#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import shlex
import subprocess
import time
import uuid

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


LAB_CIDR_DEFAULT = "192.168.56.0/24"

NIKTO_SCRIPT = Path.home() / "tools/nikto-2.6.1/program/nikto.pl"


PROFILES = {
    "nmap_light": {
        "tool": "nmap",
        "intensity": "low",
        "expected_label": "recon",
        "command": [
            "nmap", "-Pn", "--top-ports", "20", "-T2"
        ]
    },

    "nmap_service": {
        "tool": "nmap",
        "intensity": "medium",
        "expected_label": "recon",
        "command": [
            "nmap", "-Pn", "-sV", "--version-light",
            "-T2", "-p", "22,80,443,3000,8080"
        ]
    },

    "nmap_specific_ports": {
        "tool": "nmap",
        "intensity": "low",
        "expected_label": "recon",
        "command": [
            "nmap", "-Pn", "-p", "22,80,443,3000,8080"
        ]
    },

    "nmap_slow": {
        "tool": "nmap",
        "intensity": "low_and_slow",
        "expected_label": "recon",
        "command": [
            "nmap", "-Pn", "-T1",
            "--scan-delay", "500ms",
            "-p", "22,80,443,3000,8080"
        ]
    },

    "nmap_noisy_lab": {
        "tool": "nmap",
        "intensity": "noisy_lab",
        "expected_label": "recon",
        "command": [
            "nmap", "-Pn", "-T3",
            "--max-retries", "2", "-p", "1-1024"
        ]
    },

    "curl_header": {
        "tool": "curl",
        "intensity": "low",
        "expected_label": "web_fingerprint",
        "command": ["curl", "-sS", "-I"]
    },

    "whatweb_light": {
        "tool": "whatweb",
        "intensity": "low",
        "expected_label": "web_fingerprint",
        "command": ["whatweb", "-a", "1"]
    },

    "nikto_light": {
        "tool": "nikto",
        "intensity": "medium",
        "expected_label": "vuln_scan_light",
        "command": [
            "perl", str(NIKTO_SCRIPT),
            "-nointeractive", "-h"
        ]
    },

    "nuclei_info_low": {
        "tool": "nuclei",
        "intensity": "low",
        "expected_label": "vuln_scan_light",
        "command": [
            "nuclei",
            "-severity", "info,low",
            "-rate-limit", "5",
            "-jsonl",
            "-u"
        ]
    }
}


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def ensure_private_lab_target(target, lab_cidr):

    parsed = urlparse(
        target if "://" in target else f"//{target}"
    )

    host = parsed.hostname or target

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit(
            f"[BLOCKED] Target harus berupa IP lab: {target}"
        )

    network = ipaddress.ip_network(lab_cidr, strict=False)

    if ip not in network:
        raise SystemExit(
            f"[BLOCKED] Target {ip} di luar LAB_CIDR {lab_cidr}"
        )

    if not ip.is_private:
        raise SystemExit(
            f"[BLOCKED] Target {ip} bukan private IP"
        )

    return str(ip)


def build_command(profile_name, target, target_ip, run_dir):

    profile = PROFILES[profile_name]
    tool = profile["tool"]

    cmd = list(profile["command"])

    primary_output = None

    if tool == "nmap":

        output_base = run_dir / profile_name

        cmd += [
            target_ip,
            "-oA", str(output_base)
        ]

        primary_output = str(output_base)

    elif tool == "curl":

        output_file = run_dir / "headers.txt"

        cmd += [
            target,
            "-D", str(output_file),
            "-o", "/dev/null"
        ]

        primary_output = str(output_file)

    elif tool == "whatweb":

        output_file = run_dir / "whatweb.json"

        cmd += [
            target,
            f"--log-json={output_file}"
        ]

        primary_output = str(output_file)

    elif tool == "nikto":

        output_file = run_dir / "nikto.json"

        cmd += [
            target,
            "-output", str(output_file),
            "-Format", "json"
        ]

        primary_output = str(output_file)

    elif tool == "nuclei":

        output_file = run_dir / "nuclei.jsonl"

        cmd += [
            target,
            "-o", str(output_file)
        ]

        primary_output = str(output_file)

    return cmd, primary_output


def as_text(value):

    if isinstance(value, bytes):
        return value.decode(errors="replace")

    return value or ""


def main():

    parser = argparse.ArgumentParser(
        description="Safe Recon Runner for AI SOC Wazuh Dataset"
    )

    parser.add_argument(
        "--profile",
        required=True,
        choices=sorted(PROFILES.keys())
    )

    parser.add_argument("--target", required=True)

    parser.add_argument(
        "--lab-cidr",
        default=os.environ.get(
            "LAB_CIDR", LAB_CIDR_DEFAULT
        )
    )

    parser.add_argument(
        "--output-root",
        default="logs/recon"
    )

    parser.add_argument(
        "--ground-truth",
        default="ground-truth/recon.jsonl"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=300
    )

    args = parser.parse_args()

    target_ip = ensure_private_lab_target(
        args.target,
        args.lab_cidr
    )

    profile = PROFILES[args.profile]

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-{args.profile}-{uuid.uuid4().hex[:8]}"
    )

    run_dir = Path(args.output_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd, primary_output = build_command(
        args.profile,
        args.target,
        target_ip,
        run_dir
    )

    command_text = shlex.join(cmd)

    print(f"[RUN] {run_id}")
    print(f"[TARGET] {args.target}")
    print(f"[PROFILE] {args.profile}")
    print(f"[CMD] {command_text}")

    start_time = now_utc()
    t0 = time.monotonic()

    try:

        proc = subprocess.run(
            cmd,
            cwd=".",
            text=True,
            capture_output=True,
            timeout=args.timeout,
            check=False
        )

        stdout = proc.stdout
        stderr = proc.stderr
        return_code = proc.returncode

        status = (
            "completed" if return_code == 0 else "failed"
        )

    except subprocess.TimeoutExpired as exc:

        stdout = as_text(exc.stdout)
        stderr = as_text(exc.stderr) + "\nTIMEOUT"

        return_code = 124
        status = "timeout"

    except OSError as exc:

        stdout = ""
        stderr = str(exc)

        return_code = 127
        status = "execution_error"

    end_time = now_utc()

    elapsed = round(time.monotonic() - t0, 3)

    (run_dir / "stdout.log").write_text(
        stdout, encoding="utf-8"
    )

    (run_dir / "stderr.log").write_text(
        stderr, encoding="utf-8"
    )

    (run_dir / "command.txt").write_text(
        command_text + "\n",
        encoding="utf-8"
    )

    record = {
        "run_id": run_id,
        "scenario_id": args.profile,
        "tool": profile["tool"],
        "target": args.target,
        "target_ip": target_ip,
        "lab_cidr": args.lab_cidr,
        "command_profile": args.profile,
        "command": command_text,
        "intensity": profile["intensity"],
        "expected_label": profile["expected_label"],
        "start_time": start_time,
        "end_time": end_time,
        "elapsed_seconds": elapsed,
        "return_code": return_code,
        "status": status,
        "output_path": str(run_dir),
        "primary_output_path": primary_output
    }

    gt_path = Path(args.ground_truth)
    gt_path.parent.mkdir(parents=True, exist_ok=True)

    with gt_path.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(record, ensure_ascii=False) + "\n"
        )

    (run_dir / "ground_truth.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print()
    print(json.dumps(record, indent=2, ensure_ascii=False))

    if return_code != 0:
        raise SystemExit(return_code)


if __name__ == "__main__":
    main()
