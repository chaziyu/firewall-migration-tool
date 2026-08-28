#!/usr/bin/env python3
"""
Offline Check Point R81 Configuration Bundle Exporter.

Executes mgmt_cli commands against Check Point R80/R81 Management Server
and bundles the output into a standardized `checkpoint-export-v1` format.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Dict, List, Optional


COMMANDS = [
    ("show-gateways-and-servers", {"details-level": "full"}),
    ("show-hosts", {"details-level": "full", "limit": 500}),
    ("show-networks", {"details-level": "full", "limit": 500}),
    ("show-address-ranges", {"details-level": "full", "limit": 500}),
    ("show-groups", {"details-level": "full", "limit": 500}),
    ("show-groups-with-exclusion", {"details-level": "full", "limit": 500}),
    ("show-security-zones", {"details-level": "full", "limit": 500}),
    ("show-services-tcp", {"details-level": "full", "limit": 500}),
    ("show-services-udp", {"details-level": "full", "limit": 500}),
    ("show-services-sctp", {"details-level": "full", "limit": 500}),
    ("show-services-icmp", {"details-level": "full", "limit": 500}),
    ("show-services-icmp6", {"details-level": "full", "limit": 500}),
    ("show-services-other", {"details-level": "full", "limit": 500}),
    ("show-service-groups", {"details-level": "full", "limit": 500}),
    ("show-times", {"details-level": "full", "limit": 500}),
    ("show-time-groups", {"details-level": "full", "limit": 500}),
    ("show-packages", {"details-level": "full", "limit": 100}),
]


def run_mgmt_cli(cmd: str, payload: Dict[str, Any], session_id: Optional[str] = None) -> Dict[str, Any]:
    """Execute a single mgmt_cli command returning parsed JSON output."""
    cli_cmd = ["mgmt_cli", cmd, "--format", "json"]
    if session_id:
        cli_cmd.extend(["-s", session_id])

    for k, v in payload.items():
        cli_cmd.extend([k, str(v)])

    try:
        proc = subprocess.run(cli_cmd, capture_output=True, text=True, check=True)
        return json.loads(proc.stdout)
    except subprocess.CalledProcessError as exc:
        print(f"[WARN] mgmt_cli command '{cmd}' failed: {exc.stderr.strip()}", file=sys.stderr)
        return {"error": exc.stderr.strip(), "objects": []}
    except Exception as exc:
        print(f"[WARN] Failed to parse output for '{cmd}': {exc}", file=sys.stderr)
        return {"error": str(exc), "objects": []}


def export_bundle(
    package: str = "Standard",
    layer: str = "Network",
    session_id: Optional[str] = None,
    output_file: str = "checkpoint_bundle.json",
) -> None:
    """Export complete management configuration into JSON bundle."""
    responses: List[Dict[str, Any]] = []

    print(f"[*] Exporting Check Point objects...")
    for cmd, payload in COMMANDS:
        print(f"  -> Running {cmd}...")
        data = run_mgmt_cli(cmd, payload, session_id=session_id)
        responses.append({
            "command": cmd,
            "data": data,
        })

    print(f"[*] Exporting Access Rulebase for package '{package}', layer '{layer}'...")
    access_data = run_mgmt_cli(
        "show-access-rulebase",
        {"name": f"{package} {layer}", "details-level": "full", "use-object-dictionary": "true"},
        session_id=session_id,
    )
    responses.append({
        "command": "show-access-rulebase",
        "package": package,
        "layer": layer,
        "data": access_data,
    })

    print(f"[*] Exporting NAT Rulebase for package '{package}'...")
    nat_data = run_mgmt_cli(
        "show-nat-rulebase",
        {"package": package, "details-level": "full", "use-object-dictionary": "true"},
        session_id=session_id,
    )
    responses.append({
        "command": "show-nat-rulebase",
        "package": package,
        "data": nat_data,
    })

    bundle = {
        "format": "checkpoint-export-v1",
        "api_version": "1.8",
        "package": package,
        "layer": layer,
        "responses": responses,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    print(f"[+] Successfully exported configuration bundle to '{output_file}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Check Point R81 management bundle")
    parser.add_argument("--package", default="Standard", help="Policy package name (default: Standard)")
    parser.add_argument("--layer", default="Network", help="Access layer name (default: Network)")
    parser.add_argument("--session-id", help="mgmt_cli session ID (or use MGMT_CLI_SESSION env var)")
    parser.add_argument("-o", "--output", default="checkpoint_bundle.json", help="Output file path")
    args = parser.parse_args()

    export_bundle(
        package=args.package,
        layer=args.layer,
        session_id=args.session_id,
        output_file=args.output,
    )
