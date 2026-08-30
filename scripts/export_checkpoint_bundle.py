#!/usr/bin/env python3
"""
Live Check Point R81 Configuration Bundle Collector.

Executes mgmt_cli commands against Check Point R80/R81 Management Server
and bundles the output into a standardized `checkpoint-export-v1` format.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


COLLECTION_MANIFEST = {
  "core_objects": [
    ("show-gateways-and-servers", {"details-level": "full"}),
    ("show-hosts", {"details-level": "full", "limit": 500}),
    ("show-networks", {"details-level": "full", "limit": 500}),
    ("show-address-ranges", {"details-level": "full", "limit": 500}),
    ("show-wildcards", {"details-level": "full", "limit": 500}),
    ("show-multicast-address-ranges", {"details-level": "full", "limit": 500}),
    ("show-dynamic-objects", {"details-level": "full", "limit": 500}),
    ("show-dns-domains", {"details-level": "full", "limit": 500}),
    ("show-network-feeds", {"details-level": "full", "limit": 500}),
    ("show-checkpoint-hosts", {"details-level": "full", "limit": 500}),
    ("show-interoperable-devices", {"details-level": "full", "limit": 500}),
    ("show-updatable-objects", {"details-level": "full", "limit": 500}),
    ("show-data-center-objects", {"details-level": "full", "limit": 500}),
    ("show-groups", {"details-level": "full", "limit": 500}),
    ("show-groups-with-exclusion", {"details-level": "full", "limit": 500}),
    ("show-security-zones", {"details-level": "full", "limit": 500}),
  ],
  "services": [
    ("show-services-tcp", {"details-level": "full", "limit": 500}),
    ("show-services-udp", {"details-level": "full", "limit": 500}),
    ("show-services-sctp", {"details-level": "full", "limit": 500}),
    ("show-services-icmp", {"details-level": "full", "limit": 500}),
    ("show-services-icmp6", {"details-level": "full", "limit": 500}),
    ("show-services-other", {"details-level": "full", "limit": 500}),
    ("show-service-groups", {"details-level": "full", "limit": 500}),
    ("show-services-citrix-tcp", {"details-level": "full", "limit": 500}),
    ("show-services-dce-rpc", {"details-level": "full", "limit": 500}),
    ("show-services-rpc", {"details-level": "full", "limit": 500}),
    ("show-services-gtp", {"details-level": "full", "limit": 500}),
    ("show-services-compound-tcp", {"details-level": "full", "limit": 500}),
  ],
  "time": [
    ("show-times", {"details-level": "full", "limit": 500}),
    ("show-time-groups", {"details-level": "full", "limit": 500}),
  ],
  "policy_metadata": [
    ("show-packages", {"details-level": "full", "limit": 100}),
    ("show-access-layers", {"details-level": "full", "limit": 500}),
  ],
  "applications_identity": [
    ("show-access-roles", {"details-level": "full", "limit": 500}),
    ("show-application-sites", {"details-level": "full", "limit": 500}),
    ("show-application-site-groups", {"details-level": "full", "limit": 500}),
    ("show-application-site-categories", {"details-level": "full", "limit": 500}),
  ],
  "vpn": [
    ("show-vpn-communities-meshed", {"details-level": "full", "limit": 500}),
    ("show-vpn-communities-star", {"details-level": "full", "limit": 500}),
    ("show-vpn-communities-remote-access", {"details-level": "full", "limit": 500}),
  ],
}

COMMANDS = [entry for group in COLLECTION_MANIFEST.values() for entry in group]


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
        return {"collection_status": "ERROR", "error": exc.stderr.strip(), "data": {}}
    except Exception as exc:
        print(f"[WARN] Failed to parse output for '{cmd}': {exc}", file=sys.stderr)
        return {"collection_status": "ERROR", "error": str(exc), "data": {}}


def collect_paginated(
    cmd: str,
    payload: Dict[str, Any],
    session_id: Optional[str] = None,
    **scope: Any,
) -> List[Dict[str, Any]]:
    """Collect every API page and retain page boundaries as separate bundle responses."""
    responses: List[Dict[str, Any]] = []
    limit = int(payload.get("limit", 500))
    offset = int(payload.get("offset", 0))
    while True:
        page_payload = dict(payload)
        page_payload["limit"] = limit
        page_payload["offset"] = offset
        data = run_mgmt_cli(cmd, page_payload, session_id=session_id)
        if data.get("collection_status") == "ERROR":
            responses.append({"command": cmd, **scope, **data})
            break

        response: Dict[str, Any] = {"command": cmd, **scope, "collection_status": "OK", "data": data}
        for key in ("from", "to", "total"):
            if data.get(key) is not None:
                response[key] = data[key]
        responses.append(response)

        from_index, to_index, total = data.get("from"), data.get("to"), data.get("total")
        if total is None or from_index is None or to_index is None or int(to_index) >= int(total):
            break
        next_offset = int(to_index)
        if next_offset <= offset:
            responses.append({
                "command": cmd, **scope, "collection_status": "ERROR",
                "error": f"Pagination did not advance after offset {offset}", "data": {},
            })
            break
        offset = next_offset
    return responses


def _objects_from_responses(responses: Iterable[Dict[str, Any]], command: str) -> List[Dict[str, Any]]:
    objects: List[Dict[str, Any]] = []
    for response in responses:
        if response.get("command") != command:
            continue
        raw = response.get("data", {}).get("objects", [])
        if isinstance(raw, dict):
            raw = list(raw.values())
        objects.extend(item for item in raw if isinstance(item, dict))
    return objects


def _discover_package_layers(
    responses: List[Dict[str, Any]], selected_package: Optional[str], selected_layer: Optional[str],
) -> List[Tuple[str, str, Optional[str]]]:
    """Use package access-layer references; never synthesize '<package> <layer>' identities."""
    discovered: List[Tuple[str, str, Optional[str]]] = []
    packages = _objects_from_responses(responses, "show-packages")
    layer_objects = _objects_from_responses(responses, "show-access-layers")
    layer_by_uid = {str(item.get("uid")): item for item in layer_objects if item.get("uid")}
    for package in packages:
        package_name = str(package.get("name") or "")
        if not package_name or (selected_package and package_name != selected_package):
            continue
        refs = package.get("access-layers") or package.get("access-layers-settings") or []
        if isinstance(refs, dict):
            refs = refs.get("objects", refs.get("layers", []))
        for ref in refs if isinstance(refs, list) else []:
            uid = str(ref.get("uid")) if isinstance(ref, dict) and ref.get("uid") else None
            obj = layer_by_uid.get(uid or "", {})
            name = str((ref.get("name") if isinstance(ref, dict) else ref) or obj.get("name") or "")
            if name and (not selected_layer or name == selected_layer or uid == selected_layer):
                discovered.append((package_name, name, uid))
    if selected_package and selected_layer and not discovered:
        discovered.append((selected_package, selected_layer, selected_layer if "-" in selected_layer else None))
    return list(dict.fromkeys(discovered))


def _inline_layer_refs(responses: Iterable[Dict[str, Any]]) -> List[Tuple[str, str]]:
    refs: List[Tuple[str, str]] = []
    def walk(entries: Any) -> None:
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ref = entry.get("inline-layer") or entry.get("inline_layer")
            if ref:
                uid = str(ref.get("uid") or "") if isinstance(ref, dict) else str(ref)
                name = str(ref.get("name") or uid) if isinstance(ref, dict) else str(ref)
                refs.append((uid, name))
            walk(entry.get("rulebase"))
    for response in responses:
        walk(response.get("data", {}).get("rulebase"))
    return refs


def collect_access_layer_tree(
    package: str, layer: str, layer_uid: Optional[str], session_id: Optional[str],
) -> List[Dict[str, Any]]:
    responses: List[Dict[str, Any]] = []
    pending: List[Tuple[str, Optional[str]]] = [(layer, layer_uid)]
    visited: Set[str] = set()
    while pending:
        layer_name, uid = pending.pop(0)
        identity = uid or layer_name
        if identity in visited:
            continue
        visited.add(identity)
        pages = collect_paginated(
            "show-access-rulebase",
            {"name": uid or layer_name, "details-level": "full", "use-object-dictionary": "true", "limit": 500},
            session_id=session_id, package=package, layer=uid or layer_name,
        )
        responses.extend(pages)
        for child_uid, child_name in _inline_layer_refs(pages):
            if (child_uid or child_name) not in visited:
                pending.append((child_name, child_uid or None))
    return responses


def export_bundle(
    package: Optional[str] = None,
    layer: Optional[str] = None,
    gateway: Optional[str] = None,
    domain: Optional[str] = None,
    session_id: Optional[str] = None,
    output_file: str = "checkpoint_bundle.json",
) -> None:
    """Export complete management configuration into JSON bundle."""
    responses: List[Dict[str, Any]] = []

    print("[*] Exporting Check Point Management API objects...")
    for group, commands in COLLECTION_MANIFEST.items():
        print(f"  -> {group}")
        for cmd, payload in commands:
            responses.extend(collect_paginated(cmd, payload, session_id=session_id, domain=domain, gateway=gateway))

    package_layers = _discover_package_layers(responses, package, layer)
    packages = sorted({entry[0] for entry in package_layers} or ({package} if package else set()))
    for package_name, layer_name, layer_uid in package_layers:
        print(f"[*] Exporting Access Rulebase '{layer_name}' in package '{package_name}'...")
        responses.extend(collect_access_layer_tree(package_name, layer_name, layer_uid, session_id))
    for package_name in packages:
        print(f"[*] Exporting NAT Rulebase for package '{package_name}'...")
        responses.extend(collect_paginated(
            "show-nat-rulebase",
            {"package": package_name, "details-level": "full", "use-object-dictionary": "true", "limit": 500},
            session_id=session_id, package=package_name, domain=domain, gateway=gateway,
        ))

    bundle = {
        "format": "checkpoint-export-v1",
        "api_version": "1.8",
        "domain": domain,
        "gateway": gateway,
        "selected_domain": domain,
        "selected_package": package,
        "selected_access_layer": layer,
        "selected_access_layer_uid": next((uid for pkg, lyr, uid in package_layers if package == pkg and layer == lyr), None),
        "selected_gateway": gateway,
        "collection_scope": "selected" if any((package, layer, gateway, domain)) else "management-api-discovered",
        "responses": responses,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    print(f"[+] Successfully exported configuration bundle to '{output_file}'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Check Point R81 management bundle")
    parser.add_argument("--package", help="Limit collection to one policy package (default: discover all)")
    parser.add_argument("--layer", help="Limit collection to one Access Layer name or UID")
    parser.add_argument("--gateway", help="Selected gateway name or UID for Install On evaluation")
    parser.add_argument("--domain", help="Management domain scope")
    parser.add_argument("--session-id", help="mgmt_cli session ID (or use MGMT_CLI_SESSION env var)")
    parser.add_argument("-o", "--output", default="checkpoint_bundle.json", help="Output file path")
    args = parser.parse_args()

    export_bundle(
        package=args.package,
        layer=args.layer,
        gateway=args.gateway,
        domain=args.domain,
        session_id=args.session_id,
        output_file=args.output,
    )
