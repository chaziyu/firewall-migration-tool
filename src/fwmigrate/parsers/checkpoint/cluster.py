"""Source-only extraction of persistent Check Point cluster topology."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRClusterInterface, IRHighAvailability
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


_CLUSTER_TYPES = {"checkpoint-cluster", "simple-cluster", "cluster"}


def _is_cluster_object(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    value = str(obj.get("type") or obj.get("object-type") or "").strip().lower().replace("_", "-")
    return value in _CLUSTER_TYPES or value.endswith("-cluster")


def _first(obj: Dict[str, Any], *keys: str) -> Any:
    return next((obj[key] for key in keys if obj.get(key) not in (None, "")), None)


def _address(value: Any, version: Optional[int] = None) -> Optional[str]:
    if isinstance(value, dict):
        value = _first(value, "address", "ip-address", "ipv4-address", "ipv6-address")
    if value in (None, ""):
        return None
    try:
        parsed = ipaddress.ip_address(str(value).split("/")[0])
        if version and parsed.version != version:
            return None
        return str(parsed)
    except ValueError:
        return None


def _mode(obj: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    raw = _first(obj, "cluster-mode", "cluster_mode", "cluster-type", "high-availability", "load-sharing")
    text = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    if "load" in text:
        return "load-sharing", None if text in {"load-sharing", "load sharing", "true"} else str(raw)
    if text in {"ha", "high-availability", "high availability", "active/standby", "active-passive"} or obj.get("high-availability") is True:
        return "high-availability", None if text in {"ha", "high-availability", "high availability"} else str(raw)
    return "unknown", str(raw) if raw is not None else None


def _member_data(members: List[Any]) -> Tuple[List[str], List[str], Dict[str, List[str]], List[SourceInventoryItem], bool]:
    refs, names, addresses, inventory = [], [], {}, []
    partial = False
    for member in members:
        if not isinstance(member, dict):
            uid = str(member)
            refs.append(uid)
            inventory.append(SourceInventoryItem(domain="global", source_path="checkpoint/cluster/member", name=uid, source_id=uid, source_type="checkpoint-cluster-member", status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True, notes=["malformed-member-structure"]))
            partial = True
            continue
        uid = str(member.get("uid") or member.get("name") or "")
        if not uid:
            partial = True
            continue
        refs.append(uid)
        if member.get("name"):
            names.append(str(member["name"]))
        member_ips = []
        for iface in _list(member.get("interfaces")):
            if isinstance(iface, dict):
                member_ips.extend(a for a in (_address(_first(iface, "ipv4-address", "ipv6-address")),) if a)
        for key in ("ipv4-address", "ipv6-address", "main-ip-address"):
            if (a := _address(member.get(key))): member_ips.append(a)
        if member_ips: addresses[uid] = list(dict.fromkeys(member_ips))
        inventory.append(SourceInventoryItem(domain="global", source_path="checkpoint/cluster/member", name=str(member.get("name") or uid), source_id=uid, source_type="checkpoint-cluster-member", source_attributes=dict(member), status=ExtractionStatus.NORMALIZED, requires_manual_review=False))
    return refs, names, addresses, inventory, partial


def extract_clusters(responses: Iterable[CheckPointResponse]) -> Tuple[List[IRHighAvailability], List[SourceInventoryItem]]:
    responses = list(responses)
    gateway_objects = {
        str(obj.get("uid")): obj
        for response in responses
        for obj in _list(response.data.get("objects"))
        if isinstance(obj, dict) and obj.get("uid")
    }
    clusters: Dict[str, IRHighAvailability] = {}
    inventory: List[SourceInventoryItem] = []
    for response in responses:
        command = canonicalize_command(response.command)
        if command in {"cphaprob-state", "cphaprob-a-if", "cphaprob-syncstat", "clusterxl-admin"}:
            inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}", name="cluster-operational-state", source_type="checkpoint-cluster-operational-state", source_attributes={"command": response.command, "data": response.data}, status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=False, notes=["runtime evidence; not persistent configuration"]))
            continue
        if command not in {"show-gateways-and-servers", "show-simple-clusters", "show-simple-gateways"}: continue
        objects = response.data.get("objects", [])
        objects = list(objects.values()) if isinstance(objects, dict) else objects
        for obj in objects if isinstance(objects, list) else []:
            if not _is_cluster_object(obj): continue
            members = _list(obj.get("members") or obj.get("member-gateways") or obj.get("cluster-members"))
            refs, names, member_ips, member_inv, partial = _member_data(members)
            for member_id in refs:
                gateway = gateway_objects.get(member_id)
                if gateway is None:
                    partial = True
                    inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}", name=member_id, source_id=member_id, source_type="checkpoint-cluster-member", status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True, notes=["unresolved-cluster-member"]))
                    continue
                if member_id not in member_ips:
                    _, _, resolved_ips, _, _ = _member_data([gateway])
                    member_ips.update(resolved_ips)
            mode, raw_mode = _mode(obj)
            vips, bad = [], False
            for value in _list(obj.get("virtual-ips") or obj.get("virtual-ip-addresses") or obj.get("vip")):
                address = _address(value)
                bad |= address is None
                if address: vips.append(address)
            interfaces = []
            for raw in _list(obj.get("interfaces")):
                if not isinstance(raw, dict) or not raw.get("name"):
                    partial = True
                    continue
                member_addresses = {}
                for member in _list(raw.get("members") or raw.get("member-addresses")):
                    if isinstance(member, dict):
                        key = str(member.get("uid") or member.get("name") or "")
                        value = _address(_first(member, "address", "ipv4-address", "ipv6-address"))
                        if key and value: member_addresses.setdefault(key, []).append(value)
                for key, values in member_addresses.items():
                    member_ips.setdefault(key, []).extend(values)
                vip4, vip6 = _address(_first(raw, "virtual-ipv4", "virtual-ip", "ipv4-address"), 4), _address(_first(raw, "virtual-ipv6", "ipv6-address"), 6)
                if _first(raw, "virtual-ipv4", "virtual-ip", "ipv4-address") and not vip4: bad = True
                if _first(raw, "virtual-ipv6", "ipv6-address") and not vip6: bad = True
                interfaces.append(IRClusterInterface(name=str(raw["name"]), virtual_ipv4=vip4, virtual_ipv6=vip6, member_addresses=member_addresses, topology=raw.get("topology"), interface_role=raw.get("interface-role") or raw.get("role"), sync=raw.get("sync") if isinstance(raw.get("sync"), bool) else None, anti_spoofing=_first(raw, "anti-spoofing", "anti_spoofing"), source_attributes=dict(raw)))
                vips.extend(a for a in (vip4, vip6) if a)
                inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}/interface", name=str(raw["name"]), source_id=obj.get("uid"), source_type="checkpoint-cluster-interface", source_attributes=dict(raw), status=ExtractionStatus.NORMALIZED, requires_manual_review=False))
            for vip in dict.fromkeys(vips):
                inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}/vip", name=vip, source_id=obj.get("uid"), source_type="checkpoint-cluster-vip", source_attributes={"address": vip}, status=ExtractionStatus.NORMALIZED, requires_manual_review=False))
            sync_values = [str(v.get("name") or v) if isinstance(v, dict) else str(v) for v in _list(obj.get("sync-interfaces") or obj.get("sync-interface"))]
            sync_network = obj.get("sync-network")
            if sync_network is not None:
                try:
                    sync_network = str(ipaddress.ip_network(str(sync_network), strict=False))
                except ValueError:
                    partial = True
                    inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}/sync", name="sync-network", source_id=obj.get("uid"), source_type="checkpoint-cluster-sync", source_attributes={"value": sync_network}, status=ExtractionStatus.PARSE_ERROR, requires_manual_review=True, notes=["invalid-sync-network"]))
                    sync_network = None
            for sync in sync_values:
                inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}/sync", name=sync, source_id=obj.get("uid"), source_type="checkpoint-cluster-sync", source_attributes={"interface": sync, "network": obj.get("sync-network")}, status=ExtractionStatus.NORMALIZED, requires_manual_review=False))
            status = "PARTIALLY_NORMALIZED" if partial or mode == "unknown" or raw_mode or bad else "NORMALIZED"
            if bad:
                inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}", name=str(obj.get("name") or obj.get("uid") or "cluster"), source_id=obj.get("uid"), source_type="checkpoint-cluster-interface", source_attributes=dict(obj), status=ExtractionStatus.PARSE_ERROR, requires_manual_review=True, notes=["invalid-cluster-address"]))
            inventory.extend(member_inv)
            attrs = dict(obj)
            key = str(obj.get("uid") or f"{response.domain or 'global'}:{obj.get('name')}:{obj.get('type')}")
            cluster = IRHighAvailability(
                source_uuid=obj.get("uid"), cluster_uid=obj.get("uid"), name=str(obj.get("name") or obj.get("uid") or "cluster"),
                cluster_type=str(obj.get("type") or obj.get("object-type") or "cluster"), mode=mode, member_references=refs, member_names=names, member_interface_ips=member_ips,
                virtual_ips=list(dict.fromkeys(vips)),
                sync_interfaces=sync_values,
                sync_network=sync_network, cluster_interfaces=interfaces,
                topology=dict(obj.get("topology")) if isinstance(obj.get("topology"), dict) else {},
                ha_settings=dict(obj.get("ha-settings") or obj.get("cluster-settings") or {}), source_attributes=attrs,
                migration_status=status, requires_manual_review=status != "NORMALIZED",
            )
            if key in clusters:
                clusters[key].source_attributes.setdefault("duplicate-source-responses", []).append(attrs)
                continue
            clusters[key] = cluster
            inventory.append(SourceInventoryItem(
                domain=response.domain or "global", source_path=f"checkpoint/{command}", name=cluster.name, source_id=cluster.source_uuid, source_type="checkpoint-cluster",
                source_attributes=attrs, status=ExtractionStatus(status), requires_manual_review=cluster.requires_manual_review,
                notes=["persistent management object topology; operational state excluded"],
            ))
    return list(clusters.values()), inventory
