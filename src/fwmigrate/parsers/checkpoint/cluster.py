"""Source-only extraction of persistent Check Point cluster topology."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRHighAvailability
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def _list(value: Any) -> List[Any]:
    if isinstance(value, list): return value
    return [] if value is None else [value]


def extract_clusters(responses: Iterable[CheckPointResponse]) -> Tuple[List[IRHighAvailability], List[SourceInventoryItem]]:
    clusters: List[IRHighAvailability] = []
    inventory: List[SourceInventoryItem] = []
    for response in responses:
        if canonicalize_command(response.command) not in {"show-gateways-and-servers", "show-simple-clusters"}: continue
        objects = response.data.get("objects", [])
        objects = list(objects.values()) if isinstance(objects, dict) else objects
        for obj in objects if isinstance(objects, list) else []:
            if not isinstance(obj, dict) or "cluster" not in str(obj.get("type", "")).lower(): continue
            members = _list(obj.get("members") or obj.get("member-gateways") or obj.get("cluster-members"))
            refs = [str(m.get("uid") or m.get("name")) if isinstance(m, dict) else str(m) for m in members]
            attrs = dict(obj)
            cluster = IRHighAvailability(
                source_uuid=obj.get("uid"), cluster_uid=obj.get("uid"), name=str(obj.get("name") or obj.get("uid") or "cluster"),
                mode=obj.get("cluster-mode") or obj.get("mode"), member_references=refs,
                virtual_ips=[str(v.get("ipv4-address") or v.get("ipv6-address") or v.get("address") or v) if isinstance(v, dict) else str(v)
                             for v in _list(obj.get("virtual-ips") or obj.get("virtual-ip-addresses") or obj.get("vip"))],
                sync_interfaces=[str(v.get("name") or v) if isinstance(v, dict) else str(v) for v in _list(obj.get("sync-interfaces") or obj.get("sync-interface"))],
                sync_network=obj.get("sync-network"), cluster_interfaces=_list(obj.get("interfaces")),
                topology=dict(obj.get("topology")) if isinstance(obj.get("topology"), dict) else {},
                ha_settings=dict(obj.get("ha-settings") or obj.get("cluster-settings") or {}), source_attributes=attrs,
            )
            clusters.append(cluster)
            inventory.append(SourceInventoryItem(
                domain=response.domain or "global", source_path="checkpoint/show-gateways-and-servers",
                name=cluster.name, source_id=cluster.source_uuid, source_type="clusterxl",
                source_attributes=attrs, status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
                notes=["persistent management object topology; operational state excluded"],
            ))
    return clusters, inventory
