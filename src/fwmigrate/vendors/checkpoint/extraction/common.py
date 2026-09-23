from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Iterable, Optional

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..models import CheckPointResponse
from ..source_model import CheckPointSourceRecord


class SemanticKind(str, Enum):
    ADDRESS = "ADDRESS"
    ADDRESS_GROUP = "ADDRESS_GROUP"
    SECURITY_ZONE = "SECURITY_ZONE"
    SERVICE = "SERVICE"
    SERVICE_GROUP = "SERVICE_GROUP"
    APPLICATION = "APPLICATION"
    APPLICATION_GROUP = "APPLICATION_GROUP"
    APPLICATION_CATEGORY = "APPLICATION_CATEGORY"
    TIME = "TIME"
    TIME_GROUP = "TIME_GROUP"
    INSTALL_TARGET = "INSTALL_TARGET"
    UNKNOWN = "UNKNOWN"


def iter_dictionary_objects(objects: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(objects, dict):
        for key, item in objects.items():
            if isinstance(item, dict):
                value = dict(item)
                if not value.get("uid") and key:
                    value["uid"] = str(key)
                yield value
    elif isinstance(objects, list):
        yield from (dict(item) for item in objects if isinstance(item, dict))


def infer_semantic_kind(obj_type: Optional[str], name: Optional[str] = None) -> SemanticKind:
    del name
    value = (obj_type or "").strip().lower()
    if value in {"host", "network", "address-range", "multicast-address-range", "wildcard"}:
        return SemanticKind.ADDRESS
    if value in {"group", "group-with-exclusion"}:
        return SemanticKind.ADDRESS_GROUP
    if value == "security-zone":
        return SemanticKind.SECURITY_ZONE
    if value.startswith("service-"):
        return SemanticKind.SERVICE
    if value == "service-group":
        return SemanticKind.SERVICE_GROUP
    if value in {"application-site", "application"}:
        return SemanticKind.APPLICATION
    if value in {"application-site-group", "application-group"}:
        return SemanticKind.APPLICATION_GROUP
    if value in {"application-site-category", "application-category"}:
        return SemanticKind.APPLICATION_CATEGORY
    if value == "time":
        return SemanticKind.TIME
    if value == "time-group":
        return SemanticKind.TIME_GROUP
    if value in {"checkpointgateway", "checkpointcluster", "simplegateway", "simplecluster", "simple-gateway", "simple-cluster", "checkpoint-gateway", "checkpoint-cluster", "gateway", "cluster"}:
        return SemanticKind.INSTALL_TARGET
    return SemanticKind.UNKNOWN


def source_plane(response: CheckPointResponse) -> str:
    return "gaia" if response.command.startswith("gaia/") else "management"


def values(response: CheckPointResponse) -> Iterable[dict[str, Any]]:
    for key in ("objects", "rulebase", "rules", "items", "interfaces", "routes"):
        value = response.data.get(key)
        if isinstance(value, dict):
            yield from iter_dictionary_objects(value)
        elif isinstance(value, list):
            yield from (item for item in value if isinstance(item, dict))
            return


def record(response: CheckPointResponse, value: dict[str, Any], order: int | None = None) -> CheckPointSourceRecord:
    references = [value[key] for key in ("source", "destination", "service", "install-on", "members", "objects", "gateway", "vpn") if key in value]
    return CheckPointSourceRecord(
        uid=str(value["uid"]) if value.get("uid") is not None else None,
        name=str(value["name"]) if value.get("name") is not None else None,
        object_type=str(value["type"]) if value.get("type") is not None else None,
        source_plane=source_plane(response), command=response.command,
        domain=response.domain, domain_uid=response.domain_uid,
        package=response.package, package_uid=response.package_uid,
        layer=response.layer, layer_uid=response.layer_uid,
        parent_layer_uid=response.parent_layer_uid, gateway=response.gateway,
        order=order, members=list(value.get("members") or []), references=references,
        source_attributes=sanitize_source_attributes(dict(value)),
    )
