"""Deterministic, pair-scoped Juniper object and plan identities."""

import hashlib
import json
import re


def item_key(source_vdom: str, family: str, source_name: str) -> str:
    return json.dumps([source_vdom, family, source_name], ensure_ascii=True, separators=(",", ":"))


def decision_key(source_vdom: str | None, source_kind: str, source_name: str, target_field: str) -> str:
    return json.dumps([source_vdom or "", source_kind, source_name, target_field], ensure_ascii=True, separators=(",", ":"))


def target_name(family: str, source_vdom: str, source_name: str) -> str:
    prefix = {
        "address": "fg-address",
        "address_group": "fg-address-set",
        "service": "fg-application",
        "service_group": "fg-application-set",
        "interface": "fg-interface",
        "zone": "fg-zone",
        "static_route": "fg-route",
        "policy": "fg-policy",
        "schedule": "fg-schedule",
        "nat": "fg-nat",
    }.get(family, "fg-object")
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", source_name).strip("-_").lower() or "unnamed"
    suffix = hashlib.sha256(f"{source_vdom}\0{family}\0{source_name}".encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{slug[:34]}-{suffix}"
