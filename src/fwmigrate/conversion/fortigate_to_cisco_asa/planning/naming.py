"""Stable identities and safe ASA object names."""

import hashlib
import json
import re


def item_key(vdom: str, family: str, source_name: str) -> str:
    return json.dumps([vdom, family, source_name], ensure_ascii=True, separators=(",", ":"))


def decision_key(vdom: str | None, kind: str, name: str, field: str) -> str:
    return json.dumps([vdom or "", kind, name, field], ensure_ascii=True, separators=(",", ":"))


def target_name(family: str, vdom: str, source_name: str) -> str:
    prefix = {"address": "fg_addr", "address_group": "fg_ag", "service": "fg_svc",
              "service_group": "fg_sg", "interface": "fg_acl", "schedule": "fg_time",
              "static_route": "fg_route", "policy": "fg_acl", "nat": "fg_nat"}.get(family, "fg_item")
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", source_name).strip("_-").lower() or "item"
    suffix = hashlib.sha256(f"{vdom}\0{family}\0{source_name}".encode()).hexdigest()[:8]
    return f"{prefix}_{slug[:35]}_{suffix}"
