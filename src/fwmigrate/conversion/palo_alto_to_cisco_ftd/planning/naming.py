"""Stable, source-scoped Cisco FMC operation and object identities."""

import hashlib
import re


def item_key(scope: str, family: str, source_name: str) -> str:
    digest = hashlib.sha256(f"{scope}\0{family}\0{source_name}".encode("utf-8")).hexdigest()[:16]
    return f"{family}:{digest}"


def target_name(family: str, scope: str, source_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", source_name).strip("_-") or "object"
    return safe[:128]
