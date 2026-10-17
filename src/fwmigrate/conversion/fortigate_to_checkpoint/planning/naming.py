"""Stable, source-scoped Check Point operation and object identities."""

import hashlib
import re


def item_key(vdom: str, family: str, source_name: str) -> str:
    digest = hashlib.sha256(f"{vdom}\0{family}\0{source_name}".encode("utf-8")).hexdigest()[:16]
    return f"{family}:{digest}"


def target_name(family: str, vdom: str, source_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", source_name).strip("_-") or "object"
    digest = hashlib.sha256(f"{vdom}\0{family}\0{source_name}".encode("utf-8")).hexdigest()[:10]
    return f"fg_{family}_{safe[:40]}_{digest}"

