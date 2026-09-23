"""Portable, validated acquisition envelope for vendor-native source text."""

import json
import re
from dataclasses import asdict

from fwmigrate.extraction.sanitize import is_sensitive_key, sanitize_raw_text, sanitize_source_attributes
from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import FMC_BUNDLE_FORMAT

from .contracts import CollectedSource, CollectionPart, CollectionStatus


FORMAT = "fwmigrate-collection-snapshot-v1"
MAX_BYTES = 25_000_000


def _unsafe_keys(value) -> bool:
    if isinstance(value, dict):
        return any(is_sensitive_key(str(key)) or _unsafe_keys(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_unsafe_keys(item) for item in value)
    return False


def sanitize_source(vendor_id: str, source_text: str) -> str:
    if vendor_id in {"cisco_ftd", "checkpoint"}:
        data = json.loads(source_text)
        if not isinstance(data, dict):
            raise ValueError("The vendor source must be a JSON object.")
        expected = FMC_BUNDLE_FORMAT if vendor_id == "cisco_ftd" else "checkpoint-export-v1"
        if data.get("format") != expected:
            raise ValueError("Unsupported vendor source format.")
        return json.dumps(sanitize_source_attributes(data))
    if vendor_id == "cisco_asa" or vendor_id == "juniper_srx":
        return sanitize_raw_text(source_text)
    raise ValueError("Snapshot vendor has no supported live source format.")


def make_snapshot(source: CollectedSource) -> dict:
    safe_text = sanitize_source(source.vendor_id, source.source_text)
    if len(safe_text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Collected source exceeds the snapshot size limit.")
    snapshot = {
        "format": FORMAT,
        "vendor_id": source.vendor_id,
        "source_name": source.source_name,
        "collection_method": source.method,
        "status": source.status.value,
        "metadata": sanitize_source_attributes(source.metadata),
        "parts": [asdict(part) for part in source.parts],
        "warnings": [sanitize_raw_text(warning)[:200] for warning in source.warnings[:100]],
        "source_text": safe_text,
    }
    if len(json.dumps(snapshot).encode("utf-8")) > MAX_BYTES:
        raise ValueError("Collected snapshot exceeds the size limit.")
    return snapshot


def parse_snapshot(raw: bytes) -> CollectedSource:
    if len(raw) > MAX_BYTES:
        raise ValueError("Snapshot exceeds the size limit.")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise ValueError("Unsupported snapshot format or version.")
        vendor = data["vendor_id"]
        status = CollectionStatus(data["status"])
        if status == CollectionStatus.FAILED:
            raise ValueError("A failed collection has no usable snapshot.")
        source = data["source_text"]
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Snapshot source_text is required.")
        name, method = data["source_name"], data["collection_method"]
        if not all(isinstance(item, str) and 0 < len(item) < 256 for item in (vendor, name, method)) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in {".", ".."}:
            raise ValueError("Snapshot identity is invalid.")
        metadata, parts, warnings = data.get("metadata", {}), data.get("parts", []), data.get("warnings", [])
        if not isinstance(metadata, dict) or set(metadata) - {"domain", "package"} or _unsafe_keys(metadata) or any(value is not None and (not isinstance(value, str) or len(value) > 256) for value in metadata.values()):
            raise ValueError("Snapshot metadata is unsafe.")
        if not isinstance(parts, list) or len(parts) > 500 or not isinstance(warnings, list) or len(warnings) > 100:
            raise ValueError("Snapshot parts or warnings are invalid.")
        parsed_parts = tuple(CollectionPart(**part) for part in parts)
        if any(not isinstance(part.name, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,100}", part.name) or part.status not in {"SUCCESS", "EMPTY", "FAILED", "SUCCESS_WITH_DATA", "SUCCESS_EMPTY", "UNSUPPORTED_COMMAND", "PERMISSION_DENIED", "API_ERROR", "TRANSPORT_ERROR"} or not isinstance(part.complete, bool) or (part.count is not None and (not isinstance(part.count, int) or part.count < 0)) for part in parsed_parts):
            raise ValueError("Snapshot parts are invalid.")
        if any(not isinstance(warning, str) or len(warning) > 200 for warning in warnings):
            raise ValueError("Snapshot warnings are invalid.")
        return CollectedSource(vendor, sanitize_source(vendor, source), name, method, status,
                               metadata, parsed_parts, tuple(sanitize_raw_text(warning) for warning in warnings))
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed collection snapshot.") from exc
