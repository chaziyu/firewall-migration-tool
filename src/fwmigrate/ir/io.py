from __future__ import annotations

import json
from typing import Any

from fwmigrate.ir import IRConfig
from fwmigrate.ir.errors import IRSchemaError
from fwmigrate.ir.version import CURRENT_IR_SCHEMA_VERSION, LEGACY_IR_SCHEMA_VERSION


def _migrate_legacy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(payload)
    legacy_vendor_security_policies = migrated.pop("security_policies", None)
    if "policies" in migrated:
        migrated["security_policies"] = migrated.pop("policies")
    metadata = migrated.get("metadata")
    if isinstance(metadata, dict):
        metadata = dict(metadata)
        metadata.setdefault("source_vendor", "fortinet")
        migrated["metadata"] = metadata
    migrated["schema_version"] = CURRENT_IR_SCHEMA_VERSION
    if legacy_vendor_security_policies:
        extensions = dict(migrated.get("vendor_extensions") or {})
        fortios = dict(extensions.get("fortios") or {})
        fortios.setdefault("security_policies", legacy_vendor_security_policies)
        extensions["fortios"] = fortios
        migrated["vendor_extensions"] = extensions
    nat_rules = migrated.get("nat_rules")
    if isinstance(nat_rules, list):
        migrated["nat_rules"] = [
            {
                **rule,
                "type": "source",
                "source_origin": rule.get("source_origin") or "central-snat-map",
            }
            if isinstance(rule, dict) and rule.get("type") == "central"
            else rule
            for rule in nat_rules
        ]
    return migrated


def load_ir_payload(payload: dict[str, Any]) -> IRConfig:
    if not isinstance(payload, dict):
        raise IRSchemaError("Serialized IR payload must be a JSON object.")

    version = payload.get("schema_version")
    if isinstance(version, bool) or (version is not None and not isinstance(version, int)):
        raise IRSchemaError("IR schema_version must be an integer.")
    if version is None or version == LEGACY_IR_SCHEMA_VERSION:
        payload = _migrate_legacy_payload(payload)
    elif version != CURRENT_IR_SCHEMA_VERSION:
        raise IRSchemaError(
            f"Unsupported IR schema_version {version}; expected {CURRENT_IR_SCHEMA_VERSION}."
        )

    return IRConfig.model_validate(payload)


def load_ir_json(payload: str) -> IRConfig:
    raw = json.loads(payload)
    return load_ir_payload(raw)


def dump_ir_json(ir_config: IRConfig, **kwargs: Any) -> str:
    return ir_config.model_dump_json(**kwargs)
