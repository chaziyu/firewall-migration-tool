from __future__ import annotations

import logging
from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


logger = logging.getLogger(__name__)


def migrate_ir_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" not in payload:
        return _migrate_unversioned(payload)
    if payload.get("schema_version") == "1.0":
        return _migrate_1_0(payload)
    return dict(payload)


def _migrate_1_0(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.0; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated.setdefault("vpn_phase2", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_unversioned(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded unversioned legacy IR; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
