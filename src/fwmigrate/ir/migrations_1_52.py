from __future__ import annotations

import logging
from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


logger = logging.getLogger(__name__)


def migrate_1_51_to_1_52(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote schema 1.51 payloads for the additive dynamic-IP NAT enum value.

    Schema 1.52 adds no required fields to existing serialized objects. Existing
    1.51 payloads therefore migrate losslessly by updating only the schema
    version marker.
    """
    if payload.get("schema_version") != "1.51":
        return dict(payload)

    logger.warning("Loaded IR schema 1.51; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
