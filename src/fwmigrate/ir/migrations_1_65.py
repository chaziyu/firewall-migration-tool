from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_64_to_1_65(payload: dict[str, Any]) -> dict[str, Any]:
    '''Promote payloads after additive Check Point NAT provenance fields.'''
    if payload.get('schema_version') != '1.64':
        return dict(payload)
    migrated = dict(payload)
    migrated['schema_version'] = IR_SCHEMA_VERSION
    return migrated
