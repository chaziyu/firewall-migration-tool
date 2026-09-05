"""Source-only Check Point Identity Awareness and Access Role extraction."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRCheckpointAccessRole, IRCheckpointIdentitySource
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def _items(responses: Iterable[CheckPointResponse], commands: set[str]) -> Iterable[Tuple[CheckPointResponse, Dict[str, Any]]]:
    for response in responses:
        if response.command.lower() not in commands:
            continue
        objects = response.data.get("objects", response.data.get("object", []))
        if isinstance(objects, dict):
            objects = list(objects.values())
        if isinstance(objects, dict):
            objects = [objects]
        for item in objects if isinstance(objects, list) else []:
            if isinstance(item, dict):
                yield response, item


def _values(obj: Dict[str, Any], *keys: str) -> List[str]:
    values: List[str] = []
    for key in keys:
        value = obj.get(key)
        value = value if isinstance(value, list) else [value]
        values.extend(
            str(v.get("name") or v.get("uid") or v) if isinstance(v, dict) else str(v)
            for v in value if v not in (None, "")
        )
    return values


def extract_identity(responses: List[CheckPointResponse]) -> Tuple[List[IRCheckpointIdentitySource], List[IRCheckpointAccessRole], List[SourceInventoryItem]]:
    sources: List[IRCheckpointIdentitySource] = []
    roles: List[IRCheckpointAccessRole] = []
    inventory: List[SourceInventoryItem] = []
    for response, obj in _items(responses, {"show-gateways-and-servers", "show-identity-awareness", "show-identity-sources"}):
        settings = obj.get("identity-awareness") or obj.get("identity_awareness") or obj.get("identity-awareness-settings")
        if not isinstance(settings, dict):
            continue
        for key, value in settings.items():
            if not isinstance(value, (dict, list)):
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                attrs = dict(entry) if isinstance(entry, dict) else {"value": entry}
                sources.append(IRCheckpointIdentitySource(
                    name=str(attrs.get("name") or key), source_context=response.domain,
                    source_type=str(attrs.get("type") or key), enabled=attrs.get("enabled"),
                    settings=attrs, source_attributes={"gateway": obj.get("name") or obj.get("uid")},
                ))
    for response, obj in _items(responses, {"show-access-roles", "show-access-role"}):
        conditions = dict(obj)
        role = IRCheckpointAccessRole(
            name=str(obj.get("name") or obj.get("uid") or "access-role"), source_uuid=obj.get("uid"),
            source_context=response.domain, users=_values(obj, "users", "user"),
            user_groups=_values(obj, "user-groups", "user_groups", "groups"),
            machines=_values(obj, "machines", "machine"), networks=_values(obj, "networks", "network"),
            remote_access_roles=_values(obj, "remote-access-roles", "remote_access_roles", "remote-access"),
            conditions=conditions, source_attributes=dict(obj),
        )
        roles.append(role)
        inventory.append(SourceInventoryItem(
            domain=response.domain or "global", source_path="checkpoint/show-access-roles", name=role.name,
            source_id=role.source_uuid, source_type="access-role", source_attributes=dict(obj),
            status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
            notes=["identity-condition-withheld-from-access-policy"],
        ))
    return sources, roles, inventory
