"""Secret-safe Check Point identity and authentication extraction."""

from __future__ import annotations

import shlex
from typing import Any, Dict, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.ir.core import IRLocalUser, IRUserGroup, IRUserLDAP, IRUserRADIUS, IRUserSAML, IRUserTACACS
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def _attrs(tokens: List[str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for index in range(0, len(tokens) - 1, 2):
        result[tokens[index].lstrip("-").replace("-", "_")] = tokens[index + 1]
    return result


def _object_records(responses: List[CheckPointResponse]):
    for response in responses:
        command = canonicalize_command(response.command)
        objects = response.data.get("objects", [])
        if isinstance(objects, dict): objects = list(objects.values())
        if not isinstance(objects, list): continue
        for obj in objects:
            if isinstance(obj, dict): yield response, command, obj


def _pick(obj: Dict[str, Any], *keys: str) -> Any:
    return next((obj[key] for key in keys if obj.get(key) not in (None, "")), None)


def _port(value: Any) -> Any:
    try: return int(value) if value is not None else None
    except (TypeError, ValueError): return None


def _int(value: Any) -> Any:
    try: return int(value) if value is not None else None
    except (TypeError, ValueError): return None


def extract_authentication(
    responses: List[CheckPointResponse], gaia_texts: List[Tuple[str, str]],
) -> Tuple[List[IRLocalUser], List[IRUserGroup], List[IRUserLDAP], List[IRUserRADIUS], List[IRUserTACACS], List[IRUserSAML], List[SourceInventoryItem], List[UnsupportedItem]]:
    users: List[IRLocalUser] = []
    groups: List[IRUserGroup] = []
    ldap: List[IRUserLDAP] = []
    radius: List[IRUserRADIUS] = []
    tacacs: List[IRUserTACACS] = []
    saml: List[IRUserSAML] = []
    inventory: List[SourceInventoryItem] = []
    for source_record in gaia_texts:
        source, text = source_record[:2]
        source_context = source_record[2] if len(source_record) > 2 else source
        for line_no, line in enumerate(text.splitlines(), 1):
            try: tokens = shlex.split(line.strip())
            except ValueError: continue
            if len(tokens) < 3 or tokens[0].lower() not in {"set", "add"} or tokens[1].lower() not in {"user", "user-group"}: continue
            kind = tokens[1].lower(); name = tokens[2]
            attrs = sanitize_source_attributes(_attrs(tokens[3:]))
            item_type = "gaia-local-user" if kind == "user" else "gaia-user-group"
            if kind == "user":
                users.append(IRLocalUser(name=name, source_type="gaia", status=attrs.get("status"),
                    id=_int(attrs.get("uid")), uid=_int(attrs.get("uid")), gid=_int(attrs.get("gid")),
                    homedir=attrs.get("homedir"), shell=attrs.get("shell"), realname=attrs.get("realname"),
                    lock_out=attrs.get("lock_out"), force_password_change=attrs.get("force_password_change"),
                    has_password=any(k in attrs for k in ("password", "password_hash")),
                    source_attributes={k: attrs[k] for k in ("uid", "gid", "homedir", "shell", "realname", "lock_out", "force_password_change") if k in attrs}))
            else: groups.append(IRUserGroup(name=name, group_type="gaia", members=[str(attrs["member"])] if attrs.get("member") else [], source_attributes=attrs))
            inventory.append(SourceInventoryItem(domain="gaia", source_path=f"gaia/{source}", name=name, source_type=item_type, source_id=str(line_no), source_context=source_context, source_attributes={"raw_command": sanitize_raw_text(line), **attrs}, status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True, notes=["authentication-migration-requires-review"]))
    type_map = {"ldap": (ldap, IRUserLDAP), "radius": (radius, IRUserRADIUS), "tacacs": (tacacs, IRUserTACACS), "saml": (saml, IRUserSAML)}
    for response, command, obj in _object_records(responses):
        text = f"{command} {obj.get('type', '')}".lower()
        key = next((key for key in type_map if key in text), None)
        if not key: continue
        collection, model = type_map[key]
        attrs = sanitize_source_attributes(obj); name = str(obj.get("name") or obj.get("uid") or "<unnamed>")
        kwargs = {
            "name": name,
            "server": _pick(obj, "server", "server-address", "host"),
            "port": _port(_pick(obj, "port", "server-port")),
            "has_password": any(key in obj for key in ("password", "bind-password")),
            "has_secret": any(key in obj for key in ("secret", "shared-secret", "authentication-key")),
            "source_attributes": attrs,
        }
        if key == "ldap":
            kwargs.update({"dn": _pick(obj, "base-dn", "base_dn", "domain"), "secure": _pick(obj, "ssl", "tls", "secure"), "group_filter": _pick(obj, "group-filter", "group_filter"), "ca_cert": _pick(obj, "ca-certificate", "certificate")})
        elif key == "saml":
            kwargs.update({"entity_id": _pick(obj, "entity-id", "entity_id"), "single_sign_on_url": _pick(obj, "single-sign-on-url", "sso-url"), "idp_cert": _pick(obj, "idp-certificate", "certificate")})
        collection.append(model(**kwargs))
        inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/{command}", name=name, source_id=obj.get("uid"), source_type=f"checkpoint-{key}", source_attributes=attrs, status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True, notes=["authentication-secret-not-exported"]))
    return users, groups, ldap, radius, tacacs, saml, inventory, []
