from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable
from ipaddress import ip_address, ip_network

from ..model.source import PANOSConfig
from ..source_model import PANScope, pan_scope_identity
from .models import PANIndexedObject, PANReferenceResolution, PANShadowedObject
from .scopes import PANDeviceGroupHierarchy, build_scope_hierarchy, visible_scopes


_PREDEFINED_SERVICES = {"service-http", "service-https"}
_PREDEFINED_IP_EDLS = {"panw-highrisk-ip-list", "panw-known-ip-list"}
_PREDEFINED_REGIONS = {"MY"}


def _is_address_literal(name: str) -> bool:
    try:
        if "-" in name:
            start, end = name.split("-", 1)
            first, last = ip_address(start), ip_address(end)
            return first.version == last.version and first <= last
        ip_network(name, strict=False)
        return True
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class ReferenceIndex:
    objects: tuple[PANIndexedObject, ...]
    hierarchy: PANDeviceGroupHierarchy

    def candidates(self, family: str, name: str, scope: PANScope | None) -> tuple[PANIndexedObject, ...]:
        allowed = visible_scopes(scope, self.hierarchy)
        def visible(item):
            if item.scope is None:
                return False
            if item.scope.kind == "shared":
                return "shared:shared" in allowed
            if item.scope.kind == "device-group":
                return f"device-group:{item.scope.name}" in allowed
            return pan_scope_identity(item.scope) in allowed
        return tuple(item for item in self.objects if item.family == family and item.name == name and visible(item))


def _objects(config: PANOSConfig) -> Iterable[PANIndexedObject]:
    fields = {
        "address": config.addresses, "address-group": config.address_groups,
        "service": config.services, "service-group": config.service_groups,
        "schedule": config.schedules, "security-profile-group": config.security_profile_groups,
        "vulnerability-profile": config.vulnerability_profiles,
        "administrator": config.administrators, "admin-role": config.admin_roles,
        "ike-gateway": config.ike_gateways, "ike-crypto-profile": config.ike_crypto_profiles,
        "ipsec-crypto-profile": config.ipsec_crypto_profiles, "ipsec-tunnel": config.ipsec_tunnels,
        "sdwan-interface-profile": config.sdwan_interface_profiles,
        "sdwan-path-quality-profile": config.sdwan_path_quality_profiles,
        "sdwan-traffic-distribution-profile": config.sdwan_traffic_distribution_profiles,
        "sdwan-saas-quality-profile": config.sdwan_saas_quality_profiles,
        "sdwan-error-correction-profile": config.sdwan_error_correction_profiles,
        "sdwan-rule": config.sdwan_rules,
        "local-user": config.local_users,
        "tag": config.tags, "zone": config.zones,
    }
    for family, values in fields.items():
        for item in values:
            name = getattr(item, "name", None)
            if name:
                yield PANIndexedObject(family, name, getattr(item, "scope", None), getattr(item, "source_path", ""))


def build_reference_index(config: PANOSConfig) -> ReferenceIndex:
    return ReferenceIndex(tuple(_objects(config)), build_scope_hierarchy(config.scopes))


def _resolve(index: ReferenceIndex, owner, field: str, name: str, families: tuple[str, ...], *, owner_family: str, source_only: bool = False) -> PANReferenceResolution:
    if name in {"any", "application-default"}:
        return PANReferenceResolution("SOURCE_ONLY", owner.name, field, name, families[0], owner.scope, resolution_reason="PAN-OS special value", owner_family=owner_family)
    if source_only:
        return PANReferenceResolution("SOURCE_ONLY", owner.name, field, name, families[0], owner.scope, resolution_reason="typed source coverage is not authoritative", owner_family=owner_family)
    if families[0] == "address" and _is_address_literal(name):
        return PANReferenceResolution("SOURCE_ONLY", owner.name, field, name, "address", owner.scope, resolution_reason="PAN-OS address literal", owner_family=owner_family)
    if families[0] == "address" and name in _PREDEFINED_IP_EDLS:
        return PANReferenceResolution("SOURCE_ONLY", owner.name, field, name, "address", owner.scope, resolution_reason="PAN-OS predefined IP external dynamic list", owner_family=owner_family)
    if families[0] == "address" and name in _PREDEFINED_REGIONS:
        return PANReferenceResolution("SOURCE_ONLY", owner.name, field, name, "address", owner.scope, resolution_reason="PAN-OS predefined country region", owner_family=owner_family)
    if families[0] == "service" and name in _PREDEFINED_SERVICES:
        return PANReferenceResolution("SOURCE_ONLY", owner.name, field, name, "service", owner.scope, resolution_reason="PAN-OS predefined service", owner_family=owner_family)
    candidates = tuple(candidate for family in families for candidate in index.candidates(family, name, owner.scope))
    if len(candidates) == 1:
        target = candidates[0]
        return PANReferenceResolution("RESOLVED", owner.name, field, name, target.family, owner.scope, target.scope, target.source_path, "one visible candidate", owner_family)
    if not candidates:
        return PANReferenceResolution("UNRESOLVED", owner.name, field, name, families[0], owner.scope, resolution_reason="no visible typed source object", owner_family=owner_family)
    return PANReferenceResolution("AMBIGUOUS", owner.name, field, name, families[0], owner.scope, resolution_reason="multiple visible candidates; precedence is not explicitly extracted", owner_family=owner_family)


def resolve_references(config: PANOSConfig, index: ReferenceIndex | None = None) -> tuple[tuple[PANReferenceResolution, ...], tuple[PANShadowedObject, ...]]:
    index = index or build_reference_index(config)
    result: list[PANReferenceResolution] = []
    for group in config.address_groups:
        for name in group.static_members or ():
            result.append(_resolve(index, group, "static_members", name, ("address", "address-group"), owner_family="address-group"))
    for group in config.service_groups:
        for name in group.members or ():
            result.append(_resolve(index, group, "members", name, ("service", "service-group"), owner_family="service-group"))
    for rule in config.security_rules:
        for field, names, families, source_only in (
            ("from_zones", rule.from_zones, ("zone",), False), ("to_zones", rule.to_zones, ("zone",), False),
            ("source", rule.source, ("address", "address-group"), False), ("destination", rule.destination, ("address", "address-group"), False),
            ("service", rule.service, ("service", "service-group"), False), ("schedule", (rule.schedule,) if rule.schedule else (), ("schedule",), False),
            ("profile_setting.groups", rule.profile_setting.groups if rule.profile_setting else (), ("security-profile-group",), False),
            ("tags", rule.tags, ("tag",), False), ("application", rule.application, ("application",), True),
        ):
            for name in names or ():
                result.append(_resolve(index, rule, field, name, families, owner_family="policy", source_only=source_only))
    for rule in config.nat_rules:
        for field, names, families in (("from_zones", rule.from_zones, ("zone",)), ("to_zones", rule.to_zones, ("zone",)), ("source", rule.source, ("address", "address-group")), ("destination", rule.destination, ("address", "address-group")), ("service", (rule.service,) if rule.service else (), ("service", "service-group"))):
            for name in names or ():
                result.append(_resolve(index, rule, field, name, families, owner_family="nat"))
    for group in config.security_profile_groups:
        for name in group.vulnerability or ():
            result.append(_resolve(index, group, "vulnerability", name, ("vulnerability-profile",), owner_family="security-profile-group"))
        for field in ("antivirus", "anti_spyware", "url_filtering", "file_blocking", "wildfire_analysis", "data_filtering", "gtp", "sctp", "ai_security"):
            for name in getattr(group, field) or ():
                result.append(_resolve(index, group, field, name, (field.replace("_", "-") + "-profile",), owner_family="security-profile-group", source_only=True))
    for administrator in config.administrators:
        if administrator.custom_admin_role:
            result.append(_resolve(index, administrator, "custom_admin_role", administrator.custom_admin_role, ("admin-role",), owner_family="administrator"))
    for tunnel in config.ipsec_tunnels:
        for name in tunnel.ike_gateways or ():
            result.append(_resolve(index, tunnel, "ike_gateways", name, ("ike-gateway",), owner_family="ipsec-tunnel"))
        if tunnel.ipsec_crypto_profile:
            result.append(_resolve(index, tunnel, "ipsec_crypto_profile", tunnel.ipsec_crypto_profile, ("ipsec-crypto-profile",), owner_family="ipsec-tunnel"))
    for gateway in config.ike_gateways:
        for field in ("ikev1_crypto_profile", "ikev2_crypto_profile"):
            name = getattr(gateway, field)
            if name:
                result.append(_resolve(index, gateway, field, name, ("ike-crypto-profile",), owner_family="ike-gateway"))
    for rule in config.sdwan_rules:
        for field, names, families, source_only in (
            ("from_zones", rule.from_zones, ("zone",), False),
            ("to_zones", rule.to_zones, ("zone",), False),
            ("source", rule.source, ("address", "address-group"), False),
            ("destination", rule.destination, ("address", "address-group"), False),
            ("service", rule.service, ("service", "service-group"), False),
            ("tags", rule.tags, ("tag",), False),
            ("source_user", rule.source_user, ("user",), True),
            ("application", rule.application, ("application",), True),
        ):
            for name in names or ():
                result.append(_resolve(index, rule, field, name, families, owner_family="sdwan-rule", source_only=source_only))
        for field, family in (("path_quality_profile", "sdwan-path-quality-profile"), ("saas_quality_profile", "sdwan-saas-quality-profile"), ("error_correction_profile", "sdwan-error-correction-profile"), ("traffic_distribution_profile", "sdwan-traffic-distribution-profile")):
            name = getattr(rule, field)
            if name:
                result.append(_resolve(index, rule, field, name, (family,), owner_family="sdwan-rule"))
    for group in config.local_user_groups:
        for name in group.members or ():
            if index.candidates("local-user", name, group.scope):
                result.append(_resolve(index, group, "members", name, ("local-user",), owner_family="local-user-group"))
            else:
                result.append(_resolve(index, group, "members", name, ("local-user",), owner_family="local-user-group", source_only=True))
    for owner_family, objects in (("globalprotect-portal", config.globalprotect_portals), ("globalprotect-gateway", config.globalprotect_gateways)):
        for owner in objects:
            for field in ("authentication_profile", "certificate_profile", "ssl_tls_service_profile"):
                name = getattr(owner, field, None)
                if name:
                    result.append(_resolve(index, owner, field, name, (field.replace("_", "-"),), owner_family=owner_family, source_only=True))
            if owner_family == "globalprotect-gateway":
                for client_auth in owner.client_authentication or ():
                    if client_auth.authentication_profile:
                        result.append(_resolve(index, owner, "client_authentication.authentication_profile", client_auth.authentication_profile, ("authentication-profile",), owner_family=owner_family, source_only=True))
    shadowing: list[PANShadowedObject] = []
    for obj in index.objects:
        candidates = index.candidates(obj.family, obj.name, obj.scope)
        if len(candidates) > 1:
            shadowing.append(PANShadowedObject(obj.family, obj.name, pan_scope_identity(obj.scope), candidates, "ambiguous unless effective precedence is explicitly extracted"))
    unique_shadowing = {(item.family, item.name, item.visible_from): item for item in shadowing}
    return tuple(result), tuple(unique_shadowing.values())
