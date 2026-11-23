from __future__ import annotations

from functools import partial
from ..identity import source_identity

from dataclasses import dataclass
from collections.abc import Iterable
from ipaddress import ip_address, ip_network

from ..model.source import PANOSConfig
from ..source_model import PANScope, pan_scope_identity
from .models import PANIndexedObject, PANReferenceResolution, PANShadowedObject
from .scopes import PANDeviceGroupHierarchy, build_scope_hierarchy, visible_scopes


_PREDEFINED_SERVICES = {"service-http", "service-https"}
_PREDEFINED_PROFILES = {"default", "strict", "best-practice", "basic-file-blocking", "Alert-Only", "Block-All"}
_PREDEFINED_IP_EDLS = {"panw-highrisk-ip-list", "panw-known-ip-list", "panw-bulletproof-ip-list", "panw-torexit-ip-list"}
_PREDEFINED_REGIONS = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO
JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS
MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU
RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA
UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())


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
    source_objects: tuple[PANIndexedObject, ...] = ()

    def candidates(self, family: str, name: str, scope: PANScope | None) -> tuple[PANIndexedObject, ...]:
        return self._visible(self.objects, family, name, scope)

    def source_candidates(self, family: str, name: str, scope: PANScope | None) -> tuple[PANIndexedObject, ...]:
        return self._visible(self.source_objects, family, name, scope)

    def _visible(self, objects: tuple[PANIndexedObject, ...], family: str, name: str, scope: PANScope | None) -> tuple[PANIndexedObject, ...]:
        allowed = visible_scopes(scope, self.hierarchy)
        def visible(item):
            if item.scope is None:
                return False
            if item.scope.kind == "shared":
                return "shared:shared" in allowed
            return pan_scope_identity(item.scope) in allowed
        return tuple(item for item in objects if item.family == family and item.name == name and visible(item))


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
        "local-user": config.local_users, "local-user-group": config.local_user_groups,
        "interface": (*config.interfaces, *config.interface_units),
        "virtual-router": config.virtual_routers, "logical-router": config.logical_routers,
        "globalprotect-gateway": config.globalprotect_gateways,
        "tag": config.tags, "zone": config.zones,
        "application-group": config.application_groups,
        "external-list": config.external_lists,
        "custom-url-category": config.custom_url_categories,
        "dynamic-user-group": config.dynamic_user_groups,
        "antivirus-profile": config.antivirus_profiles,
        "anti-spyware-profile": config.anti_spyware_profiles,
        "url-filtering-profile": config.url_filtering_profiles,
        "file-blocking-profile": config.file_blocking_profiles,
        "wildfire-analysis-profile": config.wildfire_profiles,
        "data-filtering-profile": config.data_filtering_profiles,
        "dos-protection-profile": config.dos_protection_profiles,
        "decryption-profile": config.decryption_profiles,
        "log-setting": config.log_forwarding_profiles,
        "authentication-profile": config.authentication_profiles,
        "authentication-sequence": config.authentication_sequences,
        "qos-profile": config.qos_profiles,
        "zone-protection-profile": config.zone_protection_profiles,
        "bfd-profile": config.bfd_profiles,
        "certificate": config.certificates,
        "ssl-tls-service-profile": config.ssl_tls_service_profiles,
    }
    for family, values in fields.items():
        for item in values:
            name = getattr(item, "name", None)
            if name:
                yield PANIndexedObject(family, name, getattr(item, "scope", None), getattr(item, "source_path", ""))


def build_reference_index(config: PANOSConfig) -> ReferenceIndex:
    source_families = {"profile-group": "security-profile-group", "vulnerability": "vulnerability-profile",
                       "ike-crypto-profiles": "ike-crypto-profile", "ipsec-crypto-profiles": "ipsec-crypto-profile"}
    source_objects = tuple(PANIndexedObject(source_families.get(record.kind, record.kind), record.name, record.scope, record.source_path)
                           for record in config.source_inventory if record.name)
    return ReferenceIndex(tuple(_objects(config)), build_scope_hierarchy(config.scopes), source_objects)


def _resolve(index: ReferenceIndex, owner, field: str, name: str, families: tuple[str, ...], *, owner_family: str, source_only: bool = False) -> PANReferenceResolution:
    owner_path = getattr(owner, "source_path", None)
    resolution = partial(PANReferenceResolution, owner_identity=source_identity(owner))
    if name in {"any", "application-default"}:
        return resolution("SOURCE_ONLY", owner.name, field, name, families[0], owner.scope, resolution_reason="PAN-OS special value", owner_family=owner_family, owner_source_path=owner_path)
    if source_only:
        return resolution("SOURCE_ONLY", owner.name, field, name, families[0], owner.scope, resolution_reason="typed source coverage is not authoritative", owner_family=owner_family, owner_source_path=owner_path)

    # Explicit visible source state takes precedence over predefined PAN-OS
    # tokens.  This keeps custom objects source-faithful and avoids treating a
    # same-named explicit object as an implicit vendor object.
    candidates = tuple(candidate for family in families for candidate in index.candidates(family, name, owner.scope))
    if len(candidates) == 1:
        target = candidates[0]
        return resolution("RESOLVED", owner.name, field, name, target.family, owner.scope, target.scope, target.source_path, "one visible candidate", owner_family, owner_path)
    if len(candidates) > 1:
        return resolution("AMBIGUOUS", owner.name, field, name, families[0], owner.scope, resolution_reason="multiple visible candidates; precedence is not explicitly extracted", owner_family=owner_family, owner_source_path=owner_path)

    source_candidates = tuple(candidate for family in families for candidate in index.source_candidates(family, name, owner.scope))
    if len(source_candidates) == 1:
        target = source_candidates[0]
        reason = (
            "source-only PAN-OS region object"
            if target.family == "region"
            else "EXTRACTION_INCOMPLETE: visible source object lacks typed extraction"
        )
        return resolution(
            "SOURCE_ONLY", owner.name, field, name, target.family, owner.scope,
            target.scope, target.source_path, reason, owner_family, owner_path,
        )
    if len(source_candidates) > 1:
        return resolution("AMBIGUOUS", owner.name, field, name, families[0], owner.scope, resolution_reason="multiple visible source-only candidates", owner_family=owner_family, owner_source_path=owner_path)

    if families[0] == "address" and _is_address_literal(name):
        return resolution("SOURCE_ONLY", owner.name, field, name, "address", owner.scope, resolution_reason="PAN-OS address literal", owner_family=owner_family, owner_source_path=owner_path)
    if families[0] == "address" and name in _PREDEFINED_IP_EDLS:
        return resolution("SOURCE_ONLY", owner.name, field, name, "address", owner.scope, resolution_reason="PAN-OS predefined IP external dynamic list; version, content and license availability are unverified", owner_family=owner_family, owner_source_path=owner_path)
    if families[0] == "vulnerability-profile" and name in {"default", "strict"}:
        return resolution("SOURCE_ONLY", owner.name, field, name, "vulnerability-profile", owner.scope, resolution_reason="PAN-OS predefined vulnerability profile; effective content is not extracted", owner_family=owner_family, owner_source_path=owner_path)
    if families[0].endswith("-profile") and name in _PREDEFINED_PROFILES:
        return resolution("SOURCE_ONLY", owner.name, field, name, families[0], owner.scope, resolution_reason="PAN-OS predefined profile; effective content is not extracted", owner_family=owner_family, owner_source_path=owner_path)
    if families[0] == "address" and name in _PREDEFINED_REGIONS:
        return resolution("SOURCE_ONLY", owner.name, field, name, "region", owner.scope, resolution_reason="PAN-OS predefined country region", owner_family=owner_family, owner_source_path=owner_path)
    if families[0] == "service" and name in _PREDEFINED_SERVICES:
        return resolution("SOURCE_ONLY", owner.name, field, name, "service", owner.scope, resolution_reason="PAN-OS predefined service", owner_family=owner_family, owner_source_path=owner_path)
    return resolution("UNRESOLVED", owner.name, field, name, families[0], owner.scope, resolution_reason="no visible typed or source-only PAN-OS object", owner_family=owner_family, owner_source_path=owner_path)


def _scope_device(scope: PANScope | None) -> str | None:
    if scope is None:
        return None
    provenance = scope.template_provenance or {}
    return (
        scope.device_serial or scope.device_name
        or provenance.get("managed_device_serial") or provenance.get("managed_device")
    )


def _resolve_interface(index: ReferenceIndex, owner, field: str, name: str, *, owner_family: str) -> PANReferenceResolution:
    owner_path = getattr(owner, "source_path", None)
    resolution = partial(PANReferenceResolution, owner_identity=source_identity(owner))
    if name == "any":
        return resolution("SOURCE_ONLY", owner.name, field, name, "interface", owner.scope, resolution_reason="PAN-OS special value", owner_family=owner_family, owner_source_path=owner_path)
    direct = index.candidates("interface", name, owner.scope)
    if len(direct) == 1:
        target = direct[0]
        return resolution("RESOLVED", owner.name, field, name, "interface", owner.scope, target.scope, target.source_path, "one visible candidate", owner_family, owner_path)
    if len(direct) > 1:
        return resolution("AMBIGUOUS", owner.name, field, name, "interface", owner.scope, resolution_reason="multiple visible interface candidates", owner_family=owner_family, owner_source_path=owner_path)
    device = _scope_device(owner.scope)
    if device is None:
        return resolution("SOURCE_ONLY", owner.name, field, name, "interface", owner.scope, resolution_reason="interface ownership requires explicit device context", owner_family=owner_family, owner_source_path=owner_path)
    candidates = tuple(
        item for item in index.objects
        if item.family == "interface" and item.name == name and _scope_device(item.scope) == device
    )
    if len(candidates) == 1:
        target = candidates[0]
        return resolution("RESOLVED", owner.name, field, name, "interface", owner.scope, target.scope, target.source_path, "one interface candidate on the same explicit device", owner_family, owner_path)
    if len(candidates) > 1:
        return resolution("AMBIGUOUS", owner.name, field, name, "interface", owner.scope, resolution_reason="multiple same-device interface candidates; effective template precedence is not extracted", owner_family=owner_family, owner_source_path=owner_path)
    return resolution("UNRESOLVED", owner.name, field, name, "interface", owner.scope, resolution_reason="no interface with this name exists on the explicit source device", owner_family=owner_family, owner_source_path=owner_path)


_PROFILE_FAMILIES = {
    "virus": ("antivirus-profile", True),
    "spyware": ("anti-spyware-profile", True),
    "vulnerability": ("vulnerability-profile", False),
    "url-filtering": ("url-filtering-profile", True),
    "file-blocking": ("file-blocking-profile", True),
    "wildfire-analysis": ("wildfire-analysis-profile", True),
    "data-filtering": ("data-filtering-profile", True),
    "gtp": ("gtp-profile", True),
    "sctp": ("sctp-profile", True),
    "ai-security": ("ai-security-profile", True),
}


def _append_profile_setting_references(
    result: list[PANReferenceResolution],
    index: ReferenceIndex,
    owner,
    owner_family: str,
    present_families: set[str],
) -> None:
    profile_setting = getattr(owner, "profile_setting", None)
    if profile_setting is None:
        return
    for name in profile_setting.groups or ():
        result.append(_resolve(index, owner, "profile_setting.groups", name, ("security-profile-group",), owner_family=owner_family))
    for profile_type, names in (profile_setting.profiles or {}).items():
        family, default_source_only = _PROFILE_FAMILIES.get(profile_type, (f"{profile_type}-profile", True))
        source_only = default_source_only and family not in present_families
        for name in names or ():
            result.append(_resolve(index, owner, f"profile_setting.profiles.{profile_type}", name, (family,), owner_family=owner_family, source_only=source_only))


def _append_user_reference(result: list[PANReferenceResolution], index: ReferenceIndex, owner, field: str, name: str, owner_family: str) -> None:
    families = ("local-user", "local-user-group", "dynamic-user-group")
    if any(index.candidates(family, name, owner.scope) for family in families):
        result.append(_resolve(index, owner, field, name, families, owner_family=owner_family))
    else:
        result.append(_resolve(index, owner, field, name, families, owner_family=owner_family, source_only=True))


def _static_routes(config: PANOSConfig):
    for router in config.virtual_routers:
        yield from router.static_routes or ()
    for router in config.logical_routers:
        for vrf in router.vrfs or ():
            yield from vrf.static_routes or ()


def _append_network_address_reference(result, index, owner, field, name, owner_family):
    if not name or _is_address_literal(name):
        return
    direct = index.candidates("address", name, owner.scope)
    device = _scope_device(owner.scope)
    candidates = tuple(item for item in index.objects if item.family == "address" and item.name == name
                       and (item in direct or device is not None and _scope_device(item.scope) == device))
    if not candidates:
        return
    # Candidate existence does not prove effective network ownership or compatible address use.
    result.append(PANReferenceResolution(
        "AMBIGUOUS" if len(candidates) > 1 else "SOURCE_ONLY", owner.name, field, name, "address", owner.scope,
        resolution_reason="NETWORK_ADDRESS_OBJECT_REVIEW: address type, value and effective VSYS/template visibility require review",
        owner_family=owner_family, owner_source_path=owner.source_path, owner_identity=source_identity(owner),
    ))


def resolve_references(config: PANOSConfig, index: ReferenceIndex | None = None) -> tuple[tuple[PANReferenceResolution, ...], tuple[PANShadowedObject, ...]]:
    index = index or build_reference_index(config)
    present_families = {obj.family for obj in index.objects}
    result: list[PANReferenceResolution] = []
    source_families = (
        ("address", "address-group", "region", "external-list")
        if "external-list" in present_families
        else ("address", "address-group", "region")
    )
    for group in config.address_groups:
        for name in group.static_members or ():
            result.append(_resolve(index, group, "static_members", name, ("address", "address-group"), owner_family="address-group"))
        for name in group.tags or ():
            result.append(_resolve(index, group, "tags", name, ("tag",), owner_family="address-group"))
    for group in config.application_groups:
        for name in group.members or ():
            matched = bool(index.candidates("application-group", name, group.scope))
            result.append(_resolve(index, group, "members", name, ("application-group",), owner_family="application-group", source_only=not matched))
    for address in config.addresses:
        for name in address.tags or ():
            result.append(_resolve(index, address, "tags", name, ("tag",), owner_family="address"))
    for service in config.services:
        for name in service.tags or ():
            result.append(_resolve(index, service, "tags", name, ("tag",), owner_family="service"))
    for group in config.service_groups:
        for name in group.members or ():
            result.append(_resolve(index, group, "members", name, ("service", "service-group"), owner_family="service-group"))
        for name in group.tags or ():
            result.append(_resolve(index, group, "tags", name, ("tag",), owner_family="service-group"))
    for rule in config.security_rules:
        for field, names, families, source_only in (
            ("from_zones", rule.from_zones, ("zone",), False), ("to_zones", rule.to_zones, ("zone",), False),
            ("source", rule.source, source_families, False), ("destination", rule.destination, source_families, False),
            ("service", rule.service, ("service", "service-group"), False), ("schedule", (rule.schedule,) if rule.schedule else (), ("schedule",), False),
            ("tags", rule.tags, ("tag",), False),
        ):
            for name in names or ():
                result.append(_resolve(index, rule, field, name, families, owner_family="policy", source_only=source_only))
        for name in rule.application or ():
            matched = bool(index.candidates("application-group", name, rule.scope))
            result.append(_resolve(index, rule, "application", name, ("application-group",) if matched else ("application",), owner_family="policy", source_only=not matched))
        for name in rule.category or ():
            if name != "any" and index.candidates("custom-url-category", name, rule.scope):
                result.append(_resolve(index, rule, "category", name, ("custom-url-category",), owner_family="policy"))
        for name in rule.source_user or ():
            _append_user_reference(result, index, rule, "source_user", name, "policy")
        if rule.log_setting:
            result.append(_resolve(index, rule, "log_setting", rule.log_setting, ("log-setting",), owner_family="policy", source_only="log-setting" not in present_families))
        _append_profile_setting_references(result, index, rule, "policy", present_families)
    for rule in config.default_security_rules:
        for name in rule.tags or ():
            result.append(_resolve(index, rule, "tags", name, ("tag",), owner_family="default-security-rule"))
        if rule.log_setting:
            result.append(_resolve(index, rule, "log_setting", rule.log_setting, ("log-setting",), owner_family="default-security-rule", source_only="log-setting" not in present_families))
        _append_profile_setting_references(result, index, rule, "default-security-rule", present_families)
    for rule in config.nat_rules:
        for field, names, families in (("from_zones", rule.from_zones, ("zone",)), ("to_zones", rule.to_zones, ("zone",)), ("source", rule.source, ("address", "address-group")), ("destination", rule.destination, ("address", "address-group")), ("service", (rule.service,) if rule.service else (), ("service", "service-group")), ("tags", rule.tags, ("tag",))):
            for name in names or ():
                result.append(_resolve(index, rule, field, name, families, owner_family="nat"))
        if rule.to_interface:
            result.append(_resolve_interface(index, rule, "to_interface", rule.to_interface, owner_family="nat"))
        if rule.source_translation and getattr(rule.source_translation, "interface", None):
            result.append(_resolve_interface(index, rule, "source_translation.interface", rule.source_translation.interface, owner_family="nat"))
        for branch, field in ((rule.source_translation, "source_translation"), (rule.destination_translation, "destination_translation"), (rule.dynamic_destination_translation, "dynamic_destination_translation")):
            for attr in ("translated_address", "translated_addresses"):
                names = getattr(branch, attr, None) if branch else None
                for name in (names if isinstance(names, (list, tuple)) else (names,) if names else ()):
                    result.append(_resolve(index, rule, f"{field}.{attr}", name, ("address", "address-group"), owner_family="nat"))
    for owner in (*config.interfaces, *config.interface_units):
        for name in owner.ipv4_addresses or ():
            _append_network_address_reference(result, index, owner, "ipv4_addresses", name, "interface")
        if owner.sdwan_interface_profile:
            result.append(_resolve(index, owner, "sdwan_interface_profile", owner.sdwan_interface_profile, ("sdwan-interface-profile",), owner_family="interface"))
    for zone in config.zones:
        for name in zone.members or ():
            result.append(_resolve_interface(index, zone, "members", name, owner_family="zone"))
        if zone.zone_protection_profile:
            result.append(_resolve(index, zone, "zone_protection_profile", zone.zone_protection_profile, ("zone-protection-profile",), owner_family="zone", source_only="zone-protection-profile" not in present_families))
        if zone.log_setting:
            result.append(_resolve(index, zone, "log_setting", zone.log_setting, ("log-setting",), owner_family="zone", source_only="log-setting" not in present_families))
    for group in config.security_profile_groups:
        for name in group.vulnerability or ():
            result.append(_resolve(index, group, "vulnerability", name, ("vulnerability-profile",), owner_family="security-profile-group"))
        for field in ("antivirus", "anti_spyware", "url_filtering", "file_blocking", "wildfire_analysis", "data_filtering", "gtp", "sctp", "ai_security"):
            family = field.replace("_", "-") + "-profile"
            source_only = family not in present_families
            for name in getattr(group, field) or ():
                result.append(_resolve(index, group, field, name, (family,), owner_family="security-profile-group", source_only=source_only))
    for administrator in config.administrators:
        if administrator.custom_admin_role:
            result.append(_resolve(index, administrator, "custom_admin_role", administrator.custom_admin_role, ("admin-role",), owner_family="administrator"))
        if administrator.authentication_profile:
            result.append(_resolve(index, administrator, "authentication_profile", administrator.authentication_profile, ("authentication-profile",), owner_family="administrator", source_only="authentication-profile" not in present_families))
    for tunnel in config.ipsec_tunnels:
        if tunnel.tunnel_interface:
            result.append(_resolve_interface(index, tunnel, "tunnel_interface", tunnel.tunnel_interface, owner_family="ipsec-tunnel"))
        for name in tunnel.ike_gateways or ():
            result.append(_resolve(index, tunnel, "ike_gateways", name, ("ike-gateway",), owner_family="ipsec-tunnel"))
        if tunnel.ipsec_crypto_profile:
            result.append(_resolve(index, tunnel, "ipsec_crypto_profile", tunnel.ipsec_crypto_profile, ("ipsec-crypto-profile",), owner_family="ipsec-tunnel"))
    for gateway in config.ike_gateways:
        if gateway.local_interface:
            result.append(_resolve_interface(index, gateway, "local_interface", gateway.local_interface, owner_family="ike-gateway"))
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
            ("application", rule.application, ("application",), True),
        ):
            for name in names or ():
                result.append(_resolve(index, rule, field, name, families, owner_family="sdwan-rule", source_only=source_only))
        for name in rule.source_user or ():
            _append_user_reference(result, index, rule, "source_user", name, "sdwan-rule")
        for field, family in (("path_quality_profile", "sdwan-path-quality-profile"), ("saas_quality_profile", "sdwan-saas-quality-profile"), ("error_correction_profile", "sdwan-error-correction-profile"), ("traffic_distribution_profile", "sdwan-traffic-distribution-profile")):
            name = getattr(rule, field)
            if name:
                result.append(_resolve(index, rule, field, name, (family,), owner_family="sdwan-rule"))
    for group in config.local_user_groups:
        for name in group.members or ():
            result.append(_resolve(index, group, "members", name, ("local-user",), owner_family="local-user-group"))
    for route in _static_routes(config):
        for field in ("destination", "nexthop_ip_address"):
            _append_network_address_reference(result, index, route, field, getattr(route, field), "route")
        if route.interface:
            result.append(_resolve_interface(index, route, "interface", route.interface, owner_family="static-route"))
        if route.bfd_profile:
            result.append(_resolve(index, route, "bfd_profile", route.bfd_profile, ("bfd-profile",), owner_family="static-route", source_only="bfd-profile" not in present_families))
        if route.nexthop and route.nexthop_type == "next-vr":
            result.append(_resolve(index, route, "nexthop", route.nexthop, ("virtual-router",), owner_family="static-route"))
        elif route.nexthop and route.nexthop_type == "next-lr":
            result.append(_resolve(index, route, "nexthop", route.nexthop, ("logical-router",), owner_family="static-route"))
    for server in config.dhcp_servers:
        if server.interface:
            result.append(_resolve_interface(index, server, "interface", server.interface, owner_family="dhcp-server"))
        if server.inheritance_source:
            result.append(_resolve_interface(index, server, "inheritance_source", server.inheritance_source, owner_family="dhcp-server"))
    for owner_family, objects in (("globalprotect-portal", config.globalprotect_portals), ("globalprotect-gateway", config.globalprotect_gateways)):
        for owner in objects:
            for field in ("authentication_profile", "certificate_profile", "ssl_tls_service_profile"):
                name = getattr(owner, field, None)
                if name:
                    family = field.replace("_", "-")
                    result.append(_resolve(index, owner, field, name, (family,), owner_family=owner_family, source_only=family not in present_families))
            if owner_family == "globalprotect-gateway":
                if owner.local_interface:
                    result.append(_resolve_interface(index, owner, "local_interface", owner.local_interface, owner_family=owner_family))
                for client_auth in owner.client_authentication or ():
                    if client_auth.authentication_profile:
                        result.append(_resolve(index, owner, "client_authentication.authentication_profile", client_auth.authentication_profile, ("authentication-profile",), owner_family=owner_family, source_only="authentication-profile" not in present_families))
    for ext_owner_family, rules in (
        ("qos-rule", config.qos_rules),
        ("pbf-rule", config.pbf_rules),
        ("decryption-rule", config.decryption_rules),
        ("tunnel-inspect-rule", config.tunnel_inspect_rules),
        ("app-override-rule", config.app_override_rules),
        ("authentication-rule", config.authentication_rules),
        ("dos-rule", config.dos_rules),
    ):
        for rule in rules:
            for field, names, families in (
                ("from_zones", getattr(rule, "from_zones", None), ("zone",)),
                ("to_zones", getattr(rule, "to_zones", None), ("zone",)),
                ("source", getattr(rule, "source", None), source_families),
                ("destination", getattr(rule, "destination", None), source_families),
                ("service", getattr(rule, "service", None), ("service", "service-group")),
                ("schedule", (rule.schedule,) if getattr(rule, "schedule", None) else (), ("schedule",)),
                ("tags", getattr(rule, "tags", None), ("tag",)),
            ):
                for name in names or ():
                    result.append(_resolve(index, rule, field, name, families, owner_family=ext_owner_family))
            for iface_name in getattr(rule, "from_interfaces", None) or ():
                result.append(_resolve_interface(index, rule, "from_interfaces", iface_name, owner_family=ext_owner_family))
            if getattr(rule, "egress_interface", None):
                result.append(_resolve_interface(index, rule, "egress_interface", rule.egress_interface, owner_family=ext_owner_family))
            for name in getattr(rule, "source_user", None) or ():
                _append_user_reference(result, index, rule, "source_user", name, ext_owner_family)
            if getattr(rule, "log_setting", None):
                result.append(_resolve(index, rule, "log_setting", rule.log_setting, ("log-setting",), owner_family=ext_owner_family, source_only="log-setting" not in present_families))
            if getattr(rule, "profile", None):
                prof_family = "decryption-profile" if ext_owner_family == "decryption-rule" else f"{ext_owner_family}-profile"
                result.append(_resolve(index, rule, "profile", rule.profile, (prof_family,), owner_family=ext_owner_family, source_only=prof_family not in present_families))
    for profile in config.ssl_tls_service_profiles:
        if profile.certificate:
            result.append(_resolve(index, profile, "certificate", profile.certificate, ("certificate",), owner_family="ssl-tls-service-profile", source_only="certificate" not in present_families))
    for profile in config.saml_idp_server_profiles:
        if profile.certificate:
            result.append(_resolve(index, profile, "certificate", profile.certificate, ("certificate",), owner_family="saml-idp-server-profile", source_only="certificate" not in present_families))
    for vlan in config.vlans:
        if vlan.virtual_interface:
            result.append(_resolve_interface(index, vlan, "virtual_interface", vlan.virtual_interface, owner_family="vlan"))
        for iface in vlan.interfaces or ():
            result.append(_resolve_interface(index, vlan, "interfaces", iface, owner_family="vlan"))
    for vwire in config.virtual_wires:
        for field in ("interface1", "interface2"):
            iface = getattr(vwire, field, None)
            if iface:
                result.append(_resolve_interface(index, vwire, field, iface, owner_family="virtual-wire"))
    for gre in config.gre_tunnels:
        if gre.tunnel_interface:
            result.append(_resolve_interface(index, gre, "tunnel_interface", gre.tunnel_interface, owner_family="gre-tunnel"))
    for proxy in config.dns_proxies:
        for iface in proxy.interfaces or ():
            result.append(_resolve_interface(index, proxy, "interfaces", iface, owner_family="dns-proxy"))
    shadowing: list[PANShadowedObject] = []
    for obj in index.objects:
        candidates = index.candidates(obj.family, obj.name, obj.scope)
        if len(candidates) > 1:
            shadowing.append(PANShadowedObject(obj.family, obj.name, pan_scope_identity(obj.scope), candidates, "ambiguous unless effective precedence is explicitly extracted"))
    unique_shadowing = {(item.family, item.name, item.visible_from): item for item in shadowing}
    return tuple(result), tuple(unique_shadowing.values())
