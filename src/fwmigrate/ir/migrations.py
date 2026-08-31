from __future__ import annotations

import logging
from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


logger = logging.getLogger(__name__)


def migrate_ir_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" not in payload:
        return _migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(_migrate_1_13(_migrate_1_12(_migrate_unversioned(payload)))))))
    version = payload.get("schema_version")
    if version == IR_SCHEMA_VERSION:
        return dict(payload)
    if version == "1.0":
        migrated = _migrate_1_2(_migrate_1_1(_migrate_1_0(payload)))
    elif version == "1.1":
        migrated = _migrate_1_2(_migrate_1_1(payload))
    elif version == "1.2":
        migrated = _migrate_1_2(payload)
    elif version == "1.3":
        migrated = _migrate_1_3(payload)
    elif version == "1.4":
        migrated = _migrate_1_4(payload)
    elif version == "1.5":
        migrated = _migrate_1_5(payload)
    elif version == "1.6":
        migrated = _migrate_1_6(payload)
    elif version == "1.8":
        migrated = _migrate_1_8(payload)
    elif version == "1.10":
        migrated = _migrate_1_11(_migrate_1_10(payload))
    elif version == "1.11":
        migrated = _migrate_1_11(payload)
    elif version == "1.12":
        migrated = dict(payload)
    elif version == "1.13":
        return _migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(_migrate_1_13(dict(payload))))))
    elif version == "1.14":
        return _migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(dict(payload)))))
    elif version == "1.15":
        return _migrate_1_20(_migrate_1_17(_migrate_1_15(dict(payload))))
    elif version == "1.16":
        return _migrate_1_20(_migrate_1_17(_migrate_1_16(dict(payload))))
    elif version == "1.17":
        return _migrate_1_20(_migrate_1_17(dict(payload)))
    elif version == "1.18":
        return _migrate_1_20(_migrate_1_18(dict(payload)))
    elif version == "1.19":
        return _migrate_1_20(dict(payload))
    else:
        return dict(payload)
    return _migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(_migrate_1_13(_migrate_1_12(migrated))))))


def _migrate_1_17(payload: dict[str, Any]) -> dict[str, Any]:
    """Add schema 1.18 and 1.19 source-fidelity fields."""
    logger.warning("Loaded IR schema 1.17; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    interfaces = []
    for source_interface in payload.get("interfaces", []):
        if not isinstance(source_interface, dict):
            interfaces.append(source_interface)
            continue
        interface = dict(source_interface)
        interface.setdefault("source_vrf", None)
        interface.setdefault("ipv6_address", None)
        interface.setdefault("source_ipv6_address", None)
        interface.setdefault("source_ipv6_management_access", [])
        interface.setdefault("source_ipv6_mode", None)
        interface.setdefault("source_ipv6_send_adv", None)
        interface.setdefault("source_ipv6_manage_flag", None)
        interface.setdefault("source_ipv6_other_flag", None)
        interface.setdefault("source_secondary_ip_status", None)
        interface.setdefault("inactive_secondary_ips", [])
        interface.setdefault("review_reasons", [])
        interfaces.append(interface)
    migrated["interfaces"] = interfaces

    zones = []
    for source_zone in payload.get("zones", []):
        if not isinstance(source_zone, dict):
            zones.append(source_zone)
            continue
        zone = dict(source_zone)
        zone.setdefault("zone_type", "system")
        zone.setdefault("source_path", None)
        zones.append(zone)
    migrated["zones"] = zones

    source_sdwans = payload.get("sdwans")
    if source_sdwans is None:
        legacy_sdwan = payload.get("sdwan")
        source_sdwans = [] if legacy_sdwan is None else [legacy_sdwan]

    sdwans = []
    for source_sdwan in source_sdwans:
        if not isinstance(source_sdwan, dict):
            sdwans.append(source_sdwan)
            continue

        sdwan = dict(source_sdwan)
        source_context = sdwan.get("source_context") or "root"
        sdwan["source_context"] = source_context

        def contextualize(items: Any) -> list[Any]:
            contextualized = []
            for source_item in items or []:
                if not isinstance(source_item, dict):
                    contextualized.append(source_item)
                    continue
                item = dict(source_item)
                item.setdefault("source_context", source_context)
                contextualized.append(item)
            return contextualized

        for collection_name in (
            "zones", "members", "health_checks", "rules",
            "duplication_rules", "neighbors",
        ):
            sdwan[collection_name] = contextualize(sdwan.get(collection_name))

        for member in sdwan["members"]:
            if isinstance(member, dict):
                member.setdefault("source_explicit_fields", [])
        for check in sdwan["health_checks"]:
            if isinstance(check, dict):
                check.setdefault("source_explicit_fields", [])
                check["sla"] = contextualize(check.get("sla"))
        for rule in sdwan["rules"]:
            if isinstance(rule, dict):
                rule.setdefault("source_explicit_fields", [])
                rule["sla"] = contextualize(rule.get("sla"))

        sdwans.append(sdwan)

    migrated["sdwans"] = sdwans
    migrated.pop("sdwan", None)
    _add_route_explicit_field_defaults(migrated)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_18(payload: dict[str, Any]) -> dict[str, Any]:
    """Add static-route explicit-source provenance introduced in schema 1.19."""
    logger.warning("Loaded IR schema 1.18; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    interfaces = []
    for source_interface in payload.get("interfaces", []):
        if not isinstance(source_interface, dict):
            interfaces.append(source_interface)
            continue
        interface = dict(source_interface)
        interface.setdefault("ipv6_address", None)
        interface.setdefault("source_ipv6_address", None)
        interface.setdefault("source_ipv6_management_access", [])
        interface.setdefault("source_ipv6_mode", None)
        interface.setdefault("source_ipv6_send_adv", None)
        interface.setdefault("source_ipv6_manage_flag", None)
        interface.setdefault("source_ipv6_other_flag", None)
        interfaces.append(interface)
    migrated["interfaces"] = interfaces
    zones = []
    for source_zone in payload.get("zones", []):
        if not isinstance(source_zone, dict):
            zones.append(source_zone)
            continue
        zone = dict(source_zone)
        zone.setdefault("zone_type", "system")
        zone.setdefault("source_path", None)
        zones.append(zone)
    migrated["zones"] = zones
    _add_route_explicit_field_defaults(migrated)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_20(payload: dict[str, Any]) -> dict[str, Any]:
    """Add PAN-OS routing-instance identity fields to interfaces."""
    logger.warning("Loaded an older IR schema; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    interfaces = []
    for source_interface in payload.get("interfaces", []):
        if not isinstance(source_interface, dict):
            interfaces.append(source_interface)
            continue
        interface = dict(source_interface)
        interface.setdefault("source_routing_instance", None)
        interface.setdefault("source_routing_instance_type", None)
        interfaces.append(interface)
    migrated["interfaces"] = interfaces
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _add_route_explicit_field_defaults(payload: dict[str, Any]) -> None:
    routes = []
    for source_route in payload.get("routes", []):
        if not isinstance(source_route, dict):
            routes.append(source_route)
            continue
        route = dict(source_route)
        route.setdefault("source_explicit_fields", [])
        routes.append(route)
    payload["routes"] = routes


def _migrate_1_15(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning("Loaded IR schema 1.15; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    for key in (
        "schedule_groups", "execution_contexts", "central_snat_rules",
        "security_policies", "policy_routes", "local_in_policies",
        "proxy_policies", "shaping_policies", "dhcp6_servers",
        "source_only_rules", "custom_internet_services",
        "custom_internet_service_groups",
    ):
        migrated.setdefault(key, [])
    migrated.setdefault("session_ttl_settings", None)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_16(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning("Loaded IR schema 1.16; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["policies"] = []
    for source_policy in payload.get("policies", []):
        if not isinstance(source_policy, dict):
            migrated["policies"].append(source_policy)
            continue
        policy = dict(source_policy)
        policy.setdefault("source_ztna_device_ownership", None)
        policy.setdefault("source_ztna_ems_tags_secondary", [])
        policy.setdefault("source_ztna_geo_tags", [])
        policy.setdefault("source_ztna_policy_redirect", None)
        policy.setdefault("source_ztna_tags_match_logic", None)
        migrated["policies"].append(policy)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_14(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning("Loaded IR schema 1.14; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["zones"] = []
    for zone in payload.get("zones", []):
        if isinstance(zone, dict):
            z = dict(zone)
            z.setdefault("disabled", None)
            z.setdefault("requires_manual_review", False)
            z.setdefault("migration_status", "NORMALIZED")
            z.setdefault("review_reasons", [])
            z.setdefault("source_attributes", {})
            migrated["zones"].append(z)
        else:
            migrated["zones"].append(zone)

    migrated["schema_version"] = "1.15"
    return migrated


def _migrate_1_13(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning("Loaded IR schema 1.13; upgraded to schema 1.14")
    migrated = dict(payload)
    migrated["nat_rules"] = []
    for nat in payload.get("nat_rules", []):
        if isinstance(nat, dict):
            n = dict(nat)
            n.setdefault("translated_services", [])
            n.setdefault("source_rule_id", None)
            n.setdefault("source_attributes", {})
            migrated["nat_rules"].append(n)
        else:
            migrated["nat_rules"].append(nat)

    migrated["policies"] = []
    for pol in payload.get("policies", []):
        if isinstance(pol, dict):
            p = dict(pol)
            p.setdefault("review_reasons", [])
            migrated["policies"].append(p)
        else:
            migrated["policies"].append(pol)

    migrated["schema_version"] = "1.14"
    return migrated


def _migrate_1_12(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning("Loaded IR schema 1.12 or earlier; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated.setdefault("user_authentication_settings", None)
    migrated.setdefault("user_quarantine_settings", None)

    def add_defaults(collection: str, defaults: dict[str, Any]) -> None:
        migrated[collection] = []
        for source_item in payload.get(collection, []):
            if not isinstance(source_item, dict):
                migrated[collection].append(source_item)
                continue
            item = dict(source_item)
            for key, value in defaults.items():
                item.setdefault(key, value.copy() if isinstance(value, (list, dict)) else value)
            migrated[collection].append(item)

    add_defaults("user_groups", {
        "resolved_members": [], "unresolved_members": [],
        "member_dependencies": [], "unresolved_match_servers": [],
    })
    add_defaults("user_saml_servers", {
        "idp_certificate_resolved": None,
        "unresolved_certificate_references": [],
    })
    add_defaults("authentication_schemes", {
        "resolved_user_databases": [], "unresolved_user_databases": [],
        "user_database_dependencies": [],
    })
    add_defaults("authentication_rules", {
        "active_auth_method_resolved": None, "unresolved_auth_methods": [],
    })
    add_defaults("administrators", {
        "fortitoken_resolved": None, "access_profile_resolved": None,
        "unresolved_references": [],
    })
    add_defaults("vpn_tunnels", {"unresolved_auth_user_groups": []})
    add_defaults("security_profile_groups", {
        "migration_status": "PARTIALLY_NORMALIZED",
        "requires_manual_review": True,
        "source_profile_references": {},
    })

    migrated["policies"] = []
    for source_policy in payload.get("policies", []):
        if not isinstance(source_policy, dict):
            migrated["policies"].append(source_policy)
            continue
        policy = dict(source_policy)
        for key, value in {
            "unresolved_user_groups": [], "unresolved_users": [],
            "identity_dependency_review": False,
            "unresolved_security_profiles": [],
            "security_profile_semantics_review": False,
        }.items():
            policy.setdefault(key, value.copy() if isinstance(value, list) else value)
        if policy.get("source_user_groups") or policy.get("source_users"):
            policy["requires_manual_review"] = True
            policy["migration_status"] = "PARTIALLY_NORMALIZED"
            policy["identity_dependency_review"] = True
        if any(policy.get(field) for field in (
            "antivirus", "ips_sensor", "webfilter", "application_list",
            "source_profile_group",
        )):
            policy["requires_manual_review"] = True
            policy["migration_status"] = "PARTIALLY_NORMALIZED"
            policy["security_profile_semantics_review"] = True
        migrated["policies"].append(policy)

    if isinstance(payload.get("ssl_vpn_settings"), dict):
        settings = dict(payload["ssl_vpn_settings"])
        rules = []
        for source_rule in settings.get("authentication_rules", []):
            if isinstance(source_rule, dict):
                rule = dict(source_rule)
                rule.setdefault("unresolved_groups", [])
                rules.append(rule)
            else:
                rules.append(source_rule)
        settings["authentication_rules"] = rules
        migrated["ssl_vpn_settings"] = settings

    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_0(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.0; upgraded to schema 1.1",
    )
    migrated = dict(payload)
    migrated.setdefault("vpn_phase2", [])
    migrated["schema_version"] = "1.1"
    return migrated


def _migrate_1_1(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.1; upgraded to schema 1.2",
    )
    migrated = dict(payload)
    migrated.setdefault("fsso_providers", [])
    migrated.setdefault("fsso_ad_groups", [])
    migrated["schema_version"] = "1.2"
    return migrated


def _migrate_1_2(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.2; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_11(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.11; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated.setdefault("ssl_vpn_host_checks", [])

    migrated["ssl_vpn_portals"] = []
    for source_portal in payload.get("ssl_vpn_portals", []):
        if not isinstance(source_portal, dict):
            migrated["ssl_vpn_portals"].append(source_portal)
            continue
        portal = dict(source_portal)
        portal.setdefault("host_check", None)
        portal.setdefault("host_check_policies", [])
        portal.setdefault("host_check_interval", None)
        portal.setdefault("unresolved_host_check_policies", [])
        portal.setdefault("allow_user_access", [])
        portal.setdefault("auto_connect", None)
        portal.setdefault("exclusive_routing", None)
        portal.setdefault("ip_mode", None)
        portal.setdefault("service_restriction", None)
        portal.setdefault("split_tunneling_routing_addresses", [])
        portal.setdefault("split_tunneling_routing_negate", None)
        migrated["ssl_vpn_portals"].append(portal)

    if isinstance(payload.get("ssl_vpn_settings"), dict):
        settings = dict(payload["ssl_vpn_settings"])
        settings.setdefault("server_certificate_configured", False)
        settings.setdefault("ssl_max_proto_ver", None)
        settings.setdefault("algorithm", None)
        settings.setdefault("client_signature_algorithms", [])
        settings.setdefault("require_client_certificate", None)
        settings.setdefault("dtls_tunnel", None)
        settings.setdefault("login_attempt_limit", None)
        settings.setdefault("login_block_time", None)
        settings.setdefault("auth_timeout", None)
        settings.setdefault("idle_timeout", None)
        settings.setdefault("port", None)
        settings.setdefault("dns_server1", None)
        settings.setdefault("dns_server2", None)
        settings.setdefault("wins_server1", None)
        settings.setdefault("wins_server2", None)
        rules = []
        for source_rule in settings.get("authentication_rules", []):
            if not isinstance(source_rule, dict):
                rules.append(source_rule)
                continue
            rule = dict(source_rule)
            for field in (
                "auth", "cipher", "client_cert", "realm",
                "source_address_negate", "source_address6_negate", "user_peer",
            ):
                rule.setdefault(field, None)
            for field in (
                "source_addresses", "source_addresses6", "source_interfaces", "users",
            ):
                rule.setdefault(field, [])
            rule.setdefault("migration_status", "EXTRACT_ONLY")
            rule.setdefault("requires_manual_review", True)
            rules.append(rule)
        settings["authentication_rules"] = rules
        migrated["ssl_vpn_settings"] = settings

    migrated["vpn_phase2"] = []
    for source_phase2 in payload.get("vpn_phase2", []):
        if not isinstance(source_phase2, dict):
            migrated["vpn_phase2"].append(source_phase2)
            continue
        phase2 = dict(source_phase2)
        phase2["requires_manual_review"] = True
        migrated["vpn_phase2"].append(phase2)

    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_3(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.3; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_4(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.4; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_5(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.5; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated.setdefault("administrators", [])
    migrated.setdefault("admin_profiles", [])
    migrated.setdefault("fortitokens", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_6(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.6; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated["internet_services"] = [
        {
            **internet_service,
            "source_attributes": internet_service.get(
                "source_attributes",
                {},
            ),
        }
        if isinstance(internet_service, dict)
        else internet_service
        for internet_service in migrated.get("internet_services", [])
    ]
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


def _migrate_1_10(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.10; upgraded to schema 1.11",
    )
    migrated = dict(payload)
    migrated["services"] = []
    for source_service in payload.get("services", []):
        if not isinstance(source_service, dict):
            migrated["services"].append(source_service)
            continue
        service = dict(source_service)
        service.setdefault("source_protocol_configured", None)
        service.setdefault("source_color", None)
        service.setdefault("source_fabric_object", None)
        service.setdefault("source_unmodeled_semantic_settings", [])
        migrated["services"].append(service)

    migrated["service_groups"] = []
    for source_group in payload.get("service_groups", []):
        if not isinstance(source_group, dict):
            migrated["service_groups"].append(source_group)
            continue
        group = dict(source_group)
        group.setdefault("unsafe_members", [])
        migrated["service_groups"].append(group)

    migrated["schema_version"] = "1.11"
    return migrated


def _migrate_1_8(payload: dict[str, Any]) -> dict[str, Any]:
    logger.warning(
        "Loaded IR schema 1.8; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    migrated["routes"] = []
    for source_route in payload.get("routes", []):
        if not isinstance(source_route, dict):
            migrated["routes"].append(source_route)
            continue
        route = dict(source_route)
        legacy_zone = route.get("sdwan_zone")
        route.setdefault("address_family", "ipv4")
        route.setdefault("source_destination_reference", None)
        route.setdefault("source_prefix", None)
        route.setdefault("weight", None)
        route.setdefault("sdwan_zones", [legacy_zone] if legacy_zone else [])
        route.setdefault("dynamic_gateway", None)
        route.setdefault("link_monitor_exempt", None)
        route.setdefault("bfd", None)
        route.setdefault("vrf", None)
        route.setdefault("route_tag", None)
        route.setdefault("internet_service", None)
        route.setdefault("internet_service_custom", None)
        route.setdefault("review_reasons", [])
        migrated["routes"].append(route)

    if isinstance(payload.get("sdwan"), dict):
        sdwan = dict(payload["sdwan"])
        sdwan["rules"] = []
        for source_rule in payload["sdwan"].get("rules", []):
            if not isinstance(source_rule, dict):
                sdwan["rules"].append(source_rule)
                continue
            rule = dict(source_rule)
            legacy_health_check = rule.get("health_check")
            rule.setdefault(
                "health_checks",
                [legacy_health_check] if legacy_health_check else [],
            )
            rule.setdefault("sla", [])
            rule.setdefault("priority_zones", [])
            rule.setdefault("status", None)
            rule.setdefault("sla_compare_method", None)
            rule.setdefault("tie_break", None)
            sdwan["rules"].append(rule)
        sdwan.setdefault("duplication_rules", [])
        sdwan.setdefault("neighbors", [])
        migrated["sdwan"] = sdwan

    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
