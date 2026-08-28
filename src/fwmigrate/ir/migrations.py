from __future__ import annotations

import logging
from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


logger = logging.getLogger(__name__)


def migrate_ir_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" not in payload:
        return _migrate_unversioned(payload)
    if payload.get("schema_version") == "1.0":
        return _migrate_1_2(_migrate_1_1(_migrate_1_0(payload)))
    if payload.get("schema_version") == "1.1":
        return _migrate_1_2(_migrate_1_1(payload))
    if payload.get("schema_version") == "1.2":
        return _migrate_1_2(payload)
    if payload.get("schema_version") == "1.3":
        return _migrate_1_3(payload)
    if payload.get("schema_version") == "1.4":
        return _migrate_1_4(payload)
    if payload.get("schema_version") == "1.5":
        return _migrate_1_5(payload)
    if payload.get("schema_version") == "1.6":
        return _migrate_1_6(payload)
    if payload.get("schema_version") == "1.8":
        return _migrate_1_8(payload)
    if payload.get("schema_version") == "1.10":
        return _migrate_1_11(_migrate_1_10(payload))
    if payload.get("schema_version") == "1.11":
        return _migrate_1_11(payload)
    return dict(payload)


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
