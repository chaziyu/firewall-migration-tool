from __future__ import annotations

import logging
from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


logger = logging.getLogger(__name__)


def migrate_ir_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" not in payload:
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(_migrate_1_13(_migrate_1_12(_migrate_unversioned(payload)))))))))))))
    version = payload.get("schema_version")
    if version == IR_SCHEMA_VERSION:
        return dict(payload)
    if version == "1.46":
        migrated = dict(payload)
        for key in ("pan_log_server_profiles", "pan_log_forwarding_profiles", "pan_management_log_settings", "pan_dns_proxies", "pan_monitor_profiles", "pan_qos_profiles", "pan_vsys_settings", "pan_custom_reports"):
            migrated.setdefault(key, [])
        for key in ("pan_high_availability", "pan_device_operational_settings", "pan_botnet_report_settings"):
            migrated.setdefault(key, None)
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
    if version == "1.44":
        return _migrate_1_45(_migrate_1_44(dict(payload)))
    if version == "1.45":
        return _migrate_1_45(dict(payload))
    if version == "1.40":
        migrated = dict(payload)
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
    if version == "1.41":
        migrated = dict(payload)
        migrated.setdefault("authentication_sequences", [])
        migrated.setdefault("ssl_tls_service_profiles", [])
        for key in ("user_ldap_servers", "user_radius_servers", "user_tacacs_servers"):
            for item in migrated.get(key, []):
                if isinstance(item, dict):
                    item.setdefault("server_entries", [])
        settings = migrated.get("user_authentication_settings")
        if isinstance(settings, dict):
            settings.setdefault("management_authentication_profile", None)
            settings.setdefault("management_authentication_profile_resolved", None)
            settings.setdefault("unresolved_management_authentication_profile", None)
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
    if version == "1.42":
        migrated = dict(payload)
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
    if version == "1.43":
        migrated = dict(payload)
        for sdwan in migrated.get("sdwans", []):
            if not isinstance(sdwan, dict):
                continue
            for check in sdwan.get("health_checks", []):
                if not isinstance(check, dict):
                    continue
                if "servers" not in check:
                    server = check.get("server")
                    check["servers"] = [server] if isinstance(server, str) else []
                for sla in check.get("sla", []):
                    if isinstance(sla, dict):
                        sla.setdefault("link_cost_factors", [])
                        sla.setdefault("source_explicit_fields", [])
                        sla.setdefault("migration_status", "EXTRACT_ONLY")
                        sla.setdefault("requires_manual_review", True)
                        sla.setdefault("review_reasons", [])
                check.setdefault("migration_status", "EXTRACT_ONLY")
                check.setdefault("requires_manual_review", True)
                check.setdefault("review_reasons", [])
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
    if version == "1.34":
        return _migrate_1_34(dict(payload))
    if version == "1.35":
        migrated = dict(payload)
        for rule in migrated.get("nat_rules", []):
            if isinstance(rule, dict):
                rule.setdefault("traffic_type", "unicast")
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
    if version == "1.37":
        return _migrate_1_37(dict(payload))
    if version == "1.38":
        return _migrate_1_38(dict(payload))
    if version == "1.39":
        return _migrate_1_39(dict(payload))
    if version == "1.36":
        return _migrate_1_36(dict(payload))
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
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(_migrate_1_13(dict(payload))))))))))))
    elif version == "1.14":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(dict(payload)))))))))))
    elif version == "1.15":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(_migrate_1_15(dict(payload))))))))))
    elif version == "1.16":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(_migrate_1_16(dict(payload))))))))))
    elif version == "1.17":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(dict(payload)))))))))
    elif version == "1.18":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_18(dict(payload)))))))))
    elif version == "1.19":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(dict(payload))))))))
    elif version == "1.20":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(dict(payload)))))))
    elif version == "1.21":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(dict(payload))))))
    elif version == "1.22":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(dict(payload)))))
    elif version == "1.23":
        return _migrate_1_26(_migrate_1_25(_migrate_1_24(dict(payload))))
    elif version == "1.24":
        return _migrate_1_26(_migrate_1_25(dict(payload)))
    elif version == "1.25":
        return _migrate_1_26(dict(payload))
    elif version == "1.26":
        return _migrate_1_26(dict(payload))
    elif version == "1.27":
        return _migrate_1_26(dict(payload))
    elif version == "1.28":
        return _migrate_1_26(dict(payload))
    elif version == "1.29":
        return _migrate_1_26(dict(payload))
    elif version == "1.33":
        return _migrate_1_33(dict(payload))
    else:
        return dict(payload)
    return _migrate_1_26(_migrate_1_25(_migrate_1_24(_migrate_1_23(_migrate_1_22(_migrate_1_21(_migrate_1_20(_migrate_1_17(_migrate_1_15(_migrate_1_14(_migrate_1_13(_migrate_1_12(migrated))))))))))))


def _migrate_1_44(payload: dict[str, Any]) -> dict[str, Any]:
    """Add source-oriented DHCPv4 fields introduced in schema 1.45."""
    logger.warning("Loaded IR schema 1.44; upgraded to schema 1.45")
    migrated = dict(payload)
    for server in migrated.get("dhcp_servers", []):
        if not isinstance(server, dict):
            continue
        server.setdefault("exclude_ranges", [])
        server.setdefault("options", [])
        server.setdefault("source_explicit_fields", [])
        server.setdefault("review_reasons", [])
        for field in (
            "auto_configuration", "auto_managed_status", "conflicted_ip_timeout",
            "ddns_auth", "ddns_key_format", "ddns_key_name", "ddns_server_ip",
            "ddns_ttl", "ddns_update", "ddns_update_override", "ddns_zone",
            "dhcp_settings_from_fortiipam", "domain", "filename",
            "forticlient_on_net_status", "ip_mode", "ipsec_lease_hold",
            "mac_acl_default_action", "next_server", "ntp_service", "relay_agent",
            "server_type", "shared_subnet", "timezone", "vci_match", "wifi_ac_service",
        ):
            server.setdefault(field, None)
        for field in ("ntp_servers", "tftp_servers", "vci_strings", "wifi_ac_servers", "wins_servers"):
            server.setdefault(field, [])
        server.setdefault("has_ddns_key", False)
        for collection_name in ("ip_ranges", "exclude_ranges"):
            for item in server.get(collection_name, []):
                if not isinstance(item, dict):
                    continue
                item.setdefault("source_context", None)
                item.setdefault("lease_time_seconds", None)
                item.setdefault("uci_match", None)
                item.setdefault("uci_strings", [])
                item.setdefault("vci_match", None)
                item.setdefault("vci_strings", [])
                item.setdefault("source_explicit_fields", [])
                item.setdefault("review_reasons", [])
        for item in server.get("reservations", []):
            if isinstance(item, dict):
                for field in (
                    "source_context", "action", "reservation_type", "circuit_id",
                    "circuit_id_type", "remote_id", "remote_id_type", "description",
                ):
                    item.setdefault(field, None)
                item.setdefault("source_explicit_fields", [])
                item.setdefault("review_reasons", [])
        for item in server.get("options", []):
            if isinstance(item, dict):
                item.setdefault("source_context", None)
                item.setdefault("ips", [])
                item.setdefault("uci_match", None)
                item.setdefault("uci_strings", [])
                item.setdefault("vci_match", None)
                item.setdefault("vci_strings", [])
                item.setdefault("source_explicit_fields", [])
                item.setdefault("review_reasons", [])
    migrated["schema_version"] = "1.45"
    return migrated


def _migrate_1_45(payload: dict[str, Any]) -> dict[str, Any]:
    """Add source-only PAN-OS GlobalProtect collections introduced in schema 1.46."""
    logger.warning("Loaded IR schema 1.45; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated.setdefault("global_protect_portals", [])
    migrated.setdefault("global_protect_gateways", [])
    migrated.setdefault("global_protect_network_gateways", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_36(payload: dict[str, Any]) -> dict[str, Any]:
    """Add RADIUS accounting-server inventory fields introduced in schema 1.37."""
    logger.warning("Loaded IR schema 1.36; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    for radius in migrated.get("user_radius_servers", []):
        if isinstance(radius, dict):
            radius.setdefault("acct_interim_interval", None)
            radius.setdefault("accounting_servers", [])
    migrated.setdefault("user_radius_servers", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_37(payload: dict[str, Any]) -> dict[str, Any]:
    """Add TACACS+ source status cache metadata introduced in schema 1.38."""
    logger.warning("Loaded IR schema 1.37; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    for tacacs in migrated.get("user_tacacs_servers", []):
        if isinstance(tacacs, dict):
            tacacs.setdefault("status_ttl", None)
    migrated.setdefault("user_tacacs_servers", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_38(payload: dict[str, Any]) -> dict[str, Any]:
    """Add expanded LDAP source semantics introduced in schema 1.39."""
    logger.warning("Loaded IR schema 1.38; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    for ldap in migrated.get("user_ldap_servers", []):
        if isinstance(ldap, dict):
            ldap.setdefault("search_type", [])
            ldap.setdefault("client_certificate_resolved", None)
    migrated.setdefault("user_ldap_servers", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_39(payload: dict[str, Any]) -> dict[str, Any]:
    """Add policy security-profile reference audit fields introduced in 1.40."""
    logger.warning("Loaded IR schema 1.39; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    for policy in migrated.get("policies", []):
        if isinstance(policy, dict):
            policy.setdefault("source_security_profile_references", {})
            policy.setdefault("security_profile_reference_statuses", {})
            policy.setdefault("unresolved_security_profile_references", {})
    migrated.setdefault("policies", [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_34(payload: dict[str, Any]) -> dict[str, Any]:
    """Add canonical NAT fidelity fields introduced in schema 1.35."""
    logger.warning("Loaded IR schema 1.34; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    fields = {
        "nat_family": None,
        "original_address_family": None,
        "translated_address_family": None,
        "protocol_number": None,
        "protocol_name": None,
        "original_source_ports": [],
        "original_destination_ports": [],
        "translated_source_ports": [],
        "translated_destination_ports": [],
        "source_port_behavior": None,
        "address_range_mappings": [],
        "install_translation_route": None,
        "runtime_behavior": None,
        "source_origin": None,
    }
    migrated["nat_rules"] = [
        ({**rule, **{key: value for key, value in fields.items() if key not in rule}}
         if isinstance(rule, dict) else rule)
        for rule in payload.get("nat_rules", [])
    ]
    settings = migrated.get("ssl_vpn_settings")
    if isinstance(settings, dict):
        for field in {
            "source_fields": {}, "auth_session_check_source_ip": None,
            "auto_tunnel_static_route": None, "browser_language_detection": None,
            "check_referer": None, "ciphersuite": None,
            "deflate_compression_level": None, "deflate_min_data_size": None,
            "dns_suffix": None, "dtls_heartbeat_fail_count": None,
            "dtls_heartbeat_idle_timeout": None, "dtls_heartbeat_interval": None,
            "dtls_hello_timeout": None, "dtls_max_proto_ver": None,
            "dtls_min_proto_ver": None, "dual_stack_mode": None,
            "encode_2f_sequence": None, "encrypt_and_store_password": None,
            "force_two_factor_auth": None, "header_x_forwarded_for": None,
            "hsts_include_subdomains": None, "http_compression": None,
            "http_only_cookie": None, "http_request_body_timeout": None,
            "http_request_header_timeout": None, "https_redirect": None,
            "ipv6_dns_server1": None, "ipv6_dns_server2": None,
            "ipv6_wins_server1": None, "ipv6_wins_server2": None,
            "login_timeout": None, "port_precedence": None,
            "saml_redirect_port": None, "server_hostname": None,
            "source_address_negate": None, "source_address6": [],
            "source_address6_negate": None, "ssl_client_renegotiation": None,
            "ssl_insert_empty_fragment": None, "transform_backward_slashes": None,
            "tunnel_addr_assigned_method": None, "tunnel_connect_without_reauth": None,
            "tunnel_ipv6_pools": [], "tunnel_user_session_timeout": None,
            "unsafe_legacy_renegotiation": None, "url_obscuration": None,
            "user_peer": None, "x_content_type_options": None,
            "ztna_trusted_client": None,
        }.items():
            settings.setdefault(field, value)
    portal_fields = {
        "source_fields": {}, "client_src_range": None, "clipboard": None,
        "custom_lang": None, "customize_forticlient_download_url": None,
        "default_protocol": None, "default_window_height": None,
        "default_window_width": None, "dhcp_ip_overlap": None,
        "dhcp_ra_giaddr": None, "dhcp6_ra_linkaddr": None,
        "display_bookmark": None, "display_connection_tools": None,
        "display_history": None, "display_status": None, "dns_server1": None,
        "dns_server2": None, "dns_suffix": None, "focus_bookmark": None,
        "forticlient_download_method": None, "heading": None,
        "hide_sso_credential": None, "ipv6_dns_server1": None,
        "ipv6_dns_server2": None, "ipv6_exclusive_routing": None,
        "ipv6_service_restriction": None, "ipv6_split_tunneling": None,
        "ipv6_split_tunneling_routing_address": [],
        "ipv6_split_tunneling_routing_negate": None, "ipv6_wins_server1": None,
        "ipv6_wins_server2": None, "keep_alive": None, "landing_page_mode": None,
        "mac_addr_action": None, "mac_addr_check": None,
        "macos_forticlient_download_url": None, "os_check": None,
        "prefer_ipv6_dns": None, "redir_url": None, "rewrite_ip_uri_ui": None,
        "save_password": None, "skip_check_for_browser": None,
        "skip_check_for_unsupported_os": None, "smb_max_version": None,
        "smb_min_version": None, "smb_ntlmv1_auth": None, "smbv1": None,
        "theme": None, "use_sdwan": None, "user_bookmark": None,
        "user_group_bookmark": None, "web_mode": None,
        "windows_forticlient_download_url": None, "wins_server1": None,
        "wins_server2": None, "bookmark_groups": [], "landing_pages": [],
        "mac_address_check_rules": [], "os_check_list": [], "split_dns": [],
    }
    migrated["ssl_vpn_portals"] = [
        ({**portal, **{key: value for key, value in portal_fields.items() if key not in portal}}
         if isinstance(portal, dict) else portal)
        for portal in migrated.get("ssl_vpn_portals", [])
    ]
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_33(payload: dict[str, Any]) -> dict[str, Any]:
    """Add FortiGate policy configured/effective source semantics."""
    logger.warning(
        "Loaded IR schema 1.33; upgraded to schema %s",
        IR_SCHEMA_VERSION,
    )
    migrated = dict(payload)
    policies = []
    for source_policy in payload.get("policies", []):
        if not isinstance(source_policy, dict):
            policies.append(source_policy)
            continue
        policy = dict(source_policy)
        for field in (
            "source_timeout_send_rst",
            "source_auto_asic_offload",
            "source_np_acceleration",
            "source_port_preserve",
            "source_effective_utm_status",
            "source_effective_inspection_mode",
            "source_effective_ztna_status",
            "source_effective_timeout_send_rst",
            "source_effective_auto_asic_offload",
            "source_effective_np_acceleration",
            "source_effective_port_preserve",
        ):
            policy.setdefault(field, None)
        policies.append(policy)
    migrated["policies"] = policies
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_26(payload: dict[str, Any]) -> dict[str, Any]:
    """Add source interface inventory fields through schema 1.30."""
    logger.warning("Loaded an older IR schema; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["interfaces"] = [
        ({**interface, "source_monitor_bandwidth": None}
         if isinstance(interface, dict) and "source_monitor_bandwidth" not in interface
         else interface)
        for interface in payload.get("interfaces", [])
    ]
    for interface in migrated["interfaces"]:
        if isinstance(interface, dict):
            interface.setdefault("has_pppoe_password", None)
            interface.setdefault("pppoe_password_format", None)
            interface.setdefault("source_dns_server_override", None)
            interface.setdefault("source_dedicated_to", None)
            interface.setdefault("source_ike_saml_server", None)
            interface.setdefault("source_ike_saml_server_resolved", None)
            interface.setdefault("source_src_check", None)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_25(payload: dict[str, Any]) -> dict[str, Any]:
    """Add source interface media-type inventory."""
    logger.warning("Loaded IR schema 1.24; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["interfaces"] = [
        ({**interface, "source_media_type": None}
         if isinstance(interface, dict) and "source_media_type" not in interface
         else interface)
        for interface in payload.get("interfaces", [])
    ]
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_24(payload: dict[str, Any]) -> dict[str, Any]:
    """Add source device-identification inventory to interfaces."""
    logger.warning("Loaded IR schema 1.23; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["interfaces"] = [
        ({**interface, "source_device_identification": None}
         if isinstance(interface, dict) and "source_device_identification" not in interface
         else interface)
        for interface in payload.get("interfaces", [])
    ]
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_23(payload: dict[str, Any]) -> dict[str, Any]:
    """Add source-only FortiGate identity-based-route policy provenance."""
    logger.warning("Loaded IR schema 1.22; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    migrated["policies"] = [
        ({**policy, "source_identity_based_route": policy.get("source_identity_based_route")}
         if isinstance(policy, dict) else policy)
        for policy in payload.get("policies", [])
    ]
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


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


def _migrate_1_21(payload: dict[str, Any]) -> dict[str, Any]:
    """Add PAN-OS source-oriented interface inventory fields."""
    logger.warning("Loaded an older IR schema; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    interfaces = []
    for source_interface in payload.get("interfaces", []):
        if not isinstance(source_interface, dict):
            interfaces.append(source_interface)
            continue
        interface = dict(source_interface)
        interface.setdefault("source_mtu", None)
        interface.setdefault("source_link_state", None)
        interface.setdefault("source_speed", None)
        interface.setdefault("source_duplex", None)
        interface.setdefault("source_netflow_profile", None)
        interface.setdefault("source_lldp_enabled", None)
        interfaces.append(interface)
    migrated["interfaces"] = interfaces
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated


def _migrate_1_22(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the optional effective action to FortiGate source-only rules."""
    logger.warning("Loaded IR schema 1.21; upgraded to schema %s", IR_SCHEMA_VERSION)
    migrated = dict(payload)
    for collection in (
        "central_snat_rules",
        "security_policies",
        "policy_routes",
        "local_in_policies",
        "proxy_policies",
        "shaping_policies",
        "dhcp6_servers",
        "source_only_rules",
        "custom_internet_services",
        "custom_internet_service_groups",
    ):
        if collection not in payload:
            continue
        rules = []
        for source_rule in payload.get(collection, []):
            if not isinstance(source_rule, dict):
                rules.append(source_rule)
                continue
            rule = dict(source_rule)
            rule.setdefault("effective_action", None)
            rules.append(rule)
        migrated[collection] = rules
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
