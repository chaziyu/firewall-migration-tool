"""Pair-specific completeness accounting for FortiGate to PAN-OS migration."""

from collections import Counter


# FortiGate source families that are extracted and preserved but are not currently
# represented by PANMigrationPlan or by the recommendation engine. Their presence
# must prevent a rendered subset from being reported as a complete migration.
_SOURCE_ONLY_FAMILIES = (
    ("wildcard_fqdns", "wildcard_fqdn"),
    ("ip_pools6", "ip_pool6"),
    ("vip_groups", "vip_group"),
    ("vips6", "vip6"),
    ("vip_groups6", "vip_group6"),
    ("security_policies", "security_policy"),
    ("protocol_options", "protocol_options"),
    ("per_ip_shapers", "per_ip_shaper"),
    ("session_helpers", "session_helper"),
    ("nac_policies", "nac_policy"),
    ("address6_templates", "address6_template"),
    ("ips_settings", "ips_settings"),
    ("kmip_servers", "kmip_server"),
    ("kerberos_keytabs", "kerberos_keytab"),
    ("router_settings", "router_settings"),
    ("sdn_proxies", "sdn_proxy"),
    ("on_demand_sniffers", "on_demand_sniffer"),
    ("affinity_interrupts", "affinity_interrupt"),
    ("serial_ports", "serial_port"),
    ("firewall_regions", "firewall_region"),
    ("vendor_macs", "vendor_mac"),
    ("ssl_vpn_realms", "ssl_vpn_realm"),
    ("ssl_vpn_clients", "ssl_vpn_client"),
    ("ssl_vpn_user_bookmarks", "ssl_vpn_user_bookmark"),
    ("ssl_vpn_user_group_bookmarks", "ssl_vpn_user_group_bookmark"),
    ("ssl_vpn_host_check_software", "ssl_vpn_host_check_software"),
    ("service_categories", "service_category"),
)


def _identity(item, index):
    vdom = getattr(item, "vdom", None) or "root"
    for field in ("name", "id", "seq_num"):
        value = getattr(item, field, None)
        if value not in (None, ""):
            return vdom, str(value)
    return vdom, str(index)


def build_migration_coverage(source, recommendations=()):
    """Return migration work that is preserved but not executable yet.

    This is deliberately FortiGate -> PAN-OS specific. It does not create a
    vendor-neutral model and it does not infer target configuration.
    """
    unplanned = []

    for recommendation in recommendations:
        unplanned.append({
            "status": "RECOMMENDATION_ONLY",
            "source_vdom": recommendation.source_vdom,
            "source_kind": recommendation.source_kind,
            "source_name": recommendation.source_name,
            "family": recommendation.family,
            "target_object_type": recommendation.target_object_type,
            "readiness": recommendation.readiness.value,
            "reason": "Source configuration is represented as review guidance but is not emitted by PANMigrationPlan.",
        })

    for attribute, source_kind in _SOURCE_ONLY_FAMILIES:
        for index, item in enumerate(getattr(source, attribute, ()) or ()):
            vdom, name = _identity(item, index)
            unplanned.append({
                "status": "SOURCE_ONLY",
                "source_vdom": vdom,
                "source_kind": source_kind,
                "source_name": name,
                "family": attribute,
                "target_object_type": None,
                "readiness": "UNSUPPORTED",
                "reason": "Source configuration is preserved but this migration pair has no executable planner coverage for it.",
            })

    unplanned.sort(key=lambda item: (
        item["status"],
        str(item["source_vdom"]).casefold(),
        str(item["source_kind"]).casefold(),
        str(item["source_name"]).casefold(),
    ))
    counts = Counter(item["status"] for item in unplanned)
    return {
        "complete": not unplanned,
        "unplanned_count": len(unplanned),
        "counts": {
            "RECOMMENDATION_ONLY": counts["RECOMMENDATION_ONLY"],
            "SOURCE_ONLY": counts["SOURCE_ONLY"],
        },
        "unplanned": unplanned,
    }


__all__ = ["build_migration_coverage"]
