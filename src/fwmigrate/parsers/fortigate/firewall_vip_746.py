"""FortiOS 7.4.6 firewall VIP source contract and validation.

This module defines the FortiOS 7.4.6 source-side field contract for
``config firewall vip``.  It does not imply target-vendor portability.
Unknown, malformed, or source-only behavior must remain review evidence.
"""

from __future__ import annotations

from typing import Any


FORTIOS_746_VIP_FIELDS = frozenset({
    "add_nat46_route",
    "arp_reply",
    "color",
    "comment",
    "dns_mapping_ttl",
    "extaddr",
    "extintf",
    "extip",
    "extport",
    "gratuitous_arp_interval",
    "gslb_domain_name",
    "gslb_hostname",
    "h2_support",
    "h3_support",
    "http_cookie_age",
    "http_cookie_domain",
    "http_cookie_domain_from_host",
    "http_cookie_generation",
    "http_cookie_path",
    "http_cookie_share",
    "http_ip_header",
    "http_ip_header_name",
    "http_multiplex",
    "http_multiplex_max_concurrent_request",
    "http_multiplex_max_request",
    "http_multiplex_ttl",
    "http_redirect",
    "https_cookie_secure",
    "id",
    "ipv6_mappedip",
    "ipv6_mappedport",
    "ldb_method",
    "mapped_addr",
    "mappedip",
    "mappedport",
    "max_embryonic_connections",
    "monitor",
    "nat_source_vip",
    "nat44",
    "nat46",
    "one_click_gslb_server",
    "outlook_web_access",
    "persistence",
    "portforward",
    "portmapping_type",
    "protocol",
    "server_type",
    "service",
    "src_filter",
    "src_vip_filter",
    "srcintf_filter",
    "ssl_accept_ffdhe_groups",
    "ssl_algorithm",
    "ssl_certificate",
    "ssl_client_fallback",
    "ssl_client_rekey_count",
    "ssl_client_renegotiation",
    "ssl_client_session_state_max",
    "ssl_client_session_state_timeout",
    "ssl_client_session_state_type",
    "ssl_dh_bits",
    "ssl_hpkp",
    "ssl_hpkp_age",
    "ssl_hpkp_backup",
    "ssl_hpkp_include_subdomains",
    "ssl_hpkp_primary",
    "ssl_hpkp_report_uri",
    "ssl_hsts",
    "ssl_hsts_age",
    "ssl_hsts_include_subdomains",
    "ssl_http_location_conversion",
    "ssl_http_match_host",
    "ssl_max_version",
    "ssl_min_version",
    "ssl_mode",
    "ssl_pfs",
    "ssl_send_empty_frags",
    "ssl_server_algorithm",
    "ssl_server_max_version",
    "ssl_server_min_version",
    "ssl_server_renegotiation",
    "ssl_server_session_state_max",
    "ssl_server_session_state_timeout",
    "ssl_server_session_state_type",
    "status",
    "type",
    "uuid",
    "weblogic_server",
    "websphere_server",
})

FORTIOS_746_VIP_NESTED_SECTIONS = frozenset({
    "gslb-public-ips",
    "quic",
    "realservers",
    "ssl-cipher-suites",
    "ssl-server-cipher-suites",
})

FORTIOS_746_VIP_DEFAULTS = {
    "add_nat46_route": "enable",
    "arp_reply": "enable",
    "extintf": "any",
    "nat44": "enable",
    "nat46": "disable",
    "portforward": "disable",
    "portmapping_type": "1-to-1",
    "protocol": "tcp",
    "status": "enable",
    "type": "static-nat",
}

FORTIOS_746_VIP_TYPES = frozenset({
    "static-nat",
    "load-balance",
    "server-load-balance",
    "dns-translation",
    "fqdn",
})

FORTIOS_746_VIP_BOOKKEEPING_EXTRA_SETTINGS = frozenset({
    "invalid_fields",
    "unparsed_fields",
})


def effective_vip_settings_746(vip: Any) -> dict[str, Any]:
    """Return FortiOS effective defaults without altering source provenance."""
    explicit = set(getattr(vip, "source_explicit_fields", set()) or set())
    settings: dict[str, Any] = {}
    for field, default in FORTIOS_746_VIP_DEFAULTS.items():
        value = getattr(vip, field, None)
        if field in explicit:
            settings[field] = value
        elif value is not None:
            settings[field] = value
        else:
            settings[field] = default
    return settings


def validate_vip_746(vip: Any, source_version: str | None = None) -> list[str]:
    """Validate source accounting against the FortiOS 7.4.6 VIP contract.

    The function is intentionally conservative.  It reports source fields that
    fall outside the reviewed contract, official fields that were preserved only
    in ``extra_settings``, malformed values, and unknown VIP types.  It does not
    decide whether a valid FortiOS feature is portable to a target platform.
    """
    reasons: list[str] = []

    explicit = set(getattr(vip, "source_explicit_fields", set()) or set())
    for field in sorted(explicit - FORTIOS_746_VIP_FIELDS):
        reasons.append(
            f"VIP field '{field.replace('_', '-')}' is outside the FortiOS 7.4.6 reviewed contract."
        )

    vip_type = getattr(vip, "type", None)
    if vip_type and vip_type not in FORTIOS_746_VIP_TYPES:
        reasons.append(f"Unknown FortiOS 7.4.6 VIP type '{vip_type}'.")

    extra_settings = dict(getattr(vip, "extra_settings", {}) or {})
    for key in sorted(extra_settings):
        if key in FORTIOS_746_VIP_BOOKKEEPING_EXTRA_SETTINGS:
            continue
        if key.startswith("unparsed_"):
            reasons.append(
                "VIP contains invalid source value for "
                f"{key.removeprefix('unparsed_').replace('_', '-')} ."
            )
            continue
        if key in FORTIOS_746_VIP_FIELDS:
            reasons.append(
                f"FortiOS 7.4.6 VIP field '{key.replace('_', '-')}' is source-preserved but not typed."
            )
        else:
            reasons.append(
                f"VIP contains unmodeled source setting '{key}' and requires target-specific review."
            )

    return reasons
