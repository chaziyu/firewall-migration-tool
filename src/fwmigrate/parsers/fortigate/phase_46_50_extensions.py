"""FortiGate phases 46-50 extraction extensions.

The implementation deliberately remains source-oriented.  It improves typed
FortiOS 7.4.6 extraction and dependency accounting without claiming portable
target semantics for IPS, SSL inspection, profile groups, or vendor-specific
IPv6 controls.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import (
    FGDHCPv6IAPD,
    FGInterfaceIPv6ExtraAddress,
    FGInterfaceVRRP6,
    FGIPSSensor,
    FGIPSSensorEntry,
    FGIPSSensorExemptIP,
    FGIPv6DelegatedPrefixAdvertisement,
    FGIPv6PrefixAdvertisement,
    FGProfileGroup,
    FGProfileNestedSection,
    FGSSLSSHExemption,
    FGSSLSSHProfile,
    FGSSLSSHProtocolInspection,
)
from fwmigrate.parsers.fortigate.phase_41_security_profiles import (
    PROFILE_SECURITY_SECRET_FIELDS,
    _effective_node_attributes,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


# ---------------------------------------------------------------------------
# Phase 46 - IPS sensors
# ---------------------------------------------------------------------------


class FGIPSSelectorCriteria(BaseModel):
    """FortiOS IPS filter/selectors.  Never inferred from signature IDs."""

    severity: List[str] = Field(default_factory=list)
    protocol: List[str] = Field(default_factory=list)
    application: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    os: List[str] = Field(default_factory=list)
    vuln_type: List[int] = Field(default_factory=list)
    location: Optional[str] = None


class FGIPSSignatureCriteria(BaseModel):
    """Explicit FortiOS IPS signature/rule identifiers."""

    rule_ids: List[int] = Field(default_factory=list)


class FGIPSSensorEntry746(FGIPSSensorEntry):
    """7.4.6 IPS entry with explicit filter-vs-signature semantics."""

    selector_criteria: FGIPSSelectorCriteria = Field(default_factory=FGIPSSelectorCriteria)
    signature_criteria: FGIPSSignatureCriteria = Field(default_factory=FGIPSSignatureCriteria)
    last_modified: Optional[str] = None


IPS_SENSOR_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "block_malicious_url",
        "comment",
        "extended_log",
        "replacemsg_group",
        "scan_botnet_connections",
    },
}

IPS_ENTRY_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "action",
        "default_action",
        "default_status",
        "last_modified",
        "location",
        "log",
        "log_attack_context",
        "log_packet",
        "quarantine",
        "quarantine_expiry",
        "quarantine_log",
        "rate_mode",
        "rate_track",
        "status",
    },
    "list_fields": {
        "application",
        "cve",
        "os",
        "protocol",
        "severity",
    },
    "int_fields": {"rate_count", "rate_duration"},
    "int_list_fields": {"rule", "vuln_type"},
}

IPS_EXEMPT_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"src_ip", "dst_ip"},
}


def _entry_identity(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        # The source ID remains in source evidence.  Use -1 only as a typed
        # sentinel because the existing model requires an integer ID.
        return -1


def _build_ips_sensor(parser: Any, nodes: List[FGSourceNode]) -> None:
    for node in nodes:
        effective, extra = _effective_node_attributes(node, IPS_SENSOR_SPEC)
        entries: List[FGIPSSensorEntry] = []

        entries_nodes = [
            child for child in node.children
            if child.node_type == "config" and child.name.lower() == "entries"
        ]
        for entries_node in entries_nodes:
            for entry_node in entries_node.children:
                if entry_node.node_type != "edit":
                    continue

                values, entry_extra = _effective_node_attributes(entry_node, IPS_ENTRY_SPEC)
                rules = list(values.pop("rule", []))
                vuln_type = list(values.get("vuln_type", []))

                # Keep the existing public malformed-rule evidence name for
                # compatibility while using the shared evaluator internally.
                malformed_rules = entry_extra.pop("unparsed_rule", None)
                if malformed_rules is not None:
                    entry_extra["unparsed_rule_values"] = (
                        malformed_rules if isinstance(malformed_rules, list) else [malformed_rules]
                    )
                malformed_append_rules = entry_extra.pop("unparsed_append_rule", None)
                if malformed_append_rules is not None:
                    entry_extra.setdefault("unparsed_rule_values", []).extend(
                        malformed_append_rules
                        if isinstance(malformed_append_rules, list)
                        else [malformed_append_rules]
                    )

                exempt_ips: List[FGIPSSensorExemptIP] = []
                for child in entry_node.children:
                    if child.node_type != "config" or child.name.lower() != "exempt-ip":
                        continue
                    for exempt_node in child.children:
                        if exempt_node.node_type != "edit":
                            continue
                        exempt_values, exempt_extra = _effective_node_attributes(
                            exempt_node, IPS_EXEMPT_SPEC
                        )
                        exempt_extra = sanitize_source_attributes(exempt_extra)
                        if exempt_extra:
                            # FGIPSSensorExemptIP has no generic extension bag.
                            # Preserve unknown nested data in the parent entry
                            # without altering the authoritative source tree.
                            entry_extra.setdefault("exempt_ip_extra_settings", {})[
                                exempt_node.name
                            ] = exempt_extra
                        exempt_ips.append(
                            FGIPSSensorExemptIP(
                                id=_entry_identity(exempt_node.name),
                                src_ip=exempt_values.get("src_ip"),
                                dst_ip=exempt_values.get("dst_ip"),
                            )
                        )

                selector = FGIPSSelectorCriteria(
                    severity=list(values.get("severity", [])),
                    protocol=list(values.get("protocol", [])),
                    application=list(values.get("application", [])),
                    cve=list(values.get("cve", [])),
                    os=list(values.get("os", [])),
                    vuln_type=vuln_type,
                    location=values.get("location"),
                )
                signature = FGIPSSignatureCriteria(rule_ids=rules)

                entries.append(
                    FGIPSSensorEntry746(
                        id=_entry_identity(entry_node.name),
                        rules=rules,
                        exempt_ips=exempt_ips,
                        selector_criteria=selector,
                        signature_criteria=signature,
                        extra_settings=sanitize_source_attributes(entry_extra),
                        **{
                            key: value
                            for key, value in values.items()
                            if key in FGIPSSensorEntry746.model_fields
                            and key not in {
                                "id",
                                "rules",
                                "exempt_ips",
                                "selector_criteria",
                                "signature_criteria",
                                "extra_settings",
                            }
                        },
                    )
                )

        sensor_values = {
            key: value
            for key, value in effective.items()
            if key in FGIPSSensor.model_fields and key not in {"name", "entries", "extra_settings"}
        }
        parser.config.ips_sensors.append(
            FGIPSSensor(
                name=node.name,
                entries=entries,
                extra_settings=sanitize_source_attributes(extra),
                **sensor_values,
            )
        )


# ---------------------------------------------------------------------------
# Phase 47 - SSL/SSH inspection
# ---------------------------------------------------------------------------


class FGSSLSSHProtocolInspection746(FGSSLSSHProtocolInspection):
    cert_probe_failure: Optional[str] = None
    cert_validation_failure: Optional[str] = None
    cert_validation_timeout: Optional[str] = None
    client_certificate: Optional[str] = None
    encrypted_client_hello: Optional[str] = None
    expired_server_cert: Optional[str] = None
    inspect_all: Optional[str] = None
    min_allowed_ssl_version: Optional[str] = None
    proxy_after_tcp_handshake: Optional[str] = None
    quic: Optional[str] = None
    revoked_server_cert: Optional[str] = None
    sni_server_cert_check: Optional[str] = None
    ssh_algorithm: Optional[str] = None
    ssh_tun_policy_check: Optional[str] = None
    unsupported_ssl_cipher: Optional[str] = None
    unsupported_ssl_negotiation: Optional[str] = None
    unsupported_ssl_version: Optional[str] = None
    unsupported_version: Optional[str] = None
    untrusted_server_cert: Optional[str] = None


class FGSSLSSHExemption746(FGSSLSSHExemption):
    address6: Optional[str] = None
    fortiguard_category: Optional[int] = None
    regex: Optional[str] = None
    type: Optional[str] = None
    wildcard_fqdn: Optional[str] = None


class FGSSLSSHServer746(BaseModel):
    name: str
    ftps_client_certificate: Optional[str] = None
    https_client_certificate: Optional[str] = None
    imaps_client_certificate: Optional[str] = None
    ip: Optional[str] = None
    pop3s_client_certificate: Optional[str] = None
    smtps_client_certificate: Optional[str] = None
    ssl_other_client_certificate: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLECHOuterSNI746(BaseModel):
    name: str
    sni: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLSSHProfile746(FGSSLSSHProfile):
    allowlist: Optional[str] = None
    block_blocklisted_certificates: Optional[str] = None
    caname: Optional[str] = None
    mapi_over_https: Optional[str] = None
    rpc_over_https: Optional[str] = None
    server_cert: List[str] = Field(default_factory=list)
    server_cert_mode: Optional[str] = None
    ssl_anomaly_log: Optional[str] = None
    ssl_exemption_ip_rating: Optional[str] = None
    ssl_exemption_log: Optional[str] = None
    ssl_handshake_log: Optional[str] = None
    ssl_negotiation_log: Optional[str] = None
    ssl_server_cert_log: Optional[str] = None
    supported_alpn: List[str] = Field(default_factory=list)
    untrusted_caname: Optional[str] = None
    use_ssl_server: Optional[str] = None
    servers: List[FGSSLSSHServer746] = Field(default_factory=list)
    ech_outer_sni: List[FGSSLECHOuterSNI746] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)


SSL_ROOT_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "allowlist",
        "block_blocklisted_certificates",
        "caname",
        "comment",
        "inspection_mode",
        "mapi_over_https",
        "rpc_over_https",
        "server_cert_mode",
        "ssl_anomaly_log",
        "ssl_exemption_ip_rating",
        "ssl_exemption_log",
        "ssl_handshake_log",
        "ssl_negotiation_log",
        "ssl_server_cert_log",
        "untrusted_caname",
        "use_ssl_server",
    },
    "list_fields": {"server_cert", "supported_alpn"},
}

SSL_PROTOCOL_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "action",
        "cert_probe_failure",
        "cert_validation_failure",
        "cert_validation_timeout",
        "client_certificate",
        "encrypted_client_hello",
        "expired_server_cert",
        "inspect_all",
        "min_allowed_ssl_version",
        "proxy_after_tcp_handshake",
        "quic",
        "revoked_server_cert",
        "sni_server_cert_check",
        "ssh_algorithm",
        "ssh_tun_policy_check",
        "status",
        "unsupported_ssl_cipher",
        "unsupported_ssl_negotiation",
        "unsupported_ssl_version",
        "unsupported_version",
        "untrusted_server_cert",
    },
    "list_fields": {"ports"},
}

SSL_EXEMPT_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"address", "address6", "action", "regex", "status", "type", "wildcard_fqdn"},
    "int_fields": {"fortiguard_category"},
}

SSL_SERVER_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "ftps_client_certificate",
        "https_client_certificate",
        "imaps_client_certificate",
        "ip",
        "pop3s_client_certificate",
        "smtps_client_certificate",
        "ssl_other_client_certificate",
    },
}

SSL_ECH_SPEC: Dict[str, set[str]] = {"scalar_fields": {"sni"}}

SSL_PROTOCOL_SECTIONS = frozenset({"dot", "ftps", "https", "imaps", "pop3s", "smtps", "ssh", "ssl"})
SSL_EXEMPTION_SECTIONS = frozenset({"ssl-exempt"})
SSL_SERVER_SECTIONS = frozenset({"ssl-server"})
SSL_ECH_SECTIONS = frozenset({"ech-outer-sni"})


def _build_ssl_ssh_profile(parser: Any, nodes: List[FGSourceNode]) -> None:
    for node in nodes:
        root_values, root_extra = _effective_node_attributes(node, SSL_ROOT_SPEC)
        profile = FGSSLSSHProfile746(
            name=node.name,
            settings=sanitize_source_attributes(dict(root_values)),
            extra_settings=sanitize_source_attributes(root_extra),
            **{
                key: value
                for key, value in root_values.items()
                if key in FGSSLSSHProfile746.model_fields
                and key not in {"name", "settings", "extra_settings"}
            },
        )

        for child in node.children:
            if child.node_type != "config":
                continue
            child_name = child.name.lower()

            if child_name in SSL_PROTOCOL_SECTIONS:
                values, extra = _effective_node_attributes(child, SSL_PROTOCOL_SPEC)
                profile.protocols.append(
                    FGSSLSSHProtocolInspection746(
                        name=child.name,
                        settings=sanitize_source_attributes(dict(values)),
                        extra_settings=sanitize_source_attributes(extra),
                        **{
                            key: value
                            for key, value in values.items()
                            if key in FGSSLSSHProtocolInspection746.model_fields
                            and key not in {"name", "settings", "extra_settings"}
                        },
                    )
                )
                continue

            if child_name in SSL_EXEMPTION_SECTIONS:
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    values, extra = _effective_node_attributes(entry, SSL_EXEMPT_SPEC)
                    profile.exemptions.append(
                        FGSSLSSHExemption746(
                            name=entry.name,
                            extra_settings=sanitize_source_attributes(extra),
                            **{
                                key: value
                                for key, value in values.items()
                                if key in FGSSLSSHExemption746.model_fields
                                and key not in {"name", "extra_settings"}
                            },
                        )
                    )
                continue

            if child_name in SSL_SERVER_SECTIONS:
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    values, extra = _effective_node_attributes(entry, SSL_SERVER_SPEC)
                    profile.servers.append(
                        FGSSLSSHServer746(
                            name=entry.name,
                            extra_settings=sanitize_source_attributes(extra),
                            **{
                                key: value
                                for key, value in values.items()
                                if key in FGSSLSSHServer746.model_fields
                                and key not in {"name", "extra_settings"}
                            },
                        )
                    )
                continue

            if child_name in SSL_ECH_SECTIONS:
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    values, extra = _effective_node_attributes(entry, SSL_ECH_SPEC)
                    profile.ech_outer_sni.append(
                        FGSSLECHOuterSNI746(
                            name=entry.name,
                            sni=values.get("sni"),
                            extra_settings=sanitize_source_attributes(extra),
                        )
                    )
                continue

            # Unknown/future nested sections remain structured evidence.  They
            # are intentionally not guessed into protocol/certificate/exempt
            # buckets.
            profile.entries.append(_generic_source_section(child))

        parser.config.ssl_ssh_profiles.append(profile)


def _generic_source_section(node: FGSourceNode) -> FGProfileNestedSection:
    values, extra = _effective_node_attributes(node, {})
    settings = dict(values)
    settings.update(extra)
    return FGProfileNestedSection(
        name=node.name,
        settings=sanitize_source_attributes(settings),
        entries=[_generic_source_section(child) for child in node.children],
    )


# ---------------------------------------------------------------------------
# Phase 48 - profile groups and dependencies
# ---------------------------------------------------------------------------


class FGProfileGroup746(FGProfileGroup):
    ips_voip_filter: Optional[str] = None


PROFILE_GROUP_FIELDS = {
    "application_list",
    "av_profile",
    "casb_profile",
    "cifs_profile",
    "diameter_filter_profile",
    "dlp_profile",
    "dnsfilter_profile",
    "emailfilter_profile",
    "file_filter_profile",
    "icap_profile",
    "ips_sensor",
    "ips_voip_filter",
    "profile_protocol_options",
    "sctp_filter_profile",
    "ssh_filter_profile",
    "ssl_ssh_profile",
    "videofilter_profile",
    "virtual_patch_profile",
    "voip_profile",
    "waf_profile",
    "webfilter_profile",
}

PROFILE_GROUP_SPEC = {"scalar_fields": set(PROFILE_GROUP_FIELDS)}

PROFILE_GROUP_REFERENCE_RULES = {
    "application-list": "application list",
    "av-profile": "antivirus profile",
    "casb-profile": "casb profile",
    "cifs-profile": "cifs profile",
    "diameter-filter-profile": "diameter-filter profile",
    "dlp-profile": "dlp profile",
    "dnsfilter-profile": "dnsfilter profile",
    "emailfilter-profile": "emailfilter profile",
    "file-filter-profile": "file-filter profile",
    "icap-profile": "icap profile",
    "ips-sensor": "ips sensor",
    "ips-voip-filter": "voip profile",
    "profile-protocol-options": "firewall profile-protocol-options",
    "sctp-filter-profile": "sctp-filter profile",
    "ssh-filter-profile": "ssh-filter profile",
    "ssl-ssh-profile": "firewall ssl-ssh-profile",
    "videofilter-profile": "videofilter profile",
    "virtual-patch-profile": "virtual-patch profile",
    "voip-profile": "voip profile",
    "waf-profile": "waf profile",
    "webfilter-profile": "webfilter profile",
}


def _build_profile_groups(parser: Any, nodes: List[FGSourceNode]) -> None:
    for node in nodes:
        values, extra = _effective_node_attributes(node, PROFILE_GROUP_SPEC)
        parser.config.profile_groups.append(
            FGProfileGroup746(
                name=node.name,
                source_context=parser.current_context or "root",
                extra_settings=sanitize_source_attributes(extra),
                **{
                    key: value
                    for key, value in values.items()
                    if key in FGProfileGroup746.model_fields
                    and key not in {"name", "source_context", "extra_settings"}
                },
            )
        )


def _install_profile_group_dependencies(dependencies_module: Any) -> None:
    for field, target in PROFILE_GROUP_REFERENCE_RULES.items():
        key = ("firewall profile-group", field)
        dependencies_module.REFERENCE_RULES[key] = target
        dependencies_module.REFERENCE_TARGET_SECTIONS[key] = {target}


# ---------------------------------------------------------------------------
# Phase 49 - IPv6 interface effective-state hardening
# ---------------------------------------------------------------------------


IPV6_TYPED_CHILDREN = frozenset({
    "ip6-extra-addr",
    "ip6-prefix-list",
    "ip6-delegated-prefix-list",
    "dhcp6-iapd-list",
    "vrrp6",
})


def _normalized_model_command_fields(model: Any, synthetic: set[str]) -> set[str]:
    return {
        field.replace("_", "-")
        for field in model.model_fields
        if field not in synthetic
    }


IPV6_CHILD_FIELDS = {
    "ip6-extra-addr": set(),
    "ip6-prefix-list": _normalized_model_command_fields(
        FGIPv6PrefixAdvertisement, {"prefix", "extra_settings"}
    ),
    "ip6-delegated-prefix-list": _normalized_model_command_fields(
        FGIPv6DelegatedPrefixAdvertisement, {"prefix_id", "extra_settings"}
    ),
    "dhcp6-iapd-list": _normalized_model_command_fields(
        FGDHCPv6IAPD, {"source_iaid", "iaid", "extra_settings"}
    ),
    "vrrp6": _normalized_model_command_fields(
        FGInterfaceVRRP6, {"source_vrid", "vrid", "extra_settings"}
    ),
}


def _evaluate_ipv6_child(entry: FGSourceNode, model: Any, spec: Dict[str, set[str]]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    return _effective_node_attributes(entry, spec)


def _refresh_interface_ipv6_from_source(config: Any, parser_module: Any) -> None:
    root_spec = {
        "scalar_fields": set(getattr(parser_module, "FG_INTERFACE_IPV6_SCALAR_FIELDS", set())),
        "list_fields": set(getattr(parser_module, "FG_INTERFACE_IPV6_LIST_FIELDS", set())),
        "int_fields": set(getattr(parser_module, "FG_INTERFACE_IPV6_INT_FIELDS", set())),
    }
    # autoconf is stored under ipv6_autoconf in FGInterface.
    root_spec["scalar_fields"].add("autoconf")

    prefix_spec = {
        "scalar_fields": {"autonomous_flag", "onlink_flag"},
        "list_fields": {"dnssl", "rdnss"},
        "int_fields": {"preferred_life_time", "valid_life_time"},
    }
    delegated_spec = {
        "scalar_fields": {"autonomous_flag", "onlink_flag", "rdnss_service", "subnet", "upstream_interface"},
        "list_fields": {"rdnss"},
        "int_fields": {"delegated_prefix_iaid"},
    }
    iapd_spec = {
        "scalar_fields": {"prefix_hint"},
        "int_fields": {"prefix_hint_plt", "prefix_hint_vlt"},
    }
    vrrp6_spec = {
        "scalar_fields": {"accept_mode", "ignore_default_route", "preempt", "status", "vrdst6", "vrip6"},
        "int_fields": {"adv_interval", "priority", "start_time", "vrdst6_priority", "vrgrp"},
    }

    for interface in config.interfaces:
        ipv6_node = next(
            (
                node for node in getattr(interface, "nested_configs", [])
                if getattr(node, "node_type", None) == "config" and node.name == "ipv6"
            ),
            None,
        )
        if ipv6_node is None:
            continue

        values, extra = _effective_node_attributes(ipv6_node, root_spec)
        for key, value in values.items():
            model_key = "ipv6_autoconf" if key == "autoconf" else key
            if model_key in interface.__class__.model_fields:
                setattr(interface, model_key, value)
        if extra:
            source_settings = dict(getattr(interface, "ipv6_source_settings", {}) or {})
            source_settings.update(sanitize_source_attributes(extra))
            interface.ipv6_source_settings = source_settings

        extra_addresses: List[FGInterfaceIPv6ExtraAddress] = []
        prefixes: List[FGIPv6PrefixAdvertisement] = []
        delegated: List[FGIPv6DelegatedPrefixAdvertisement] = []
        iapd: List[FGDHCPv6IAPD] = []
        vrrp6: List[FGInterfaceVRRP6] = []

        for child in ipv6_node.children:
            if child.node_type != "config":
                continue
            if child.name == "ip6-extra-addr":
                for entry in child.children:
                    if entry.node_type == "edit":
                        _, child_extra = _effective_node_attributes(entry, {})
                        extra_addresses.append(
                            FGInterfaceIPv6ExtraAddress(
                                source_address=entry.name,
                                extra_settings=sanitize_source_attributes(child_extra),
                            )
                        )
            elif child.name == "ip6-prefix-list":
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    child_values, child_extra = _evaluate_ipv6_child(entry, FGIPv6PrefixAdvertisement, prefix_spec)
                    prefixes.append(
                        FGIPv6PrefixAdvertisement(
                            prefix=entry.name,
                            extra_settings=sanitize_source_attributes(child_extra),
                            **child_values,
                        )
                    )
            elif child.name == "ip6-delegated-prefix-list":
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    child_values, child_extra = _evaluate_ipv6_child(entry, FGIPv6DelegatedPrefixAdvertisement, delegated_spec)
                    delegated.append(
                        FGIPv6DelegatedPrefixAdvertisement(
                            prefix_id=entry.name,
                            extra_settings=sanitize_source_attributes(child_extra),
                            **child_values,
                        )
                    )
            elif child.name == "dhcp6-iapd-list":
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    child_values, child_extra = _evaluate_ipv6_child(entry, FGDHCPv6IAPD, iapd_spec)
                    try:
                        iaid: Optional[int] = int(entry.name)
                    except (TypeError, ValueError):
                        iaid = None
                        child_extra["unparsed_iaid"] = entry.name
                    iapd.append(
                        FGDHCPv6IAPD(
                            source_iaid=entry.name,
                            iaid=iaid,
                            extra_settings=sanitize_source_attributes(child_extra),
                            **child_values,
                        )
                    )
            elif child.name == "vrrp6":
                for entry in child.children:
                    if entry.node_type != "edit":
                        continue
                    child_values, child_extra = _evaluate_ipv6_child(entry, FGInterfaceVRRP6, vrrp6_spec)
                    try:
                        vrid: Optional[int] = int(entry.name)
                    except (TypeError, ValueError):
                        vrid = None
                        child_extra["unparsed_vrid"] = entry.name
                    vrrp6.append(
                        FGInterfaceVRRP6(
                            source_vrid=entry.name,
                            vrid=vrid,
                            extra_settings=sanitize_source_attributes(child_extra),
                            **child_values,
                        )
                    )

        interface.ipv6_extra_addresses = extra_addresses
        interface.ipv6_prefix_advertisements = prefixes
        interface.ipv6_delegated_prefix_advertisements = delegated
        interface.dhcp6_iapd = iapd
        interface.vrrp6 = vrrp6


def _install_ipv6_inventory_classifier(extractor_module: Any) -> None:
    def is_typed_ipv6_interface_inventory(item: Any) -> bool:
        if "interface-nested-config" not in item.notes:
            return False
        if not item.source_path.endswith(" interface ipv6"):
            return False
        if not all(
            command.operation in {"set", "append", "unset"}
            and str(command.key).replace("_", "-").lower()
            in extractor_module.INTERFACE_IPV6_TYPED_COMMANDS
            for command in item.commands
        ):
            return False

        def valid_child(node: Any, section_name: Optional[str] = None) -> bool:
            current_section = section_name
            if node.source_path != item.source_path:
                suffix = node.source_path[len(item.source_path):].strip()
                if suffix:
                    current_section = suffix.split()[0]
            if current_section and current_section not in IPV6_TYPED_CHILDREN:
                return False
            allowed_fields = IPV6_CHILD_FIELDS.get(current_section, set())
            for command in node.commands:
                key = str(command.key).replace("_", "-").lower()
                if command.operation not in {"set", "append", "unset"}:
                    return False
                if current_section and key not in allowed_fields:
                    return False
            return all(valid_child(child, current_section) for child in node.children)

        return all(valid_child(child) for child in item.children)

    extractor_module._is_typed_ipv6_interface_inventory = is_typed_ipv6_interface_inventory

    original_extract = extractor_module.extract_fortigate_config
    if getattr(original_extract, "_phase_49_wrapped", False):
        return

    def extract_fortigate_config(*args: Any, **kwargs: Any) -> Any:
        result = original_extract(*args, **kwargs)
        for inventory in result.inventory_items:
            if is_typed_ipv6_interface_inventory(inventory):
                inventory.requires_manual_review = bool(
                    inventory.notes and any(
                        note.startswith("unresolved-reference:")
                        or note.startswith("incompatible-")
                        for note in inventory.notes
                    )
                )
        result.requires_manual_review = bool(result.blocking_reasons) or any(
            item.requires_manual_review for item in result.inventory_items
        )
        result.canonical_ir.requires_manual_review = result.requires_manual_review
        return result

    extract_fortigate_config._phase_49_wrapped = True
    extractor_module.extract_fortigate_config = extract_fortigate_config


# ---------------------------------------------------------------------------
# Phase 50 - IPv6 firewall-policy family classification
# ---------------------------------------------------------------------------


def _enabled_reference(value: Any) -> bool:
    if isinstance(value, str):
        return value.lower() not in {"", "disable", "none"}
    return bool(value)


def _refresh_policy_address_families(config: Any) -> None:
    for policy in config.policies:
        has_ipv4 = bool(policy.srcaddr or policy.dstaddr) or any(
            _enabled_reference(getattr(policy, field, None))
            for field in ("internet_service", "internet_service_src")
        )
        has_ipv6 = bool(policy.srcaddr6 or policy.dstaddr6) or any(
            _enabled_reference(getattr(policy, field, None))
            for field in ("internet_service6", "internet_service6_src")
        )
        if has_ipv4 and has_ipv6:
            policy.address_family = "dual-stack"
        elif has_ipv6:
            policy.address_family = "ipv6"
        else:
            policy.address_family = "ipv4"


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------


def install_phase_46_50_extensions(
    parser_module: Any,
    dependencies_module: Any,
    extractor_module: Any,
    source_tree_module: Any,
) -> None:
    """Install phases 46-50 after the Phase 41/42 wrappers."""

    # Route IPS through the recursive source-tree path so the shared evaluator
    # sees every set/append/unset operation in source order.
    source_tree_module.STRUCTURED_SECURITY_SECTIONS.add("ips sensor")
    parser_module.STRUCTURED_SECURITY_SECTIONS.add("ips sensor")

    _install_profile_group_dependencies(dependencies_module)
    _install_ipv6_inventory_classifier(extractor_module)

    parser_cls = parser_module.FortiGateParser
    current_build = parser_cls._build_structured_typed_parents
    if not getattr(current_build, "_phase_46_50_wrapped", False):
        def build_structured_typed_parents(
            self: Any,
            source_path: str,
            top_edits: List[FGSourceNode],
        ) -> None:
            if source_path == "ips sensor":
                _build_ips_sensor(self, top_edits)
                return
            if source_path == "firewall ssl-ssh-profile":
                _build_ssl_ssh_profile(self, top_edits)
                return
            if source_path == "firewall profile-group":
                _build_profile_groups(self, top_edits)
                return
            current_build(self, source_path, top_edits)

        build_structured_typed_parents._phase_46_50_wrapped = True
        parser_cls._build_structured_typed_parents = build_structured_typed_parents

    current_parse = parser_cls.parse
    if not getattr(current_parse, "_phase_46_50_wrapped", False):
        def parse(self: Any) -> Any:
            config = current_parse(self)
            _refresh_interface_ipv6_from_source(config, parser_module)
            _refresh_policy_address_families(config)
            return config

        parse._phase_46_50_wrapped = True
        parser_cls.parse = parse

    # Expose exact hierarchy constants for tests and later phases.
    parser_module.SSL_PROTOCOL_SECTIONS = SSL_PROTOCOL_SECTIONS
    parser_module.SSL_EXEMPTION_SECTIONS = SSL_EXEMPTION_SECTIONS
    parser_module.SSL_SERVER_SECTIONS = SSL_SERVER_SECTIONS
    parser_module.PROFILE_GROUP_REFERENCE_RULES = PROFILE_GROUP_REFERENCE_RULES
