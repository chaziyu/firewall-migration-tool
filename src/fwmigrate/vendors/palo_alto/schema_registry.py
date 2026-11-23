"""Declarative PAN-OS XML path and primitive source-field metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class PANPathSpec:
    name: str
    path_suffix: tuple[str, ...]
    scalar_fields: frozenset[str] = field(default_factory=frozenset)
    member_list_fields: frozenset[str] = field(default_factory=frozenset)
    entry_list_fields: frozenset[str] = field(default_factory=frozenset)
    nested_fields: frozenset[str] = field(default_factory=frozenset)
    field_map: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.path_suffix or any(not item for item in self.path_suffix):
            raise ValueError("PAN-OS path specs require a non-empty name and path suffix.")
        categories = (self.scalar_fields, self.member_list_fields, self.entry_list_fields, self.nested_fields)
        for left, right in ((categories[i], categories[j]) for i in range(4) for j in range(i + 1, 4)):
            overlap = left & right
            if overlap:
                raise ValueError(f"{self.name!r}: fields {sorted(overlap)!r} have incompatible categories")
        known = set().union(*categories)
        if set(self.field_map) - known:
            raise ValueError(f"{self.name!r}: field mappings must refer to registered fields")
        if any(not source or not target for source, target in self.field_map.items()):
            raise ValueError(f"{self.name!r}: field mappings cannot contain empty names")
        if len(set(self.field_map.values())) != len(self.field_map):
            raise ValueError(f"{self.name!r}: field mappings must have unique model targets")
        object.__setattr__(self, "field_map", MappingProxyType(dict(self.field_map)))


_REGISTRY: dict[str, PANPathSpec] = {}

# Structural containers that may legitimately appear before a registered
# vendor-object suffix. Unknown containers fail closed so a future PAN-OS
# subtree cannot be reinterpreted as a known object merely because it ends in
# a familiar tag sequence such as address/entry.
_STRUCTURAL_CONTEXT_SEGMENTS = frozenset({
    "config",
    "devices",
    "device",
    "entry",
    "shared",
    "vsys",
    "device-group",
    "template",
    "template-stack",
    "network",
    "deviceconfig",
    "user-id",
    "rulebase",
    "pre-rulebase",
    "post-rulebase",
    "crypto-profiles",
    "profiles",
    "server-profile",
    "log-settings",
    "threats",
    "mgt-config",
    "user-id-collector",
})


def _known_context_segments() -> frozenset[str]:
    suffix_segments = {
        segment
        for spec in _REGISTRY.values()
        for segment in spec.path_suffix
    }
    nested_segments = {
        segment
        for spec in _REGISTRY.values()
        for nested_path in spec.nested_fields
        for segment in nested_path.split("/")
        if segment and segment != "*"
    }
    return _STRUCTURAL_CONTEXT_SEGMENTS | frozenset(suffix_segments | nested_segments)


def _context_is_supported(path: tuple[str, ...], spec: PANPathSpec) -> bool:
    prefix_length = len(path) - len(spec.path_suffix)
    if prefix_length <= 0:
        return False
    prefix = path[:prefix_length]
    if prefix[0] != "config":
        return False
    known = _known_context_segments()
    return all(segment in known for segment in prefix)



def register_path(spec: PANPathSpec) -> None:
    if spec.name in _REGISTRY:
        raise ValueError(f"PAN-OS path already registered: {spec.name!r}")
    if any(item.path_suffix == spec.path_suffix for item in _REGISTRY.values()):
        raise ValueError(f"PAN-OS path suffix already registered: {spec.path_suffix!r}")
    _REGISTRY[spec.name] = spec


def get_path_spec(name: str) -> PANPathSpec | None:
    return _REGISTRY.get(name)


def match_path_spec(path: tuple[str, ...]) -> PANPathSpec | None:
    matches = [spec for spec in _REGISTRY.values() if path[-len(spec.path_suffix):] == spec.path_suffix]
    match = max(matches, key=lambda spec: len(spec.path_suffix), default=None)
    if match is None or not _context_is_supported(path, match):
        return None
    ancestors = [
        spec
        for end in range(1, len(path))
        for spec in _REGISTRY.values()
        if path[:end][-len(spec.path_suffix):] == spec.path_suffix
    ]
    if ancestors and not (
        match.name == "interface_unit"
        and any(spec.name.startswith("interface_") for spec in ancestors)
    ):
        return None
    return match


def registered_paths() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def _spec(name: str, suffix: tuple[str, ...], *, scalar=(), members=(), entries=(), nested=(), field_map=None) -> None:
    register_path(PANPathSpec(name, suffix, frozenset(scalar), frozenset(members), frozenset(entries), frozenset(nested), field_map or {}))


_spec("address", ("address", "entry"), scalar=("ip-netmask", "ip-range", "ip-wildcard", "fqdn", "description"), members=("tag",), field_map={"ip-netmask": "ip_netmask", "ip-range": "ip_range", "ip-wildcard": "ip_wildcard", "tag": "tags"})
_spec("tag", ("tag", "entry"), scalar=("color", "comments"))
_spec("address_group", ("address-group", "entry"), scalar=("description",), nested=("static", "dynamic"), members=("tag",), field_map={"static": "static_members", "dynamic": "dynamic_filter", "tag": "tags"})
_spec("service", ("service", "entry"), scalar=("description",), members=("tag",), nested=("protocol", "protocol/tcp", "protocol/udp", "protocol/*/port", "protocol/*/source-port", "protocol/*/override"), field_map={"tag": "tags"})
_spec("service_group", ("service-group", "entry"), scalar=("description", "disable-override"), members=("members", "tag"), field_map={"tag": "tags", "disable-override": "disable_override"})
_spec("security_profile_group", ("profile-group", "entry"), members=("virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering", "gtp", "sctp", "ai-security"), scalar=("disable-override",), field_map={"virus": "antivirus", "spyware": "anti_spyware", "url-filtering": "url_filtering", "file-blocking": "file_blocking", "wildfire-analysis": "wildfire_analysis", "data-filtering": "data_filtering", "disable-override": "disable_override"})
_spec("schedule", ("schedule", "entry"), nested=("schedule-type", "schedule-type/recurring", "schedule-type/recurring/daily", "schedule-type/recurring/weekly", "schedule-type/non-recurring"), field_map={"schedule-type": "recurring"})
_spec("security_rule", ("security", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "application", "service", "category", "source-hip", "destination-hip", "tag", "saas-user-list", "saas-tenant-list"), scalar=("negate-source", "negate-destination", "schedule", "action", "rule-type", "description", "group-tag", "log-start", "log-end", "log-setting", "disabled", "disable-inspect", "disable-server-response-inspection", "icmp-unreachable"), nested=("profile-setting",), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "source-hip": "source_hip", "destination-hip": "destination_hip", "tag": "tags", "group-tag": "group_tag", "negate-source": "negate_source", "negate-destination": "negate_destination", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "rule-type": "rule_type", "disable-inspect": "disable_inspect", "disable-server-response-inspection": "disable_server_response_inspection", "saas-user-list": "saas_user_list", "saas-tenant-list": "saas_tenant_list", "profile-setting": "profile_setting", "icmp-unreachable": "icmp_unreachable"})
_spec("default_security_rule", ("default-security-rules", "rules", "entry"), members=("tag",), scalar=("action", "disabled", "log-start", "log-end", "log-setting", "description", "group-tag", "disable-server-response-inspection", "icmp-unreachable"), nested=("option", "profile-setting"), field_map={"tag": "tags", "group-tag": "group_tag", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "disable-server-response-inspection": "disable_server_response_inspection", "profile-setting": "profile_setting", "icmp-unreachable": "icmp_unreachable"})
_spec("nat_rule", ("nat", "rules", "entry"), members=("from", "to", "source", "destination", "tag"), scalar=("service", "disabled", "active-active-device-binding", "nat-type", "to-interface", "description"), nested=("source-translation", "source-translation/dynamic-ip-and-port", "source-translation/persistent-dynamic-ip-and-port", "source-translation/dynamic-ip", "source-translation/static-ip", "destination-translation", "dynamic-destination-translation", "dynamic-destination-translation/distribution", "dynamic-destination-translation/dns-rewrite"), field_map={"from": "from_zones", "to": "to_zones", "tag": "tags", "nat-type": "nat_type", "to-interface": "to_interface", "active-active-device-binding": "active_active_device_binding", "source-translation": "source_translation", "destination-translation": "destination_translation", "dynamic-destination-translation": "dynamic_destination_translation"})
_spec("interface_import", ("import", "network", "interface"), members=("member",), field_map={"member": "interfaces"})
_spec("virtual_router_import", ("import", "network", "virtual-router"), members=("member",), field_map={"member": "virtual_routers"})
_spec("zone", ("zone", "entry"), scalar=("network-type", "zone-protection-profile", "packet-buffer-protection", "network-inspection", "pre-nat-user-identification", "pre-nat-device-identification", "pre-nat-source-policy-lookup", "pre-nat-source-ip-downstream", "log-setting", "user-identification", "device-identification", "enable-user-identification", "enable-device-identification"), members=("user-acl-include", "user-acl-exclude", "device-acl-include", "device-acl-exclude"), nested=("network", "user-acl", "device-acl"), field_map={"network-type": "network_type", "zone-protection-profile": "zone_protection_profile", "packet-buffer-protection": "packet_buffer_protection", "network-inspection": "network_inspection", "pre-nat-user-identification": "pre_nat_user_identification", "pre-nat-device-identification": "pre_nat_device_identification", "pre-nat-source-policy-lookup": "pre_nat_source_policy_lookup", "pre-nat-source-ip-downstream": "pre_nat_source_ip_downstream", "log-setting": "log_setting", "enable-user-identification": "user_identification", "enable-device-identification": "device_identification", "user-acl-include": "user_acl_include", "user-acl-exclude": "user_acl_exclude", "device-acl-include": "device_acl_include", "device-acl-exclude": "device_acl_exclude", "network": "members"})
_spec("interface_unit", ("units", "entry"), scalar=("tag", "interface-management-profile"), nested=("ip", "ipv6"), field_map={"interface-management-profile": "management_profile", "ip": "ipv4_addresses", "ipv6": "ipv6_addresses"})
_spec("management_profile", ("profiles", "interface-management-profile", "entry"),
      scalar=("ping", "https", "ssh", "snmp", "http", "telnet", "http-ocsp", "response-pages",
              "userid-service", "userid-syslog-listener-ssl", "userid-syslog-listener-udp"),
      nested=("permitted-ip",), field_map={"permitted-ip": "permitted_ips"})
for _family in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
    _spec(f"interface_{_family}", (_family, "entry"), scalar=("comment", "link-state", "speed", "duplex", "vlan", "lldp", "aggregate-group"), nested=("layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"), field_map={"link-state": "link_state", "lldp": "lldp_enable", "aggregate-group": "aggregate_group"})
_spec("ipsec_tunnel", ("ipsec", "entry"), scalar=("tunnel-interface", "ipsec-crypto-profile", "tunnel-monitor", "global-protect-satellite"), nested=("auto-key", "manual-key", "proxy-id"), field_map={"tunnel-interface": "tunnel_interface", "ipsec-crypto-profile": "ipsec_crypto_profile", "tunnel-monitor": "tunnel_monitor", "global-protect-satellite": "globalprotect_satellite"})
_spec("vulnerability_profile", ("profiles", "vulnerability", "entry"), nested=("rules", "exceptions", "threat-exception"), field_map={"threat-exception": "exceptions"})
_spec("administrator", ("administrators", "entry"), scalar=("role-type", "built-in-role", "custom-admin-role", "authentication-profile", "password"), field_map={"role-type": "role_type", "built-in-role": "built_in_role", "custom-admin-role": "custom_admin_role", "authentication-profile": "authentication_profile"})
_spec("administrator_mgt_config", ("mgt-config", "users", "entry"), scalar=("role-type", "built-in-role", "custom-admin-role", "authentication-profile", "password"), nested=("permissions",), field_map={"role-type": "role_type", "built-in-role": "built_in_role", "custom-admin-role": "custom_admin_role", "authentication-profile": "authentication_profile"})
_spec("admin_role", ("admin-role", "entry"), scalar=("role-scope",), nested=("permissions",), field_map={"role-scope": "role_scope"})
_spec("ike_gateway", ("ike", "gateway", "entry"), scalar=("local-interface", "local-ip", "peer-address-type", "peer-address", "ike-version", "ikev1-exchange-mode", "ikev1-crypto-profile", "ikev2-crypto-profile", "ikev2-require-cookie", "authentication-method", "ikev1-dpd-enabled", "ikev1-dpd-interval", "ikev1-dpd-retry", "ikev2-dpd-enabled", "ikev2-dpd-interval", "nat-traversal", "nat-traversal-keepalive", "nat-traversal-udp-checksum", "passive-mode", "fragmentation"), nested=("authentication", "local-id", "peer-id"))
_spec("ike_crypto_profile", ("ike-crypto-profiles", "entry"), nested=("encryption", "authentication", "dh-group", "lifetime"))
_spec("ipsec_crypto_profile", ("ipsec-crypto-profiles", "entry"), nested=("protocol", "esp", "ah", "dh-group", "lifetime"))
_spec("dhcp_server", ("dhcp", "entry"), scalar=("interface", "mode", "probe-ip", "lease-type", "lease-timeout", "inheritance-source", "gateway", "subnet-mask", "dns-primary", "dns-secondary", "pop3-server", "smtp-server", "dns-suffix"), nested=("wins", "ntp", "ip-pool", "reservations", "options", "relay"), field_map={"probe-ip": "probe_ip", "lease-type": "lease_type", "lease-timeout": "lease_timeout", "inheritance-source": "inheritance_source", "subnet-mask": "subnet_mask", "dns-primary": "dns_primary", "dns-secondary": "dns_secondary", "pop3-server": "pop3_server", "smtp-server": "smtp_server", "dns-suffix": "dns_suffix", "ip-pool": "ip_pools"})
_spec("dhcp_interface", ("dhcp", "interface", "entry"), scalar=("mode", "probe-ip", "lease-type", "lease-timeout", "inheritance-source", "gateway", "subnet-mask", "dns-primary", "dns-secondary", "pop3-server", "smtp-server", "dns-suffix"), nested=("server", "wins", "ntp", "ip-pool", "reservations", "options", "relay"), field_map={"probe-ip": "probe_ip", "lease-type": "lease_type", "lease-timeout": "lease_timeout", "inheritance-source": "inheritance_source", "subnet-mask": "subnet_mask", "dns-primary": "dns_primary", "dns-secondary": "dns_secondary", "pop3-server": "pop3_server", "smtp-server": "smtp_server", "dns-suffix": "dns_suffix", "ip-pool": "ip_pools"})
_spec("sdwan_interface_profile", ("interface-profile", "entry"), scalar=("link-tag", "link-type", "vpn-data-tunnel-support", "maximum-download", "maximum-upload", "error-correction", "path-monitoring", "vpn-failover-metric", "probe-frequency", "probe-idle-time", "failback-hold-time", "comment"))
_spec("sdwan_path_quality_profile", ("path-quality-profile", "entry"), scalar=("latency-threshold", "latency-sensitivity", "packet-loss-threshold", "packet-loss-sensitivity", "jitter-threshold", "jitter-sensitivity"))
_spec("sdwan_traffic_distribution_profile", ("traffic-distribution-profile", "entry"), scalar=("distribution-mode",), nested=("link",))
_spec("sdwan_saas_quality_profile", ("saas-quality-profile", "entry"), scalar=("monitor-mode", "probe-configuration"), members=("target",), field_map={"monitor-mode": "monitor_mode", "probe-configuration": "probe_configuration", "target": "targets"})
_spec("sdwan_error_correction_profile", ("error-correction-profile", "entry"), scalar=("activation-threshold", "mode"))
_spec("sdwan_interface_profile_cli", ("sdwan-interface-profile", "entry"), scalar=("link-tag", "link-type", "vpn-data-tunnel-support", "maximum-download", "maximum-upload", "error-correction", "path-monitoring", "vpn-failover-metric", "probe-frequency", "probe-idle-time", "failback-hold-time", "comment"))
_spec("sdwan_path_quality_profile_cli", ("sdwan-path-quality", "entry"), nested=("metric",))
_spec("sdwan_traffic_distribution_profile_cli", ("sdwan-traffic-distribution", "entry"), scalar=("traffic-distribution",), nested=("link-tags",))
_spec("sdwan_saas_quality_profile_cli", ("sdwan-saas-quality", "entry"), nested=("monitor-mode",))
_spec("sdwan_error_correction_profile_cli", ("sdwan-error-correction", "entry"), scalar=("activation-threshold",), nested=("mode",))
_spec("sdwan_rule", ("sdwan", "rules", "entry"), members=("from", "to", "source", "source-user", "destination", "application", "service", "tag"), scalar=("path-quality-profile", "saas-quality-profile", "error-correction-profile", "traffic-distribution-profile", "nat-session-failover-action", "group-tag", "description", "disabled", "negate-source", "negate-destination"), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "tag": "tags", "path-quality-profile": "path_quality_profile", "saas-quality-profile": "saas_quality_profile", "error-correction-profile": "error_correction_profile", "traffic-distribution-profile": "traffic_distribution_profile", "nat-session-failover-action": "nat_session_failover_action", "group-tag": "group_tag", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("local_user", ("local-user", "entry"), scalar=("disabled", "password"))
_spec("local_user_database", ("local-user-database", "user", "entry"), scalar=("disabled", "phash", "password"), field_map={"phash": "password_configured"})
_spec("local_user_group", ("local-user-database", "user-group", "entry"), members=("user",), field_map={"user": "members"})
_spec("local_user_group_compat", ("local-user-group", "entry"), members=("members",))
_spec("group_mapping", ("group-mapping", "entry"), scalar=("server-profile", "disabled", "use-ldap-for-serialno-check", "ldap-serial-number-check", "use-modify-timestamp", "limited-group-search", "nested-group-level", "alternate-user-name-1", "alternate-user-name-2", "alternate-user-name-3", "alternate-username-1", "alternate-username-2", "alternate-username-3", "last-modify-attr", "last-modify-attribute"), members=("group-object", "group-member", "group-name", "user-object", "user-name", "user-email", "group-email", "container-object", "group-include-list", "group-object-attributes", "group-member-attributes", "group-name-attributes", "user-object-attributes", "user-name-attributes", "user-email-attributes", "group-email-attributes", "container-object-attributes"), field_map={"server-profile": "server_profile", "use-ldap-for-serialno-check": "ldap_serial_number_check", "use-modify-timestamp": "use_modify_timestamp", "limited-group-search": "limited_group_search", "nested-group-level": "nested_group_level", "alternate-user-name-1": "alternate_username_1", "alternate-user-name-2": "alternate_username_2", "alternate-user-name-3": "alternate_username_3", "last-modify-attr": "last_modify_attribute", "group-object": "group_object_attributes", "group-member": "group_member_attributes", "group-name": "group_name_attributes", "user-object": "user_object_attributes", "user-name": "user_name_attributes", "user-email": "user_email_attributes", "group-email": "group_email_attributes", "container-object": "container_object_attributes", "group-include-list": "group_include_list"})
_spec("globalprotect_portal", ("global-protect", "portal", "entry"), scalar=("ssl-tls-service-profile", "certificate-profile", "clientless-vpn-enabled"), nested=("client-config", "clientless-vpn"), field_map={"ssl-tls-service-profile": "ssl_tls_service_profile", "certificate-profile": "certificate_profile", "clientless-vpn-enabled": "clientless_vpn_enabled", "client-config": "client_configs", "clientless-vpn": "clientless_vpn"})
_spec("globalprotect_gateway", ("global-protect", "gateway", "entry"), scalar=("tunnel-mode", "local-interface", "local-address", "ip-address-family", "ssl-tls-service-profile", "certificate-profile"), nested=("client-authentication", "remote-user-tunnel"), field_map={"tunnel-mode": "tunnel_mode", "local-interface": "local_interface", "local-address": "local_address", "ip-address-family": "ip_address_family", "ssl-tls-service-profile": "ssl_tls_service_profile", "certificate-profile": "certificate_profile", "client-authentication": "client_authentication", "remote-user-tunnel": "remote_user_tunnels"})
_spec("globalprotect_portal_selected", ("global-protect", "global-protect-portal", "entry"), scalar=("ssl-tls-service-profile", "certificate-profile", "clientless-vpn-enabled"), nested=("client-config", "clientless-vpn"), field_map={"ssl-tls-service-profile": "ssl_tls_service_profile", "certificate-profile": "certificate_profile", "clientless-vpn-enabled": "clientless_vpn_enabled", "client-config": "client_configs", "clientless-vpn": "clientless_vpn"})
_spec("globalprotect_gateway_selected", ("global-protect", "global-protect-gateway", "entry"), scalar=("tunnel-mode", "ssl-tls-service-profile", "certificate-profile"), nested=("local-address", "client-auth", "remote-user-tunnel-configs"), field_map={"tunnel-mode": "tunnel_mode", "ssl-tls-service-profile": "ssl_tls_service_profile", "certificate-profile": "certificate_profile", "client-auth": "client_authentication", "remote-user-tunnel-configs": "remote_user_tunnels"})
_spec("virtual_router", ("virtual-router", "entry"), members=("interface",), nested=("routing-table", "protocol", "bgp", "ospf", "ospfv3", "rip", "redistribution-profile", "ecmp", "admin-dists"), field_map={"interface": "interfaces", "bgp": "bgp", "ospf": "ospf", "ospfv3": "ospfv3", "rip": "rip", "redistribution-profile": "redistribution_profiles", "admin-dists": "admin_dists"})
_spec("logical_router", ("logical-router", "entry"), nested=("vrf",), field_map={"vrf": "vrfs"})

# System / Device Setup / HA
_spec("system_settings", ("deviceconfig", "system"), scalar=("hostname", "ip-address", "netmask", "default-gateway", "ipv6-address", "ipv6-default-gateway", "timezone", "domain", "update-server", "advanced-routing", "login-banner", "type"), nested=("dns-setting", "ntp-servers", "service", "route", "panorama", "snmp-setting", "permitted-ip"), field_map={"ip-address": "ip_address", "default-gateway": "default_gateway", "ipv6-address": "ipv6_address", "ipv6-default-gateway": "ipv6_default_gateway", "update-server": "update_server", "advanced-routing": "advanced_routing", "login-banner": "login_banner", "dns-setting": "dns_setting", "ntp-servers": "ntp_servers", "snmp-setting": "snmp_setting", "permitted-ip": "permitted_ip"})
_spec("ha_config", ("deviceconfig", "high-availability"), scalar=("enabled",), nested=("mode", "group", "interface", "election-option", "state-synchronization"), field_map={"election-option": "election_option", "state-synchronization": "state_synchronization"})
_spec("device_setup_setting", ("deviceconfig", "setting"), nested=("config", "management", "wildfire", "tcp", "session", "logging", "ctd", "application", "alarm", "user-id-collector"), field_map={"user-id-collector": "user_id_collector"})

# Extended Policy Families
_spec("qos_rule", ("qos", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "application", "service", "category", "tag"), scalar=("schedule", "class", "negate-source", "negate-destination", "disabled", "description"), nested=("dscp-marking",), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "tag": "tags", "class": "qos_class", "dscp-marking": "dscp_marking", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("pbf_rule", ("pbf", "rules", "entry"), members=("source", "destination", "source-user", "application", "service", "tag"), scalar=("schedule", "active-active-device-binding", "negate-source", "negate-destination", "disabled", "description"), nested=("from", "action", "enforce-symmetric-return"), field_map={"source-user": "source_user", "tag": "tags", "active-active-device-binding": "active_active_device_binding", "enforce-symmetric-return": "enforce_symmetric_return", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("decryption_rule", ("decryption", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "service", "category", "source-hip", "destination-hip", "tag"), scalar=("action", "profile", "log-setting", "negate-source", "negate-destination", "disabled", "description"), nested=("type",), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "source-hip": "source_hip", "destination-hip": "destination_hip", "tag": "tags", "log-setting": "log_setting", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("tunnel_inspect_rule", ("tunnel-inspect", "rules", "entry"), members=("from", "to", "source", "destination", "tag"), scalar=("tunnel-protocol", "action", "profile", "disabled", "description"), field_map={"from": "from_zones", "to": "to_zones", "tag": "tags", "tunnel-protocol": "tunnel_protocol"})
_spec("app_override_rule", ("application-override", "rules", "entry"), members=("from", "to", "source", "destination", "tag"), scalar=("protocol", "port", "application", "negate-source", "negate-destination", "disabled", "description"), field_map={"from": "from_zones", "to": "to_zones", "tag": "tags", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("authentication_rule", ("authentication", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "service", "category", "source-hip", "destination-hip", "tag"), scalar=("authentication-enforcement", "action", "timeout", "log-setting", "negate-source", "negate-destination", "disabled", "description"), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "source-hip": "source_hip", "destination-hip": "destination_hip", "tag": "tags", "authentication-enforcement": "authentication_enforcement", "log-setting": "log_setting", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("dos_rule", ("dos", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "service", "tag"), scalar=("schedule", "log-setting", "disabled", "description"), nested=("action", "protection"), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "tag": "tags", "log-setting": "log_setting"})

# Extended Objects & Security Profiles
_spec("application_group", ("application-group", "entry"), members=("members",), scalar=("disable-override",), field_map={"disable-override": "disable_override"})
_spec("region", ("region", "entry"), members=("address",), nested=("geo-location",), field_map={"address": "addresses", "geo-location": "geo_location"})
_spec("dynamic_user_group", ("dynamic-user-group", "entry"), scalar=("filter", "description"), members=("tag",), field_map={"tag": "tags"})
_spec("hip_object", ("hip-objects", "entry"), scalar=("description",), nested=("host-info", "network-info", "patch-management", "disk-backup", "disk-encryption", "mobile-device", "certificate"), field_map={"host-info": "host_info", "network-info": "network_info", "patch-management": "patch_management", "disk-backup": "disk_backup", "disk-encryption": "disk_encryption", "mobile-device": "mobile_device"})
_spec("hip_profile", ("hip-profiles", "entry"), scalar=("match", "description"))
_spec("external_list", ("external-list", "entry"), scalar=("description", "url", "certificate-profile", "username"), nested=("type", "recurring"), field_map={"certificate-profile": "certificate_profile"})
_spec("custom_url_category", ("custom-url-category", "entry"), members=("list",), scalar=("type", "description"), field_map={"list": "list_entries"})
_spec("data_pattern", ("data-patterns", "entry"), scalar=("description",), nested=("pattern-type",), field_map={"pattern-type": "pattern_type"})
_spec("custom_threat_vulnerability", ("threats", "vulnerability", "entry"), scalar=("threatname", "severity", "category", "comment"), nested=("default-action",), field_map={"default-action": "default_action"})
_spec("custom_threat_spyware", ("threats", "spyware", "entry"), scalar=("threatname", "severity", "category", "comment"), nested=("default-action",), field_map={"default-action": "default_action"})
_spec("antivirus_profile", ("profiles", "virus", "entry"), scalar=("description", "packet-capture"), nested=("decoder", "application", "threat-exception"), field_map={"packet-capture": "packet_capture", "decoder": "decoders", "application": "applications", "threat-exception": "threat_exceptions"})
_spec("anti_spyware_profile", ("profiles", "spyware", "entry"), scalar=("description", "cloud-inline-analysis"), nested=("botnet-domains", "rules", "threat-exception"), field_map={"cloud-inline-analysis": "cloud_inline_analysis", "botnet-domains": "botnet_domains", "threat-exception": "threat_exceptions"})
_spec("url_filtering_profile", ("profiles", "url-filtering", "entry"), scalar=("description", "log-http-hdr-xff", "log-http-hdr-user-agent", "log-http-hdr-referer", "safe-search-enforcement"), members=("allow", "alert", "block", "continue", "override"), nested=("credential-enforcement",), field_map={"continue": "continue_categories", "override": "override_categories", "credential-enforcement": "credential_enforcement", "log-http-hdr-xff": "log_http_hdr_xff", "log-http-hdr-user-agent": "log_http_hdr_user_agent", "log-http-hdr-referer": "log_http_hdr_referer", "safe-search-enforcement": "safe_search_enforcement"})
_spec("file_blocking_profile", ("profiles", "file-blocking", "entry"), scalar=("description",), nested=("rules",))
_spec("wildfire_profile", ("profiles", "wildfire-analysis", "entry"), scalar=("description",), nested=("rules",))
_spec("data_filtering_profile", ("profiles", "data-filtering", "entry"), scalar=("description", "data-capture"), nested=("rules",), field_map={"data-capture": "data_capture"})
_spec("dos_protection_profile", ("profiles", "dos-protection", "entry"), scalar=("description", "type"), nested=("flood", "resource"))
_spec("decryption_profile", ("profiles", "decryption", "entry"), nested=("ssl-forward-proxy", "ssl-inbound-proxy", "ssl-no-proxy", "ssl-protocol-settings", "ssh-proxy"), field_map={"ssl-forward-proxy": "ssl_forward_proxy", "ssl-inbound-proxy": "ssl_inbound_proxy", "ssl-no-proxy": "ssl_no_proxy", "ssl-protocol-settings": "ssl_protocol_settings", "ssh-proxy": "ssh_proxy"})
_spec("log_forwarding_profile", ("log-settings", "profiles", "entry"), scalar=("description", "enhanced-application-logging"), nested=("match-list",), field_map={"enhanced-application-logging": "enhanced_application_logging", "match-list": "match_list"})
_spec("authentication_profile", ("authentication-profile", "entry"), members=("allow-list",), scalar=("username-modifier", "user-domain"), nested=("method", "single-sign-on", "lockout", "multi-factor-auth"), field_map={"allow-list": "allow_list", "username-modifier": "username_modifier", "user-domain": "user_domain", "single-sign-on": "single_sign_on", "multi-factor-auth": "multi_factor_auth"})
_spec("authentication_sequence", ("authentication-sequence", "entry"), members=("authentication-profiles",), scalar=("use-domain-find-profile",), field_map={"authentication-profiles": "authentication_profiles", "use-domain-find-profile": "use_domain_find_profile"})

# Network Extensions
_spec("vlan", ("network", "vlan", "entry"), scalar=("virtual-interface",), members=("interface",), nested=("mac",), field_map={"virtual-interface": "virtual_interface", "interface": "interfaces"})
_spec("virtual_wire", ("network", "virtual-wire", "entry"), scalar=("interface1", "interface2", "tag-allowed"), nested=("link-state-pass-through", "multicast-firewalling"), field_map={"tag-allowed": "tag_allowed", "link-state-pass-through": "link_state_pass_through", "multicast-firewalling": "multicast_firewalling"})
_spec("gre_tunnel", ("tunnel", "gre", "entry"), scalar=("tunnel-interface", "ttl", "copy-tos", "disabled"), nested=("local-address", "peer-address", "keep-alive"), field_map={"tunnel-interface": "tunnel_interface", "local-address": "local_address", "peer-address": "peer_address", "copy-tos": "copy_tos", "keep-alive": "keep_alive"})
_spec("dns_proxy", ("network", "dns-proxy", "entry"), members=("interface",), nested=("default", "cache", "tcp-queries", "domain-servers"), field_map={"interface": "interfaces", "tcp-queries": "tcp_queries", "domain-servers": "domain_servers"})
_spec("qos_interface", ("network", "qos", "interface", "entry"), nested=("regular-traffic", "tunnel-traffic"), field_map={"regular-traffic": "regular_traffic", "tunnel-traffic": "tunnel_traffic"})
_spec("qos_profile", ("network", "qos", "profile", "entry"), nested=("class-bandwidth-type",), field_map={"class-bandwidth-type": "class_bandwidth_type"})
_spec("zone_protection_profile", ("network", "profiles", "zone-protection-profile", "entry"), scalar=("description", "discard-ip-spoof", "discard-strict-source-routing", "discard-loose-source-routing", "tcp-reject-non-syn", "asymmetric-path"), nested=("flood", "scan"), field_map={"discard-ip-spoof": "discard_ip_spoof", "discard-strict-source-routing": "discard_strict_source_routing", "discard-loose-source-routing": "discard_loose_source_routing", "tcp-reject-non-syn": "tcp_reject_non_syn", "asymmetric-path": "asymmetric_path"})
_spec("monitor_profile", ("network", "profiles", "monitor-profile", "entry"), scalar=("interval", "threshold", "action"))
_spec("lldp_profile", ("network", "profiles", "lldp-profile", "entry"), scalar=("mode", "snmp-syslog-notification"), nested=("option-tlvs",), field_map={"snmp-syslog-notification": "snmp_syslog_notification", "option-tlvs": "option_tlvs"})
_spec("bfd_profile", ("network", "profiles", "bfd-profile", "entry"), scalar=("mode", "min-tx-interval", "min-rx-interval", "multiplier", "detection-mode", "hold-time"), field_map={"min-tx-interval": "min_tx_interval", "min-rx-interval": "min_rx_interval", "detection-mode": "detection_mode", "hold-time": "hold_time"})
_spec("gp_clientless_app", ("global-protect", "clientless-apps", "entry"), scalar=("app-url", "description"), field_map={"app-url": "app_url"})
_spec("gp_clientless_app_group", ("global-protect", "clientless-app-groups", "entry"), members=("members",), scalar=("description",))
_spec("gp_mdm", ("global-protect", "mdm", "entry"), scalar=("server", "port", "description"))

# Device, Auth Server, Certificate & Log Server Profiles
_spec("radius_server_profile", ("server-profile", "radius", "entry"), scalar=("timeout", "retries"), nested=("protocol", "server"), field_map={"server": "servers"})
_spec("ldap_server_profile", ("server-profile", "ldap", "entry"), scalar=("ldap-type", "ssl", "verify-server-certificate", "base", "bind-dn", "bind-password", "bind-timelimit", "timelimit"), nested=("server",), field_map={"ldap-type": "ldap_type", "verify-server-certificate": "verify_server_certificate", "bind-dn": "bind_dn", "bind-password": "bind_password_configured", "bind-timelimit": "bind_timelimit", "server": "servers"})
_spec("tacplus_server_profile", ("server-profile", "tacplus", "entry"), scalar=("protocol", "timeout"), nested=("server",), field_map={"server": "servers"})
_spec("kerberos_server_profile", ("server-profile", "kerberos", "entry"), nested=("server",), field_map={"server": "servers"})
_spec("saml_idp_server_profile", ("server-profile", "saml-idp", "entry"), scalar=("entity-id", "sso-url", "slo-url", "sso-binding", "slo-binding", "certificate", "max-clock-skew"), field_map={"entity-id": "entity_id", "sso-url": "sso_url", "slo-url": "slo_url", "sso-binding": "sso_binding", "slo-binding": "slo_binding", "max-clock-skew": "max_clock_skew"})
_spec("mfa_server_profile", ("server-profile", "mfa", "entry"), scalar=("mfa-vendor-type",), nested=("mfa-config",), field_map={"mfa-vendor-type": "mfa_vendor_type", "mfa-config": "mfa_config"})
_spec("certificate", ("certificate", "entry"), scalar=("common-name", "algorithm", "ca", "expiry-epoch", "not-valid-before", "not-valid-after", "subject", "issuer", "public-key", "private-key"), field_map={"common-name": "common_name", "expiry-epoch": "expiry_epoch", "not-valid-before": "not_valid_before", "not-valid-after": "not_valid_after", "public-key": "public_key", "private-key": "private_key_configured"})
_spec("ssl_tls_service_profile", ("ssl-tls-service-profile", "entry"), scalar=("certificate",), nested=("protocol-settings",), field_map={"protocol-settings": "protocol_settings"})
_spec("syslog_server_profile", ("log-settings", "syslog", "entry"), nested=("server",), field_map={"server": "servers"})
_spec("email_server_profile", ("log-settings", "email", "entry"), nested=("server",), field_map={"server": "servers"})
_spec("snmptrap_server_profile", ("log-settings", "snmptrap", "entry"), nested=("version",))
_spec("http_server_profile", ("log-settings", "http", "entry"), scalar=("tag-registration",), nested=("server",), field_map={"tag-registration": "tag_registration", "server": "servers"})
_spec("netflow_server_profile", ("server-profile", "netflow", "entry"), scalar=("active-timeout", "export-pan-fields"), nested=("template-refresh-rate", "server"), field_map={"active-timeout": "active_timeout", "export-pan-fields": "export_pan_fields", "template-refresh-rate": "template_refresh_rate", "server": "servers"})
_spec("password_complexity", ("mgt-config", "password-complexity"), scalar=("enabled", "minimum-length", "minimum-uppercase-letters", "minimum-lowercase-letters", "minimum-numeric-letters", "minimum-special-characters", "block-username-inclusion", "new-password-differs-by-characters", "password-history-count"), field_map={"minimum-length": "minimum_length", "minimum-uppercase-letters": "minimum_uppercase_letters", "minimum-lowercase-letters": "minimum_lowercase_letters", "minimum-numeric-letters": "minimum_numeric_letters", "minimum-special-characters": "minimum_special_characters", "block-username-inclusion": "block_username_inclusion", "new-password-differs-by-characters": "new_password_differs_by_characters", "password-history-count": "password_history_count"})
_spec("password_profile", ("mgt-config", "password-profile", "entry"), scalar=("expiration-period", "expiration-warning-period", "post-expiration-grace-period", "post-expiration-admin-login-count"), field_map={"expiration-period": "expiration_period", "expiration-warning-period": "expiration_warning_period", "post-expiration-grace-period": "post_expiration_grace_period", "post-expiration-admin-login-count": "post_expiration_admin_login_count"})
_spec("user_id_agent", ("user-id-agent", "entry"), scalar=("host", "port", "disabled", "ntlm-auth", "ldap-proxy"), field_map={"ntlm-auth": "ntlm_auth", "ldap-proxy": "ldap_proxy"})
_spec("device_object_shared", ("shared", "devices", "entry"), scalar=("description", "source"), members=("tag",), field_map={"tag": "tags"})
_spec("device_object_vsys", ("vsys", "entry", "devices", "entry"), scalar=("description", "source"), members=("tag",), field_map={"tag": "tags"})
_spec("scp_server_profile", ("server-profile", "scp", "entry"), scalar=("hostname", "port", "username", "password", "protocol"), nested=("server",), field_map={"password": "password_configured", "server": "servers"})
_spec("ssh_server_profile", ("server-profile", "ssh", "entry"), scalar=("hostname", "port", "username", "password", "protocol"), nested=("server",), field_map={"password": "password_configured", "server": "servers"})
_spec("user_identification", ("vsys", "entry", "user-identification"))
_spec("user_id_collector", ("vsys", "entry", "user-id-collector"))
_spec("log_system_setting", ("log-settings", "system"), nested=("match-list",), field_map={"match-list": "match_list"})
_spec("log_config_setting", ("log-settings", "config"), nested=("match-list",), field_map={"match-list": "match_list"})
_spec("log_threat_setting", ("log-settings", "threat"), nested=("match-list",), field_map={"match-list": "match_list"})
_spec("log_traffic_setting", ("log-settings", "traffic"), nested=("match-list",), field_map={"match-list": "match_list"})
_spec("log_wildfire_setting", ("log-settings", "wildfire"), nested=("match-list",), field_map={"match-list": "match_list"})
_spec("log_userid_setting", ("log-settings", "userid"), nested=("match-list",), field_map={"match-list": "match_list"})
