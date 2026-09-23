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
    allowed_scope_kinds: frozenset[str] = frozenset()

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
    if match is None:
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
_spec("service_group", ("service-group", "entry"), scalar=("description",), members=("members", "tag"), field_map={"tag": "tags"})
_spec("security_profile_group", ("profile-group", "entry"), members=("virus", "spyware", "vulnerability", "url-filtering", "file-blocking", "wildfire-analysis", "data-filtering", "gtp", "sctp", "ai-security"), scalar=("disable-override",), field_map={"virus": "antivirus", "spyware": "anti_spyware", "url-filtering": "url_filtering", "file-blocking": "file_blocking", "wildfire-analysis": "wildfire_analysis", "data-filtering": "data_filtering", "disable-override": "disable_override"})
_spec("schedule", ("schedule", "entry"), nested=("schedule-type", "schedule-type/recurring", "schedule-type/recurring/daily", "schedule-type/recurring/weekly", "schedule-type/non-recurring"), field_map={"schedule-type": "recurring"})
_spec("security_rule", ("security", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "application", "service", "category", "source-hip", "destination-hip", "tag", "saas-user-list", "saas-tenant-list"), scalar=("negate-source", "negate-destination", "schedule", "action", "rule-type", "description", "group-tag", "log-start", "log-end", "log-setting", "disabled", "disable-inspect", "disable-server-response-inspection"), nested=("profile-setting",), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "source-hip": "source_hip", "destination-hip": "destination_hip", "tag": "tags", "group-tag": "group_tag", "negate-source": "negate_source", "negate-destination": "negate_destination", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "rule-type": "rule_type", "disable-inspect": "disable_inspect", "disable-server-response-inspection": "disable_server_response_inspection", "saas-user-list": "saas_user_list", "saas-tenant-list": "saas_tenant_list", "profile-setting": "profile_setting"})
_spec("default_security_rule", ("default-security-rules", "rules", "entry"), members=("tag",), scalar=("action", "disabled", "log-start", "log-end", "log-setting", "description", "group-tag", "disable-server-response-inspection", "icmp-unreachable"), nested=("option", "profile-setting"), field_map={"tag": "tags", "group-tag": "group_tag", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "disable-server-response-inspection": "disable_server_response_inspection", "profile-setting": "profile_setting", "icmp-unreachable": "icmp_unreachable"})
_spec("nat_rule", ("nat", "rules", "entry"), members=("from", "to", "source", "destination"), scalar=("service", "disabled", "active-active-device-binding"), nested=("source-translation", "source-translation/dynamic-ip-and-port", "source-translation/static-ip", "destination-translation", "dynamic-destination-translation", "dynamic-destination-translation/distribution", "dynamic-destination-translation/dns-rewrite"), field_map={"from": "from_zones", "to": "to_zones", "active-active-device-binding": "active_active_device_binding", "source-translation": "source_translation", "destination-translation": "destination_translation", "dynamic-destination-translation": "dynamic_destination_translation"})
_spec("interface_import", ("import", "network", "interface"), members=("member",), field_map={"member": "interfaces"})
_spec("virtual_router_import", ("import", "network", "virtual-router"), members=("member",), field_map={"member": "virtual_routers"})
_spec("zone", ("zone", "entry"), scalar=("network-type", "zone-protection-profile", "packet-buffer-protection", "network-inspection", "pre-nat-user-identification", "pre-nat-device-identification", "pre-nat-source-policy-lookup", "pre-nat-source-ip-downstream", "log-setting", "user-identification", "device-identification"), members=("user-acl-include", "user-acl-exclude", "device-acl-include", "device-acl-exclude"), nested=("network",), field_map={"network-type": "network_type", "zone-protection-profile": "zone_protection_profile", "packet-buffer-protection": "packet_buffer_protection", "network-inspection": "network_inspection", "pre-nat-user-identification": "pre_nat_user_identification", "pre-nat-device-identification": "pre_nat_device_identification", "pre-nat-source-policy-lookup": "pre_nat_source_policy_lookup", "pre-nat-source-ip-downstream": "pre_nat_source_ip_downstream", "log-setting": "log_setting", "user-identification": "user_identification", "device-identification": "device_identification", "user-acl-include": "user_acl_include", "user-acl-exclude": "user_acl_exclude", "device-acl-include": "device_acl_include", "device-acl-exclude": "device_acl_exclude", "network": "members"})
_spec("interface_unit", ("units", "entry"), scalar=("tag", "interface-management-profile"), nested=("ip", "ipv6"), field_map={"interface-management-profile": "management_profile", "ip": "ipv4_addresses", "ipv6": "ipv6_addresses"})
for _family in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
    _spec(f"interface_{_family}", (_family, "entry"), scalar=("comment", "link-state", "speed", "duplex", "vlan", "lldp", "aggregate-group"), nested=("layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"), field_map={"link-state": "link_state", "lldp": "lldp_enable", "aggregate-group": "aggregate_group"})
_spec("ipsec_tunnel", ("ipsec", "entry"), scalar=("tunnel-interface", "ipsec-crypto-profile", "tunnel-monitor", "global-protect-satellite"), nested=("auto-key", "manual-key", "proxy-id"), field_map={"tunnel-interface": "tunnel_interface", "ipsec-crypto-profile": "ipsec_crypto_profile", "tunnel-monitor": "tunnel_monitor", "global-protect-satellite": "globalprotect_satellite"})
_spec("vulnerability_profile", ("vulnerability", "entry"), nested=("rules", "exceptions"))
_spec("administrator", ("administrators", "entry"), scalar=("role-type", "built-in-role", "custom-admin-role", "authentication-profile", "password"), field_map={"role-type": "role_type", "built-in-role": "built_in_role", "custom-admin-role": "custom_admin_role", "authentication-profile": "authentication_profile"})
_spec("admin_role", ("admin-role", "entry"), scalar=("role-scope",), nested=("permissions",), field_map={"role-scope": "role_scope"})
_spec("ike_gateway", ("ike", "gateway", "entry"), scalar=("local-interface", "local-ip", "peer-address-type", "peer-address", "ike-version", "ikev1-exchange-mode", "ikev1-crypto-profile", "ikev2-crypto-profile", "ikev2-require-cookie", "authentication-method", "local-id", "peer-id", "ikev1-dpd-enabled", "ikev1-dpd-interval", "ikev1-dpd-retry", "ikev2-dpd-enabled", "ikev2-dpd-interval", "nat-traversal", "nat-traversal-keepalive", "nat-traversal-udp-checksum", "passive-mode", "fragmentation"), nested=("authentication",))
_spec("ike_crypto_profile", ("ike-crypto-profile", "entry"), nested=("encryption", "authentication", "dh-group", "lifetime"))
_spec("ipsec_crypto_profile", ("ipsec-crypto-profile", "entry"), nested=("protocol", "esp", "ah", "dh-group", "lifetime"))
_spec("dhcp_server", ("dhcp", "entry"), scalar=("interface", "mode", "probe-ip", "lease-type", "lease-timeout", "inheritance-source", "gateway", "subnet-mask", "dns-primary", "dns-secondary", "pop3-server", "smtp-server", "dns-suffix"), nested=("wins", "ntp", "ip-pool", "reservations", "options"), field_map={"probe-ip": "probe_ip", "lease-type": "lease_type", "lease-timeout": "lease_timeout", "inheritance-source": "inheritance_source", "subnet-mask": "subnet_mask", "dns-primary": "dns_primary", "dns-secondary": "dns_secondary", "pop3-server": "pop3_server", "smtp-server": "smtp_server", "dns-suffix": "dns_suffix", "ip-pool": "ip_pools"})
_spec("dhcp_interface", ("dhcp", "interface", "entry"), scalar=("mode", "probe-ip", "lease-type", "lease-timeout", "inheritance-source", "gateway", "subnet-mask", "dns-primary", "dns-secondary", "pop3-server", "smtp-server", "dns-suffix"), nested=("wins", "ntp", "ip-pool", "reservations", "options"), field_map={"probe-ip": "probe_ip", "lease-type": "lease_type", "lease-timeout": "lease_timeout", "inheritance-source": "inheritance_source", "subnet-mask": "subnet_mask", "dns-primary": "dns_primary", "dns-secondary": "dns_secondary", "pop3-server": "pop3_server", "smtp-server": "smtp_server", "dns-suffix": "dns_suffix", "ip-pool": "ip_pools"})
_spec("sdwan_interface_profile", ("interface-profile", "entry"), scalar=("link-tag", "link-type", "vpn-data-tunnel-support", "maximum-download", "maximum-upload", "error-correction", "path-monitoring", "vpn-failover-metric", "probe-frequency", "probe-idle-time", "failback-hold-time", "comment"))
_spec("sdwan_path_quality_profile", ("path-quality-profile", "entry"), scalar=("latency-threshold", "latency-sensitivity", "packet-loss-threshold", "packet-loss-sensitivity", "jitter-threshold", "jitter-sensitivity"))
_spec("sdwan_traffic_distribution_profile", ("traffic-distribution-profile", "entry"), scalar=("distribution-mode",), nested=("link",))
_spec("sdwan_saas_quality_profile", ("saas-quality-profile", "entry"), scalar=("monitor-mode", "probe-configuration"), members=("target",), field_map={"monitor-mode": "monitor_mode", "probe-configuration": "probe_configuration", "target": "targets"})
_spec("sdwan_error_correction_profile", ("error-correction-profile", "entry"), scalar=("activation-threshold", "mode"))
_spec("sdwan_rule", ("sdwan", "rules", "entry"), members=("from", "to", "source", "source-user", "destination", "application", "service", "tag"), scalar=("path-quality-profile", "saas-quality-profile", "error-correction-profile", "traffic-distribution-profile", "nat-session-failover-action", "group-tag", "description", "disabled", "negate-source", "negate-destination"), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "tag": "tags", "path-quality-profile": "path_quality_profile", "saas-quality-profile": "saas_quality_profile", "error-correction-profile": "error_correction_profile", "traffic-distribution-profile": "traffic_distribution_profile", "nat-session-failover-action": "nat_session_failover_action", "group-tag": "group_tag", "negate-source": "negate_source", "negate-destination": "negate_destination"})
_spec("local_user", ("local-user", "entry"), scalar=("disabled", "password"))
_spec("local_user_database", ("user", "entry"), scalar=("disabled", "password"))
_spec("local_user_group", ("local-user-group", "entry"), members=("members",))
_spec("group_mapping", ("group-mapping", "entry"), scalar=("server-profile", "disabled", "ldap-serial-number-check", "use-modify-timestamp", "limited-group-search", "nested-group-level", "alternate-username-1", "alternate-username-2", "alternate-username-3", "last-modify-attribute"), members=("group-object-attributes", "group-member-attributes", "group-name-attributes", "user-object-attributes", "user-name-attributes", "user-email-attributes", "group-email-attributes", "container-object-attributes", "group-include-list"), field_map={"server-profile": "server_profile", "ldap-serial-number-check": "ldap_serial_number_check", "use-modify-timestamp": "use_modify_timestamp", "limited-group-search": "limited_group_search", "nested-group-level": "nested_group_level", "alternate-username-1": "alternate_username_1", "alternate-username-2": "alternate_username_2", "alternate-username-3": "alternate_username_3", "last-modify-attribute": "last_modify_attribute", "group-object-attributes": "group_object_attributes", "group-member-attributes": "group_member_attributes", "group-name-attributes": "group_name_attributes", "user-object-attributes": "user_object_attributes", "user-name-attributes": "user_name_attributes", "user-email-attributes": "user_email_attributes", "group-email-attributes": "group_email_attributes", "container-object-attributes": "container_object_attributes", "group-include-list": "group_include_list"})
_spec("globalprotect_portal", ("portal", "entry"), scalar=("ssl-tls-service-profile", "certificate-profile", "clientless-vpn-enabled"), nested=("client-config", "clientless-vpn"), field_map={"ssl-tls-service-profile": "ssl_tls_service_profile", "certificate-profile": "certificate_profile", "clientless-vpn-enabled": "clientless_vpn_enabled", "client-config": "client_configs", "clientless-vpn": "clientless_vpn"})
_spec("globalprotect_gateway", ("gateway", "entry"), scalar=("tunnel-mode", "local-interface", "local-address", "ip-address-family", "ssl-tls-service-profile", "certificate-profile"), nested=("client-authentication", "remote-user-tunnel"), field_map={"tunnel-mode": "tunnel_mode", "local-interface": "local_interface", "local-address": "local_address", "ip-address-family": "ip_address_family", "ssl-tls-service-profile": "ssl_tls_service_profile", "certificate-profile": "certificate_profile", "client-authentication": "client_authentication", "remote-user-tunnel": "remote_user_tunnels"})
_spec("virtual_router", ("virtual-router", "entry"), members=("interface",), nested=("static-routes", "protocol", "bgp", "ospf", "ospfv3", "rip", "redistribution-profile"), field_map={"interface": "interfaces", "static-routes": "static_routes", "bgp": "bgp", "ospf": "ospf", "ospfv3": "ospfv3", "rip": "rip", "redistribution-profile": "redistribution_profiles"})
_spec("logical_router", ("logical-router", "entry"), nested=("vrf",), field_map={"vrf": "vrfs"})
