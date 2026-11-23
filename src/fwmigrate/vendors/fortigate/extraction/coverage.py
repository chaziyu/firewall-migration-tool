from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import BaseModel

from ..model.source import FGConfig
from .source_inventory import SourceObjectRecord


@dataclass(frozen=True, slots=True)
class TypedSourceSpec:
    source_path: str
    config_field: str
    nested_fields: tuple[str, ...] = ()
    parent_fields: tuple[str, ...] = ()
    object_field: str | None = "name"
    filter_field: str | None = None
    filter_value: Any = None


@dataclass(frozen=True, slots=True)
class TypedSourceObject:
    identity: tuple[str | None, str, str | None, tuple[str, ...]]
    model: BaseModel


TypedSourceIdentity = tuple[str | None, str, str | None, tuple[str, ...]]
TypedSourceInventory = dict[str, tuple[TypedSourceObject, ...]]
TypedSourceIdentityIndex = dict[TypedSourceIdentity, TypedSourceObject]


_SPECS = (
    TypedSourceSpec("firewall central-snat-map", "central_snat", object_field="policy_id"),
    TypedSourceSpec("system interface", "interfaces"),
    TypedSourceSpec("system session-helper", "session_helpers", object_field="id"),
    TypedSourceSpec("user nac-policy", "nac_policies"),
    TypedSourceSpec("firewall address6-template", "address6_templates"),
    TypedSourceSpec("firewall address6-template subnet-segment", "address6_templates", ("segments",), ("name",), "id"),
    TypedSourceSpec("firewall address6-template subnet-segment values", "address6_templates", ("segments", "values"), ("name", "id"), "name"),
    TypedSourceSpec("ips settings", "ips_settings", object_field=None),
    TypedSourceSpec("vpn kmip-server", "kmip_servers"),
    TypedSourceSpec("vpn kmip-server server-list", "kmip_servers", ("server_list",), ("name",), "id"),
    TypedSourceSpec("user krb-keytab", "kerberos_keytabs"),
    TypedSourceSpec("router setting", "router_settings", object_field=None),
    TypedSourceSpec("system sdn-proxy", "sdn_proxies"),
    TypedSourceSpec("firewall on-demand-sniffer", "on_demand_sniffers"),
    TypedSourceSpec("system affinity-interrupt", "affinity_interrupts", object_field="id"),
    TypedSourceSpec("system serial-port", "serial_ports"),
    TypedSourceSpec("firewall region", "firewall_regions", object_field="id"),
    TypedSourceSpec("firewall vendor-mac", "vendor_macs", object_field="id"),
    TypedSourceSpec("system interface secondaryip", "interfaces", ("secondary_ips",), ("name",), "id"),
    TypedSourceSpec("system zone", "zones"),
    TypedSourceSpec("system zone tagging", "zones", ("tagging",), ("name",)),
    TypedSourceSpec("firewall address", "addresses", filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("firewall address6", "addresses", filter_field="address_family", filter_value="ipv6"),
    TypedSourceSpec("firewall address tagging", "addresses", ("tagging",), ("name",), filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("firewall addrgrp", "address_groups", filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("firewall addrgrp6", "address_groups", filter_field="address_family", filter_value="ipv6"),
    TypedSourceSpec("firewall addrgrp tagging", "address_groups", ("tagging",), ("name",), filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("firewall wildcard-fqdn custom", "wildcard_fqdns"),
    TypedSourceSpec("firewall service category", "service_categories"),
    TypedSourceSpec("firewall service custom", "services"),
    TypedSourceSpec("firewall service group", "service_groups"),
    TypedSourceSpec("firewall schedule group", "schedule_groups"),
    TypedSourceSpec("firewall schedule onetime", "one_time_schedules"),
    TypedSourceSpec("firewall schedule recurring", "recurring_schedules"),
    TypedSourceSpec("firewall ippool", "ip_pools"),
    TypedSourceSpec("firewall ippool6", "ip_pools6"),
    TypedSourceSpec("firewall vip", "vips"),
    TypedSourceSpec("firewall vip6", "vips6"),
    TypedSourceSpec("firewall vip realservers", "vips", ("realservers",), ("name",), "id"),
    TypedSourceSpec("firewall vipgrp", "vip_groups"),
    TypedSourceSpec("firewall vipgrp6", "vip_groups6"),
    TypedSourceSpec("firewall policy", "policies", object_field="policy_id"),
    TypedSourceSpec("firewall security-policy", "security_policies", object_field="policy_id"),
    TypedSourceSpec("firewall profile-protocol-options", "protocol_options"),
    TypedSourceSpec("firewall shaper per-ip-shaper", "per_ip_shapers"),
    TypedSourceSpec("router static", "static_routes", object_field="seq_num"),
    TypedSourceSpec("router static6", "static_routes", object_field="seq_num"),
    TypedSourceSpec("vpn ipsec phase1-interface", "ipsec_phase1"),
    TypedSourceSpec("vpn ipsec phase1", "ipsec_policy_phase1"),
    TypedSourceSpec("vpn ipsec phase2-interface", "ipsec_phase2"),
    TypedSourceSpec("vpn ipsec phase2", "ipsec_policy_phase2"),
    TypedSourceSpec("system dhcp server", "dhcp_servers", object_field="id"),
    TypedSourceSpec("system dhcp server ip-range", "dhcp_servers", ("ip_ranges",), ("id",), "id"),
    TypedSourceSpec("system dhcp server exclude-range", "dhcp_servers", ("exclude_ranges",), ("id",), "id"),
    TypedSourceSpec("system dhcp server reserved-address", "dhcp_servers", ("reserved_addresses",), ("id",), "id"),
    TypedSourceSpec("system sdwan", "sdwans", object_field=None),
    TypedSourceSpec("system sdwan zone", "sdwans", ("zones",), object_field="name"),
    TypedSourceSpec("system sdwan members", "sdwans", ("members",), object_field="seq_num"),
    TypedSourceSpec("system sdwan health-check", "sdwans", ("health_checks",)),
    TypedSourceSpec("system sdwan service", "sdwans", ("services",), object_field="id"),
    TypedSourceSpec("vpn ssl settings", "ssl_vpn_settings", object_field=None),
    TypedSourceSpec("vpn ssl web realm", "ssl_vpn_realms", object_field="url_path"),
    TypedSourceSpec("vpn ssl client", "ssl_vpn_clients"),
    TypedSourceSpec("vpn ssl web user-bookmark", "ssl_vpn_user_bookmarks", object_field="owner_name"),
    TypedSourceSpec("vpn ssl web user-bookmark bookmarks", "ssl_vpn_user_bookmarks", ("bookmarks",), ("owner_name",), "name"),
    TypedSourceSpec("vpn ssl web user-bookmark bookmarks form-data", "ssl_vpn_user_bookmarks", ("bookmarks", "form_data"), ("owner_name", "name"), "name"),
    TypedSourceSpec("vpn ssl web user-group-bookmark", "ssl_vpn_user_group_bookmarks", object_field="owner_name"),
    TypedSourceSpec("vpn ssl web user-group-bookmark bookmarks", "ssl_vpn_user_group_bookmarks", ("bookmarks",), ("owner_name",), "name"),
    TypedSourceSpec("vpn ssl web user-group-bookmark bookmarks form-data", "ssl_vpn_user_group_bookmarks", ("bookmarks", "form_data"), ("owner_name", "name"), "name"),
    TypedSourceSpec("vpn ssl settings authentication-rule", "ssl_vpn_settings", ("authentication_rules",), object_field="id"),
    TypedSourceSpec("vpn ssl web portal", "ssl_vpn_portals"),
    TypedSourceSpec("vpn ssl web host-check-software", "ssl_vpn_host_check_software"),
    TypedSourceSpec("vpn ssl web host-check-software check-item-list", "ssl_vpn_host_check_software", ("check_items",), ("name",), "id"),
    TypedSourceSpec("user local", "local_users"),
    TypedSourceSpec("user group", "user_groups"),
    TypedSourceSpec("user group match", "user_groups", ("matches",), ("name",), "id"),
    TypedSourceSpec("user group guest", "user_groups", ("guests",), ("name",), "id"),
    TypedSourceSpec("system admin", "administrators"),
    TypedSourceSpec("system accprofile", "admin_profiles"),
    TypedSourceSpec("system accprofile fwgrp-permission", "admin_profiles", ("firewall_permission",), ("name",), None),
    TypedSourceSpec("system accprofile loggrp-permission", "admin_profiles", ("log_permission",), ("name",), None),
    TypedSourceSpec("system accprofile netgrp-permission", "admin_profiles", ("network_permission",), ("name",), None),
    TypedSourceSpec("system accprofile sysgrp-permission", "admin_profiles", ("system_permission",), ("name",), None),
    TypedSourceSpec("system accprofile utmgrp-permission", "admin_profiles", ("utm_permission",), ("name",), None),
    TypedSourceSpec("ips sensor", "ips_sensors"),
    TypedSourceSpec("ips sensor entries", "ips_sensors", ("entries",), ("name",), "id"),
    TypedSourceSpec("ips sensor entries exempt-ip", "ips_sensors", ("entries", "exempt_ips"), ("name", "id"), "id"),
    TypedSourceSpec("firewall profile-group", "profile_groups"),
    TypedSourceSpec("system external-resource", "external_resources"),
    TypedSourceSpec("system ha", "ha_config", object_field=None),
    TypedSourceSpec("system ha ha-mgmt-interfaces", "ha_config", ("ha_mgmt_interfaces",), (), "id"),
    TypedSourceSpec("system snmp sysinfo", "snmp_sysinfo", object_field=None),
    TypedSourceSpec("system snmp community", "snmp_communities", object_field="id"),
    TypedSourceSpec("system snmp community hosts", "snmp_communities", ("hosts",), ("id",), "id"),
    TypedSourceSpec("system snmp user", "snmp_users"),
    TypedSourceSpec("system fortiguard", "fortiguard", object_field=None),
    TypedSourceSpec("router bgp", "router_bgp", object_field=None),
    TypedSourceSpec("router bgp neighbor", "router_bgp", ("neighbors",), (), "ip"),
    TypedSourceSpec("router bgp neighbor-group", "router_bgp", ("neighbor_groups",), (), "ip"),
    TypedSourceSpec("router bgp network", "router_bgp", ("networks",), (), "id"),
    TypedSourceSpec("router bgp network6", "router_bgp", ("networks6",), (), "id"),
    TypedSourceSpec("router bgp redistribute", "router_bgp", ("redistribute",), (), "name"),
    TypedSourceSpec("router bgp redistribute6", "router_bgp", ("redistribute6",), (), "name"),
    TypedSourceSpec("router ospf", "router_ospf", object_field=None),
    TypedSourceSpec("router ospf area", "router_ospf", ("areas",), (), "id"),
    TypedSourceSpec("router ospf ospf-interface", "router_ospf", ("ospf_interfaces",), (), "name"),
    TypedSourceSpec("router ospf network", "router_ospf", ("networks",), (), "id"),
    TypedSourceSpec("router ospf redistribute", "router_ospf", ("redistribute",), (), "name"),
    TypedSourceSpec("router ospf6", "router_ospf6", object_field=None),
    TypedSourceSpec("router rip", "router_rip", object_field=None),
    TypedSourceSpec("router policy", "policy_routes", object_field="seq_num", filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("router policy6", "policy_routes", object_field="seq_num", filter_field="address_family", filter_value="ipv6"),
    TypedSourceSpec("router prefix-list", "prefix_lists", filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("router prefix-list rule", "prefix_lists", ("rules",), ("name",), "id", filter_field="address_family", filter_value="ipv4"),
    TypedSourceSpec("router prefix-list6", "prefix_lists", filter_field="address_family", filter_value="ipv6"),
    TypedSourceSpec("router prefix-list6 rule", "prefix_lists", ("rules",), ("name",), "id", filter_field="address_family", filter_value="ipv6"),
    TypedSourceSpec("router route-map", "route_maps"),
    TypedSourceSpec("router route-map rule", "route_maps", ("rules",), ("name",), "id"),
    TypedSourceSpec("router aspath-list", "aspath_lists"),
    TypedSourceSpec("router aspath-list rule", "aspath_lists", ("rules",), ("name",), "id"),
    TypedSourceSpec("router community-list", "community_lists"),
    TypedSourceSpec("router community-list rule", "community_lists", ("rules",), ("name",), "id"),
    TypedSourceSpec("router multicast", "router_multicast", object_field=None),
    TypedSourceSpec("router multicast interface", "router_multicast", ("interfaces",), (), "name"),
    TypedSourceSpec("system ipam", "system_ipam", object_field=None),
    TypedSourceSpec("extender-controller extender", "fortiextenders"),
    TypedSourceSpec("firewall proxy-policy", "proxy_policies", object_field="policy_id"),
    TypedSourceSpec("firewall auth-policy", "auth_policies", object_field="policy_id"),
    TypedSourceSpec("firewall shaper traffic-shaper", "traffic_shapers"),
    TypedSourceSpec("firewall ldb-monitor", "ldb_monitors"),
    TypedSourceSpec("antivirus profile", "antivirus_profiles"),
    TypedSourceSpec("webfilter profile", "webfilter_profiles"),
    TypedSourceSpec("webfilter profile ftgd-wf filters", "webfilter_profiles", ("ftgd_filters",), ("name",), "id"),
    TypedSourceSpec("webfilter urlfilter", "urlfilter_tables", object_field="id"),
    TypedSourceSpec("webfilter urlfilter entries", "urlfilter_tables", ("entries",), ("id",), "id"),
    TypedSourceSpec("webfilter ftgd-local-cat", "webfilter_local_categories"),
    TypedSourceSpec("webfilter ftgd-local-rating", "webfilter_local_ratings", object_field="url"),
    TypedSourceSpec("webfilter override", "webfilter_overrides", object_field="id"),
    TypedSourceSpec("dnsfilter profile", "dnsfilter_profiles"),
    TypedSourceSpec("dnsfilter profile ftgd-dns filters", "dnsfilter_profiles", ("ftgd_filters",), ("name",), "id"),
    TypedSourceSpec("application list", "application_lists"),
    TypedSourceSpec("application list entries", "application_lists", ("entries",), ("name",), "id"),
    TypedSourceSpec("file-filter profile", "file_filter_profiles"),
    TypedSourceSpec("file-filter profile rules", "file_filter_profiles", ("rules",), ("name",), "name"),
    TypedSourceSpec("emailfilter profile", "emailfilter_profiles"),
    TypedSourceSpec("voip profile", "voip_profiles"),
    TypedSourceSpec("waf profile", "waf_profiles"),
    TypedSourceSpec("firewall ssl-ssh-profile", "ssl_ssh_profiles"),
    TypedSourceSpec("user ldap", "ldap_servers"),
    TypedSourceSpec("user radius", "radius_servers"),
    TypedSourceSpec("user tacacs+", "tacacs_servers"),
    TypedSourceSpec("user fsso", "fsso_servers"),
    TypedSourceSpec("user fsso-polling", "fsso_pollings", object_field="id"),
    TypedSourceSpec("user fortitoken", "fortitokens", object_field="serial_number"),
    TypedSourceSpec("user setting", "user_settings", object_field=None),
    TypedSourceSpec("user password-policy", "password_policies"),
    TypedSourceSpec("wireless-controller vap", "wireless_vaps"),
    TypedSourceSpec("wireless-controller wtp", "wireless_wtps", object_field="wtp_id"),
    TypedSourceSpec("wireless-controller wtp-profile", "wtp_profiles"),
    TypedSourceSpec("wireless-controller wids-profile", "wids_profiles"),
    TypedSourceSpec("switch-controller managed-switch", "managed_switches", object_field="switch_id"),
    TypedSourceSpec("switch-controller managed-switch ports", "managed_switches", ("ports",), ("switch_id",), "port_name"),
    TypedSourceSpec("log syslogd setting", "syslog_settings", object_field=None, filter_field="syslog_name", filter_value="syslogd"),
    TypedSourceSpec("log syslogd2 setting", "syslog_settings", object_field=None, filter_field="syslog_name", filter_value="syslogd2"),
    TypedSourceSpec("log syslogd3 setting", "syslog_settings", object_field=None, filter_field="syslog_name", filter_value="syslogd3"),
    TypedSourceSpec("log syslogd4 setting", "syslog_settings", object_field=None, filter_field="syslog_name", filter_value="syslogd4"),
    TypedSourceSpec("log memory setting", "log_memory_settings", object_field=None),
    TypedSourceSpec("log disk setting", "log_disk_settings", object_field=None),
    TypedSourceSpec("log setting", "log_settings", object_field=None),
    TypedSourceSpec("log threat-weight", "log_threat_weights", object_field=None),
    TypedSourceSpec("user guest", "guest_users", object_field="id"),
    TypedSourceSpec("switch-controller port-policy", "switch_port_policies"),
    TypedSourceSpec("switch-controller lldp-profile", "switch_lldp_profiles"),
    TypedSourceSpec("switch-controller qos qos-policy", "switch_qos_policies"),
    TypedSourceSpec("switch-controller vlan-policy", "switch_vlan_policies"),
)

_SPEC_BY_PATH = {spec.source_path: spec for spec in _SPECS}


def typed_source_paths() -> frozenset[str]:
    return frozenset(_SPEC_BY_PATH)


def supports_path(source_path: str) -> bool:
    return source_path in _SPEC_BY_PATH


def build_typed_source_inventory(config: FGConfig) -> TypedSourceInventory:
    inventory: TypedSourceInventory = {}
    for spec in _SPECS:
        roots = getattr(config, spec.config_field)
        found: list[TypedSourceObject] = []
        for root in roots:
            if spec.filter_field and getattr(root, spec.filter_field) != spec.filter_value:
                continue
            root_vdom = getattr(root, "cli_vdom", getattr(root, "vdom", "root"))
            models = [(root, ())]
            for index, field in enumerate(spec.nested_fields):
                children = []
                parent_field = spec.parent_fields[index] if index < len(spec.parent_fields) else None
                for parent, ancestors in models:
                    parents = ancestors
                    if parent_field:
                        parent_name = _source_id(parent, parent_field)
                        if parent_name is not None:
                            parents = (*parents, parent_name)
                    value = getattr(parent, field)
                    children.extend((item, parents) for item in (value if isinstance(value, list) else [value]) if item is not None)
                models = children
            for model, parents in models:
                object_name = _source_id(model, spec.object_field) if spec.object_field else None
                identity = (getattr(model, "cli_vdom", getattr(model, "vdom", root_vdom)), spec.source_path, object_name, parents)
                found.append(TypedSourceObject(identity, model))
        inventory[spec.source_path] = tuple(found)
    return inventory


def _source_id(model: BaseModel, field: str) -> str | None:
    value = getattr(model, field, None)
    if value is None:
        extra = getattr(model, "raw_extra", {})
        value = extra.get(f"unparsed_{field}")
    return None if value is None else str(value)


def find_typed_source_object(
    identity_index: Mapping[TypedSourceIdentity, TypedSourceObject],
    record: SourceObjectRecord,
) -> TypedSourceObject | None:
    identity = (record.vdom, record.source_path, record.object_name, record.parent_objects)
    found = identity_index.get(identity)
    if found is None and record.cli_scope == "global":
        global_object = identity_index.get(("root", *identity[1:]))
        if global_object is not None and not hasattr(global_object.model, "vdom") and not hasattr(global_object.model, "cli_vdom"):
            return global_object
    return found


def build_typed_source_identity_index(
    inventory: Mapping[str, tuple[TypedSourceObject, ...]],
) -> TypedSourceIdentityIndex:
    identity_index: TypedSourceIdentityIndex = {}
    for typed_objects in inventory.values():
        for typed_object in typed_objects:
            # Preserve the previous linear lookup's first-match behavior.
            identity_index.setdefault(typed_object.identity, typed_object)
    return identity_index


def extraction_status(
    typed_supported: bool, typed_object: TypedSourceObject | None,
    record: SourceObjectRecord | None = None,
) -> str:
    if record is not None and record.object_name is None and not record.commands:
        return "EMPTY_SECTION"
    if typed_object is None:
        return "MODEL_GAP" if typed_supported else "SOURCE_ONLY"
    return "TYPED_WITH_RAW_EXTRA" if getattr(typed_object.model, "raw_extra", {}) else "TYPED"
