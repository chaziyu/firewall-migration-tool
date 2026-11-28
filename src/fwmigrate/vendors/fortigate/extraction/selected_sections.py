from __future__ import annotations

from typing import Protocol

from ..model.selected_sections import (
    FGNACPolicy, FGAddress6Template, FGAddress6TemplateSegment, FGAddress6TemplateValue,
    FGIPSSettings, FGKMIPServer, FGKMIPServerEntry, FGKerberosKeytab, FGRouterSettings,
    FGSDNProxy, FGOnDemandSniffer, FGAffinityInterrupt, FGSerialPort,
    FGFirewallRegion, FGVendorMAC,
    FGSystemGlobal, FGSystemDNS, FGSystemNTP, FGNTPServerEntry,
    FGSystemHA, FGHAMgmtInterface,
    FGSNMPSysinfo, FGSNMPCommunity, FGSNMPCommunityHost, FGSNMPUser, FGFortiGuard,
    FGRouterBGP, FGBGPNeighbor, FGBGPNetwork, FGBGPRedistribute,
    FGRouterOSPF, FGOSPFArea, FGOSPFInterface, FGOSPFNetwork, FGOSPFRedistribute,
    FGRouterOSPF6, FGRouterRIP,
    FGPolicyRoute, FGPrefixList, FGPrefixListRule,
    FGRouteMap, FGRouteMapRule, FGASPathList, FGASPathListRule,
    FGCommunityList, FGCommunityListRule,
    FGRouterMulticast, FGMulticastInterface, FGSystemIPAM, FGFortiExtender,
    FGProxyPolicy, FGAuthPolicy, FGTrafficShaper, FGLDBMonitor,
    FGAntivirusProfile, FGAVProtocolConfig,
    FGWebFilterProfile, FGWebFilterFTGDFilter,
    FGURLFilterTable, FGURLFilterEntry,
    FGWebFilterLocalCategory, FGWebFilterLocalRating, FGWebFilterOverride,
    FGDNSFilterProfile, FGDNSFilterFTGDFilter,
    FGApplicationList, FGApplicationListEntry,
    FGFileFilterProfile, FGFileFilterRule,
    FGEmailFilterProfile, FGVoIPProfile, FGWAFProfile,
    FGSSLSSHProfile, FGSSLSSHProtocolConfig,
    FGLDAPServer, FGRADIUSServer, FGTACACSServer, FGFSSOServer, FGFSSOPolling,
    FGFortiToken, FGUserSetting, FGPasswordPolicy, FGSystemPasswordPolicy,
    FGWirelessVAP, FGWirelessWTP, FGWirelessWTPProfile, FGWirelessWTPProfilePlatform, FGWirelessWIDSProfile,
    FGManagedSwitch, FGManagedSwitchPort,
    FGSyslogSetting, FGLogMemorySetting, FGLogDiskSetting, FGLogSetting,
    FGLogThreatWeight, FGThreatWeightLevel, FGThreatWeightIPS,
    FGThreatWeightMalware, FGThreatWeightCategoryEntry,
    FGUserGuest, FGSwitchPortPolicy, FGSwitchLLDPProfile, FGSwitchQoSPolicy, FGSwitchVLANPolicy,
    FGCertificate, FGLocalInPolicy, FGFortiAnalyzerSetting, FGLogFortiGuardSetting,
    FGSystemStorage, FGSAMLServer,
)
from ..nodes import CommandNode
from .common import (
    evaluate_config, evaluate_edit, get_child_config,
    iter_section_configs, iter_section_edits, source_model_kwargs,
)
from .section_index import SectionIndex


class Config(Protocol):
    nac_policies: list[FGNACPolicy]
    address6_templates: list[FGAddress6Template]
    ips_settings: list[FGIPSSettings]
    kmip_servers: list[FGKMIPServer]
    kerberos_keytabs: list[FGKerberosKeytab]
    router_settings: list[FGRouterSettings]
    sdn_proxies: list[FGSDNProxy]
    on_demand_sniffers: list[FGOnDemandSniffer]
    affinity_interrupts: list[FGAffinityInterrupt]
    serial_ports: list[FGSerialPort]
    firewall_regions: list[FGFirewallRegion]
    vendor_macs: list[FGVendorMAC]


def extract_selected_sections(tree: SectionIndex, config: Config) -> None:
    _simple_edits(tree, config, "user nac-policy", "nac_policies", FGNACPolicy)
    _extract_nac_settings(tree, config)
    _extract_address6_templates(tree, config)
    _extract_config_settings(tree, config, "ips settings", "ips_settings", FGIPSSettings)
    _extract_kmip(tree, config)
    _extract_keytabs(tree, config)
    _extract_config_settings(tree, config, "router setting", "router_settings", FGRouterSettings)
    _extract_sdn_proxy(tree, config)
    _simple_edits(tree, config, "firewall on-demand-sniffer", "on_demand_sniffers", FGOnDemandSniffer)
    _simple_edits(tree, config, "system affinity-interrupt", "affinity_interrupts", FGAffinityInterrupt, numeric_id=True)
    _simple_edits(tree, config, "system serial-port", "serial_ports", FGSerialPort)
    _simple_edits(tree, config, "firewall region", "firewall_regions", FGFirewallRegion, numeric_id=True)
    _simple_edits(tree, config, "firewall vendor-mac", "vendor_macs", FGVendorMAC, numeric_id=True)

    # System / HA / SNMP / DNS / NTP / FortiGuard
    _extract_tuple_config_settings(tree, config, "system global", "system_global", FGSystemGlobal)
    _extract_tuple_config_settings(tree, config, "system dns", "system_dns", FGSystemDNS)
    _extract_system_ntp(tree, config)
    _extract_system_ha(tree, config)
    _extract_config_settings(tree, config, "system snmp sysinfo", "snmp_sysinfo", FGSNMPSysinfo)
    _extract_snmp_communities(tree, config)
    _extract_snmp_users(tree, config)
    _extract_config_settings(tree, config, "system fortiguard", "fortiguard", FGFortiGuard)

    # Dynamic Routing & Multicast
    _extract_router_bgp(tree, config)
    _extract_router_ospf(tree, config)
    _extract_config_settings(tree, config, "router ospf6", "router_ospf6", FGRouterOSPF6)
    _extract_config_settings(tree, config, "router rip", "router_rip", FGRouterRIP)
    _extract_policy_routes(tree, config, "router policy", "ipv4")
    _extract_policy_routes(tree, config, "router policy6", "ipv6")
    _extract_prefix_lists(tree, config, "router prefix-list", "ipv4")
    _extract_prefix_lists(tree, config, "router prefix-list6", "ipv6")
    _extract_route_maps(tree, config)
    _extract_aspath_lists(tree, config)
    _extract_community_lists(tree, config)
    _extract_router_multicast(tree, config)
    _extract_config_settings(tree, config, "system ipam", "system_ipam", FGSystemIPAM)
    _extract_fortiextenders(tree, config)

    # Extended Policies & Shapers
    _extract_numbered_policies(tree, config, "firewall proxy-policy", "proxy_policies", FGProxyPolicy)
    _extract_numbered_policies(tree, config, "firewall auth-policy", "auth_policies", FGAuthPolicy)
    _simple_edits(tree, config, "firewall shaper traffic-shaper", "traffic_shapers", FGTrafficShaper)
    _simple_edits(tree, config, "firewall ldb-monitor", "ldb_monitors", FGLDBMonitor)

    # Security Profiles
    _extract_antivirus_profiles(tree, config)
    _extract_webfilter_profiles(tree, config)
    _extract_urlfilter_tables(tree, config)
    _simple_edits(tree, config, "webfilter ftgd-local-cat", "webfilter_local_categories", FGWebFilterLocalCategory)
    _simple_edits(tree, config, "webfilter ftgd-local-rating", "webfilter_local_ratings", FGWebFilterLocalRating, id_field="url")
    _simple_edits(tree, config, "webfilter override", "webfilter_overrides", FGWebFilterOverride, numeric_id=True)
    _extract_dnsfilter_profiles(tree, config)
    _extract_application_lists(tree, config)
    _extract_file_filter_profiles(tree, config)
    _simple_edits(tree, config, "emailfilter profile", "emailfilter_profiles", FGEmailFilterProfile)
    _extract_voip_profiles(tree, config)
    _simple_edits(tree, config, "waf profile", "waf_profiles", FGWAFProfile)
    _extract_ssl_ssh_profiles(tree, config)

    # User & Auth Extensions
    _extract_ldap_servers(tree, config)
    _extract_radius_servers(tree, config)
    _extract_tacacs_servers(tree, config)
    _extract_fsso_servers(tree, config)
    _extract_fsso_pollings(tree, config)
    _extract_fortitokens(tree, config)
    _extract_config_settings(tree, config, "user setting", "user_settings", FGUserSetting)
    _simple_edits(tree, config, "user password-policy", "password_policies", FGPasswordPolicy)
    _extract_config_settings(tree, config, "system password-policy", "system_password_policies", FGSystemPasswordPolicy)

    # WiFi, Switch & Logging
    _extract_wireless_vaps(tree, config)
    _extract_wireless_wtps(tree, config)
    _extract_wtp_profiles(tree, config)
    _simple_edits(tree, config, "wireless-controller wids-profile", "wids_profiles", FGWirelessWIDSProfile)
    _extract_managed_switches(tree, config)
    for syslog_name, path in (
        ("syslogd", "log syslogd setting"),
        ("syslogd2", "log syslogd2 setting"),
        ("syslogd3", "log syslogd3 setting"),
        ("syslogd4", "log syslogd4 setting"),
    ):
        _extract_syslog_setting(tree, config, path, syslog_name)
    _extract_config_settings(tree, config, "log memory setting", "log_memory_settings", FGLogMemorySetting)
    _extract_log_disk_settings(tree, config)
    _extract_config_settings(tree, config, "log setting", "log_settings", FGLogSetting)
    _extract_log_threat_weight(tree, config)
    _extract_guest_users(tree, config)
    _simple_edits(tree, config, "switch-controller port-policy", "switch_port_policies", FGSwitchPortPolicy)
    _simple_edits(tree, config, "switch-controller lldp-profile", "switch_lldp_profiles", FGSwitchLLDPProfile)
    _simple_edits(tree, config, "switch-controller qos qos-policy", "switch_qos_policies", FGSwitchQoSPolicy)
    _simple_edits(tree, config, "switch-controller vlan-policy", "switch_vlan_policies", FGSwitchVLANPolicy)

    for store in ("local", "ca", "remote"):
        _extract_certificates(tree, config, store)
    _extract_local_in_policies(tree, config, "firewall local-in-policy", "ipv4")
    _extract_local_in_policies(tree, config, "firewall local-in-policy6", "ipv6")
    for target_name, path in (
        ("fortianalyzer", "log fortianalyzer setting"),
        ("fortianalyzer2", "log fortianalyzer2 setting"),
        ("fortianalyzer3", "log fortianalyzer3 setting"),
    ):
        _extract_fortianalyzer_setting(tree, config, path, target_name)
    _extract_config_settings(tree, config, "log fortiguard setting", "log_fortiguard_settings", FGLogFortiGuardSetting)
    _simple_edits(tree, config, "system storage", "system_storages", FGSystemStorage)
    _simple_edits(tree, config, "user saml", "saml_servers", FGSAMLServer)


def _assign_numeric_id(values, raw_name: str, field_name: str = "id") -> None:
    try:
        values[field_name] = int(raw_name)
    except ValueError:
        values[field_name] = None
        values["raw_extra"][f"unparsed_{field_name}"] = raw_name


def _simple_edits(tree, config, path, destination, model_type, *, numeric_id=False, id_field: str = "name", field_map=None):
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(
            evaluation, model_type=model_type,
            vdom=source.vdom if "vdom" in model_type.model_fields else None,
            field_map=field_map,
        )
        if numeric_id:
            _assign_numeric_id(values, source.edit.name, id_field if id_field != "name" else "id")
        elif id_field in model_type.model_fields:
            values[id_field] = source.edit.name
        getattr(config, destination).append(model_type(**values))


def _extract_config_settings(tree, config, path, destination, model_type, *, field_map=None):
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(
            evaluation, model_type=model_type,
            vdom=source.vdom if "vdom" in model_type.model_fields else None,
            field_map=field_map,
        )
        getattr(config, destination).append(model_type(**values))


def _extract_tuple_config_settings(tree, config, path, destination, model_type, *, field_map=None):
    items = list(getattr(config, destination, ()))
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(
            evaluation, model_type=model_type,
            vdom=source.vdom if "vdom" in model_type.model_fields else None,
            field_map=field_map,
        )
        items.append(model_type(**values))
    setattr(config, destination, tuple(items))


def _secret_present(node, key: str) -> bool:
    present = False
    for command in node.commands:
        if isinstance(command, CommandNode) and command.key == key:
            if command.operation.lower() in {"set", "append"}:
                present = True
            elif command.operation.lower() == "unset":
                present = False
    return present


def _extract_address6_templates(tree, config):
    path = "firewall address6-template"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGAddress6Template, name=source.edit.name, vdom=source.vdom)
        segments = get_child_config(source.edit, "subnet-segment")
        if segments is not None:
            values["segments"] = []
            for edit in segments.edits:
                segment_path = f"{path} subnet-segment"
                segment_eval = evaluate_edit(segment_path, edit)
                segment_values = source_model_kwargs(segment_eval, model_type=FGAddress6TemplateSegment)
                _assign_numeric_id(segment_values, edit.name)
                child = get_child_config(edit, "values")
                if child is not None:
                    segment_values["values"] = []
                    for value_edit in child.edits:
                        value_eval = evaluate_edit(f"{segment_path} values", value_edit)
                        value_attributes = source_model_kwargs(value_eval, model_type=FGAddress6TemplateValue, name=value_edit.name)
                        segment_values["values"].append(FGAddress6TemplateValue(**value_attributes))
                values["segments"].append(FGAddress6TemplateSegment(**segment_values))
        config.address6_templates.append(FGAddress6Template(**values))


def _extract_kmip(tree, config):
    path = "vpn kmip-server"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGKMIPServer, name=source.edit.name, vdom=source.vdom)
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        server_list = get_child_config(source.edit, "server-list")
        if server_list is not None:
            values["server_list"] = []
            for edit in server_list.edits:
                child_eval = evaluate_edit(f"{path} server-list", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGKMIPServerEntry)
                _assign_numeric_id(child_values, edit.name)
                values["server_list"].append(FGKMIPServerEntry(**child_values))
        config.kmip_servers.append(FGKMIPServer(**values))


def _extract_keytabs(tree, config):
    path = "user krb-keytab"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGKerberosKeytab, name=source.edit.name, vdom=source.vdom)
        values["keytab_configured"] = _secret_present(source.edit, "keytab")
        values["raw_extra"].pop("keytab", None)
        config.kerberos_keytabs.append(FGKerberosKeytab(**values))


def _extract_sdn_proxy(tree, config):
    path = "system sdn-proxy"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGSDNProxy, name=source.edit.name, vdom=source.vdom)
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        config.sdn_proxies.append(FGSDNProxy(**values))


def _extract_system_ntp(tree, config):
    path = "system ntp"
    items = list(getattr(config, "system_ntp", ()))
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGSystemNTP, vdom=source.vdom)
        values["key_configured"] = _secret_present(source.config, "key")
        values["raw_extra"].pop("key", None)
        ntpserver = get_child_config(source.config, "ntpserver")
        if ntpserver is not None:
            values["ntpservers"] = []
            for edit in ntpserver.edits:
                child_eval = evaluate_edit(f"{path} ntpserver", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGNTPServerEntry)
                _assign_numeric_id(child_values, edit.name)
                child_values["key_configured"] = _secret_present(edit, "key")
                child_values["raw_extra"].pop("key", None)
                values["ntpservers"].append(FGNTPServerEntry(**child_values))
        items.append(FGSystemNTP(**values))
    config.system_ntp = tuple(items)


def _extract_system_ha(tree, config):
    path = "system ha"
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGSystemHA, vdom=source.vdom)
        values["password_configured"] = _secret_present(source.config, "password")
        values["raw_extra"].pop("password", None)
        mgmt_interfaces = get_child_config(source.config, "ha-mgmt-interfaces")
        if mgmt_interfaces is not None:
            values["ha_mgmt_interfaces"] = []
            for edit in mgmt_interfaces.edits:
                child_eval = evaluate_edit(f"{path} ha-mgmt-interfaces", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGHAMgmtInterface)
                _assign_numeric_id(child_values, edit.name)
                values["ha_mgmt_interfaces"].append(FGHAMgmtInterface(**child_values))
        config.ha_config.append(FGSystemHA(**values))


def _extract_snmp_communities(tree, config):
    path = "system snmp community"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGSNMPCommunity, vdom=source.vdom)
        _assign_numeric_id(values, source.edit.name)
        values["community_configured"] = _secret_present(source.edit, "name")
        # Community name in SNMP v1/v2c acts as a shared secret, so redact raw name value
        values["name"] = None
        values["raw_extra"].pop("name", None)
        hosts = get_child_config(source.edit, "hosts")
        if hosts is not None:
            values["hosts"] = []
            for edit in hosts.edits:
                child_eval = evaluate_edit(f"{path} hosts", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGSNMPCommunityHost)
                _assign_numeric_id(child_values, edit.name)
                values["hosts"].append(FGSNMPCommunityHost(**child_values))
        config.snmp_communities.append(FGSNMPCommunity(**values))


def _extract_snmp_users(tree, config):
    path = "system snmp user"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGSNMPUser, name=source.edit.name, vdom=source.vdom)
        values["auth_pwd_configured"] = _secret_present(source.edit, "auth-pwd")
        values["priv_pwd_configured"] = _secret_present(source.edit, "priv-pwd")
        values["raw_extra"].pop("auth-pwd", None)
        values["raw_extra"].pop("priv-pwd", None)
        config.snmp_users.append(FGSNMPUser(**values))


def _extract_router_bgp(tree, config):
    path = "router bgp"
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(
            evaluation, model_type=FGRouterBGP, vdom=source.vdom,
            field_map={"as": "bgp_as"},
        )
        for child_name, field_name, sub_path in (
            ("neighbor", "neighbors", f"{path} neighbor"),
            ("neighbor-group", "neighbor_groups", f"{path} neighbor-group"),
        ):
            child = get_child_config(source.config, child_name)
            if child is not None:
                values[field_name] = []
                for edit in child.edits:
                    child_eval = evaluate_edit(sub_path, edit)
                    child_values = source_model_kwargs(child_eval, model_type=FGBGPNeighbor)
                    child_values["ip"] = edit.name
                    child_values["password_configured"] = _secret_present(edit, "password")
                    child_values["raw_extra"].pop("password", None)
                    values[field_name].append(FGBGPNeighbor(**child_values))
        for child_name, field_name, sub_path in (
            ("network", "networks", f"{path} network"),
            ("network6", "networks6", f"{path} network6"),
        ):
            child = get_child_config(source.config, child_name)
            if child is not None:
                values[field_name] = []
                for edit in child.edits:
                    child_eval = evaluate_edit(sub_path, edit)
                    child_values = source_model_kwargs(child_eval, model_type=FGBGPNetwork)
                    _assign_numeric_id(child_values, edit.name)
                    values[field_name].append(FGBGPNetwork(**child_values))
        for child_name, field_name, sub_path in (
            ("redistribute", "redistribute", f"{path} redistribute"),
            ("redistribute6", "redistribute6", f"{path} redistribute6"),
        ):
            child = get_child_config(source.config, child_name)
            if child is not None:
                values[field_name] = []
                for edit in child.edits:
                    child_eval = evaluate_edit(sub_path, edit)
                    child_values = source_model_kwargs(child_eval, model_type=FGBGPRedistribute, name=edit.name)
                    values[field_name].append(FGBGPRedistribute(**child_values))
        config.router_bgp.append(FGRouterBGP(**values))


def _extract_router_ospf(tree, config):
    path = "router ospf"
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGRouterOSPF, vdom=source.vdom)
        area_cfg = get_child_config(source.config, "area")
        if area_cfg is not None:
            values["areas"] = []
            for edit in area_cfg.edits:
                child_eval = evaluate_edit(f"{path} area", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGOSPFArea)
                child_values["id"] = edit.name
                values["areas"].append(FGOSPFArea(**child_values))
        intf_cfg = get_child_config(source.config, "ospf-interface")
        if intf_cfg is not None:
            values["ospf_interfaces"] = []
            for edit in intf_cfg.edits:
                child_eval = evaluate_edit(f"{path} ospf-interface", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGOSPFInterface, name=edit.name)
                child_values["auth_key_configured"] = _secret_present(edit, "authentication-key")
                child_values["raw_extra"].pop("authentication-key", None)
                values["ospf_interfaces"].append(FGOSPFInterface(**child_values))
        net_cfg = get_child_config(source.config, "network")
        if net_cfg is not None:
            values["networks"] = []
            for edit in net_cfg.edits:
                child_eval = evaluate_edit(f"{path} network", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGOSPFNetwork)
                _assign_numeric_id(child_values, edit.name)
                values["networks"].append(FGOSPFNetwork(**child_values))
        redist_cfg = get_child_config(source.config, "redistribute")
        if redist_cfg is not None:
            values["redistribute"] = []
            for edit in redist_cfg.edits:
                child_eval = evaluate_edit(f"{path} redistribute", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGOSPFRedistribute, name=edit.name)
                values["redistribute"].append(FGOSPFRedistribute(**child_values))
        config.router_ospf.append(FGRouterOSPF(**values))


def _extract_policy_routes(tree, config, path: str, address_family: str):
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGPolicyRoute, vdom=source.vdom)
        values["address_family"] = address_family
        _assign_numeric_id(values, source.edit.name, "seq_num")
        config.policy_routes.append(FGPolicyRoute(**values))


def _extract_prefix_lists(tree, config, path: str, address_family: str):
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGPrefixList, name=source.edit.name, vdom=source.vdom)
        values["address_family"] = address_family
        rule_cfg = get_child_config(source.edit, "rule")
        if rule_cfg is not None:
            values["rules"] = []
            for edit in rule_cfg.edits:
                child_eval = evaluate_edit(f"{path} rule", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGPrefixListRule)
                _assign_numeric_id(child_values, edit.name)
                values["rules"].append(FGPrefixListRule(**child_values))
        config.prefix_lists.append(FGPrefixList(**values))


def _extract_route_maps(tree, config):
    path = "router route-map"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGRouteMap, name=source.edit.name, vdom=source.vdom)
        rule_cfg = get_child_config(source.edit, "rule")
        if rule_cfg is not None:
            values["rules"] = []
            for edit in rule_cfg.edits:
                child_eval = evaluate_edit(f"{path} rule", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGRouteMapRule)
                _assign_numeric_id(child_values, edit.name)
                values["rules"].append(FGRouteMapRule(**child_values))
        config.route_maps.append(FGRouteMap(**values))


def _extract_aspath_lists(tree, config):
    path = "router aspath-list"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGASPathList, name=source.edit.name, vdom=source.vdom)
        rule_cfg = get_child_config(source.edit, "rule")
        if rule_cfg is not None:
            values["rules"] = []
            for edit in rule_cfg.edits:
                child_eval = evaluate_edit(f"{path} rule", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGASPathListRule)
                _assign_numeric_id(child_values, edit.name)
                values["rules"].append(FGASPathListRule(**child_values))
        config.aspath_lists.append(FGASPathList(**values))


def _extract_community_lists(tree, config):
    path = "router community-list"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGCommunityList, name=source.edit.name, vdom=source.vdom)
        rule_cfg = get_child_config(source.edit, "rule")
        if rule_cfg is not None:
            values["rules"] = []
            for edit in rule_cfg.edits:
                child_eval = evaluate_edit(f"{path} rule", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGCommunityListRule)
                _assign_numeric_id(child_values, edit.name)
                values["rules"].append(FGCommunityListRule(**child_values))
        config.community_lists.append(FGCommunityList(**values))


def _extract_router_multicast(tree, config):
    path = "router multicast"
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGRouterMulticast, vdom=source.vdom)
        intf_cfg = get_child_config(source.config, "interface")
        if intf_cfg is not None:
            values["interfaces"] = []
            for edit in intf_cfg.edits:
                child_eval = evaluate_edit(f"{path} interface", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGMulticastInterface, name=edit.name)
                values["interfaces"].append(FGMulticastInterface(**child_values))
        config.router_multicast.append(FGRouterMulticast(**values))


def _extract_fortiextenders(tree, config):
    path = "extender-controller extender"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGFortiExtender, name=source.edit.name, vdom=source.vdom)
        values["login_password_configured"] = _secret_present(source.edit, "login-password")
        values["raw_extra"].pop("login-password", None)
        config.fortiextenders.append(FGFortiExtender(**values))


def _extract_numbered_policies(tree, config, path: str, destination: str, model_type):
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(
            evaluation, model_type=model_type, vdom=source.vdom,
            field_map={"policyid": "policy_id"},
        )
        if values.get("policy_id") is None:
            _assign_numeric_id(values, source.edit.name, "policy_id")
        getattr(config, destination).append(model_type(**values))


def _extract_antivirus_profiles(tree, config):
    path = "antivirus profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGAntivirusProfile, name=source.edit.name, vdom=source.vdom)
        protocols = []
        for proto in ("http", "ftp", "imap", "pop3", "smtp", "mapi", "nntp", "cifs", "ssh"):
            child = get_child_config(source.edit, proto)
            if child is not None:
                child_eval = evaluate_config(f"{path} {proto}", child)
                child_values = source_model_kwargs(child_eval, model_type=FGAVProtocolConfig)
                child_values["protocol"] = proto
                protocols.append(FGAVProtocolConfig(**child_values))
        values["protocols"] = protocols
        config.antivirus_profiles.append(FGAntivirusProfile(**values))


def _extract_webfilter_profiles(tree, config):
    path = "webfilter profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGWebFilterProfile, name=source.edit.name, vdom=source.vdom)
        web_child = get_child_config(source.edit, "web")
        if web_child is not None:
            web_eval = evaluate_config(f"{path} web", web_child)
            for key, target in (
                ("urlfilter-table", "urlfilter_table"),
                ("block-invalid-url", "block_invalid_url"),
                ("safe-search", "safe_search"),
                ("youtube-restrict", "youtube_restrict"),
            ):
                if key in web_eval.values:
                    values[target] = web_eval.values[key]
                    values["explicit_fields"].add(target)
        ftgd_child = get_child_config(source.edit, "ftgd-wf")
        if ftgd_child is not None:
            ftgd_eval = evaluate_config(f"{path} ftgd-wf", ftgd_child)
            for key, target in (("options", "ftgd_options"), ("ovrd", "ftgd_ovrd")):
                if key in ftgd_eval.values:
                    values[target] = ftgd_eval.values[key]
                    values["explicit_fields"].add(target)
            filters_child = get_child_config(ftgd_child, "filters")
            if filters_child is not None:
                values["ftgd_filters"] = []
                for edit in filters_child.edits:
                    child_eval = evaluate_edit(f"{path} ftgd-wf filters", edit)
                    child_values = source_model_kwargs(child_eval, model_type=FGWebFilterFTGDFilter)
                    _assign_numeric_id(child_values, edit.name)
                    values["ftgd_filters"].append(FGWebFilterFTGDFilter(**child_values))
        config.webfilter_profiles.append(FGWebFilterProfile(**values))


def _extract_urlfilter_tables(tree, config):
    path = "webfilter urlfilter"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGURLFilterTable, vdom=source.vdom)
        _assign_numeric_id(values, source.edit.name)
        entries_cfg = get_child_config(source.edit, "entries")
        if entries_cfg is not None:
            values["entries"] = []
            for edit in entries_cfg.edits:
                child_eval = evaluate_edit(f"{path} entries", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGURLFilterEntry)
                _assign_numeric_id(child_values, edit.name)
                values["entries"].append(FGURLFilterEntry(**child_values))
        config.urlfilter_tables.append(FGURLFilterTable(**values))


def _extract_dnsfilter_profiles(tree, config):
    path = "dnsfilter profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGDNSFilterProfile, name=source.edit.name, vdom=source.vdom)
        dom_child = get_child_config(source.edit, "domain-filter")
        if dom_child is not None:
            dom_eval = evaluate_config(f"{path} domain-filter", dom_child)
            if "domain-filter-table" in dom_eval.values:
                values["domain_filter_table"] = dom_eval.values["domain-filter-table"]
                values["explicit_fields"].add("domain_filter_table")
        ftgd_child = get_child_config(source.edit, "ftgd-dns")
        if ftgd_child is not None:
            ftgd_eval = evaluate_config(f"{path} ftgd-dns", ftgd_child)
            if "options" in ftgd_eval.values:
                values["ftgd_options"] = ftgd_eval.values["options"]
                values["explicit_fields"].add("ftgd_options")
            filters_child = get_child_config(ftgd_child, "filters")
            if filters_child is not None:
                values["ftgd_filters"] = []
                for edit in filters_child.edits:
                    child_eval = evaluate_edit(f"{path} ftgd-dns filters", edit)
                    child_values = source_model_kwargs(child_eval, model_type=FGDNSFilterFTGDFilter)
                    _assign_numeric_id(child_values, edit.name)
                    values["ftgd_filters"].append(FGDNSFilterFTGDFilter(**child_values))
        config.dnsfilter_profiles.append(FGDNSFilterProfile(**values))


def _extract_application_lists(tree, config):
    path = "application list"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGApplicationList, name=source.edit.name, vdom=source.vdom)
        entries_cfg = get_child_config(source.edit, "entries")
        if entries_cfg is not None:
            values["entries"] = []
            for edit in entries_cfg.edits:
                child_eval = evaluate_edit(f"{path} entries", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGApplicationListEntry)
                _assign_numeric_id(child_values, edit.name)
                values["entries"].append(FGApplicationListEntry(**child_values))
        config.application_lists.append(FGApplicationList(**values))


def _extract_file_filter_profiles(tree, config):
    path = "file-filter profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGFileFilterProfile, name=source.edit.name, vdom=source.vdom)
        rules_cfg = get_child_config(source.edit, "rules")
        if rules_cfg is not None:
            values["rules"] = []
            for edit in rules_cfg.edits:
                child_eval = evaluate_edit(f"{path} rules", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGFileFilterRule, name=edit.name)
                values["rules"].append(FGFileFilterRule(**child_values))
        config.file_filter_profiles.append(FGFileFilterProfile(**values))


def _extract_voip_profiles(tree, config):
    path = "voip profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGVoIPProfile, name=source.edit.name, vdom=source.vdom)
        sip_child = get_child_config(source.edit, "sip")
        if sip_child is not None:
            sip_eval = evaluate_config(f"{path} sip", sip_child)
            for key, target in (
                ("status", "sip_status"),
                ("rtp", "sip_rtp"),
                ("strict-register", "sip_strict_register"),
                ("invite-rate", "sip_invite_rate"),
                ("register-rate", "sip_register_rate"),
                ("log-violations", "sip_log_violations"),
            ):
                if key in sip_eval.values:
                    values[target] = sip_eval.values[key]
                    values["explicit_fields"].add(target)
        config.voip_profiles.append(FGVoIPProfile(**values))


def _extract_ssl_ssh_profiles(tree, config):
    path = "firewall ssl-ssh-profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGSSLSSHProfile, name=source.edit.name, vdom=source.vdom)
        protocols = []
        for proto in ("ssl", "https", "ftps", "imaps", "pop3s", "smtps", "ssh", "dot"):
            child = get_child_config(source.edit, proto)
            if child is not None:
                child_eval = evaluate_config(f"{path} {proto}", child)
                child_values = source_model_kwargs(child_eval, model_type=FGSSLSSHProtocolConfig)
                child_values["protocol"] = proto
                protocols.append(FGSSLSSHProtocolConfig(**child_values))
        values["protocols"] = protocols
        config.ssl_ssh_profiles.append(FGSSLSSHProfile(**values))


def _extract_ldap_servers(tree, config):
    path = "user ldap"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGLDAPServer, name=source.edit.name, vdom=source.vdom)
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        config.ldap_servers.append(FGLDAPServer(**values))


def _extract_radius_servers(tree, config):
    path = "user radius"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(
            evaluation, model_type=FGRADIUSServer, name=source.edit.name, vdom=source.vdom,
            field_map={"class": "radius_class"},
        )
        values["secret_configured"] = _secret_present(source.edit, "secret")
        values["secondary_secret_configured"] = _secret_present(source.edit, "secondary-secret")
        values["tertiary_secret_configured"] = _secret_present(source.edit, "tertiary-secret")
        for secret_key in ("secret", "secondary-secret", "tertiary-secret", "rsso-secret"):
            values["raw_extra"].pop(secret_key, None)
        config.radius_servers.append(FGRADIUSServer(**values))


def _extract_tacacs_servers(tree, config):
    path = "user tacacs+"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGTACACSServer, name=source.edit.name, vdom=source.vdom)
        values["secret_configured"] = _secret_present(source.edit, "key")
        values["secondary_secret_configured"] = _secret_present(source.edit, "secondary-key")
        values["tertiary_secret_configured"] = _secret_present(source.edit, "tertiary-key")
        for secret_key in ("key", "secondary-key", "tertiary-key"):
            values["raw_extra"].pop(secret_key, None)
        config.tacacs_servers.append(FGTACACSServer(**values))


def _extract_fsso_servers(tree, config):
    path = "user fsso"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGFSSOServer, name=source.edit.name, vdom=source.vdom)
        values["password_configured"] = any(
            _secret_present(source.edit, key)
            for key in ("password", "password2", "password3", "password4", "password5")
        )
        for secret_key in ("password", "password2", "password3", "password4", "password5"):
            values["raw_extra"].pop(secret_key, None)
        config.fsso_servers.append(FGFSSOServer(**values))


def _extract_fsso_pollings(tree, config):
    path = "user fsso-polling"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGFSSOPolling, vdom=source.vdom)
        _assign_numeric_id(values, source.edit.name)
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        config.fsso_pollings.append(FGFSSOPolling(**values))


def _extract_fortitokens(tree, config):
    path = "user fortitoken"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGFortiToken, vdom=source.vdom)
        values["serial_number"] = source.edit.name
        values["seed_configured"] = _secret_present(source.edit, "seed")
        values["activation_code_configured"] = _secret_present(source.edit, "activation-code")
        values["raw_extra"].pop("seed", None)
        values["raw_extra"].pop("activation-code", None)
        config.fortitokens.append(FGFortiToken(**values))


def _extract_wireless_vaps(tree, config):
    path = "wireless-controller vap"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGWirelessVAP, name=source.edit.name, vdom=source.vdom)
        values["passphrase_configured"] = _secret_present(source.edit, "passphrase") or _secret_present(source.edit, "key")
        values["raw_extra"].pop("passphrase", None)
        values["raw_extra"].pop("key", None)
        config.wireless_vaps.append(FGWirelessVAP(**values))


def _extract_wireless_wtps(tree, config):
    path = "wireless-controller wtp"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGWirelessWTP, vdom=source.vdom)
        values["wtp_id"] = source.edit.name
        values["login_passwd_configured"] = _secret_present(source.edit, "login-passwd")
        values["raw_extra"].pop("login-passwd", None)
        config.wireless_wtps.append(FGWirelessWTP(**values))


def _extract_nac_settings(tree, config):
    path = "switch-controller nac-settings"
    for source in iter_section_configs(tree, path):
        if source.config.edits:
            for edit in source.config.edits:
                evaluation = evaluate_edit(path, edit)
                values = source_model_kwargs(evaluation, model_type=FGNACPolicy, name=edit.name, vdom=source.vdom)
                values["source_path"] = path
                config.nac_policies.append(FGNACPolicy(**values))
        elif source.config.commands:
            evaluation = evaluate_config(path, source.config)
            values = source_model_kwargs(evaluation, model_type=FGNACPolicy, vdom=source.vdom)
            values["name"] = values.get("name") or "nac-settings"
            values["source_path"] = path
            config.nac_policies.append(FGNACPolicy(**values))


def _extract_wtp_profiles(tree, config):
    path = "wireless-controller wtp-profile"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGWirelessWTPProfile, name=source.edit.name, vdom=source.vdom)
        values["login_passwd_configured"] = _secret_present(source.edit, "login-passwd")
        values["raw_extra"].pop("login-passwd", None)
        platform_cfg = get_child_config(source.edit, "platform")
        if platform_cfg is not None:
            platform_eval = evaluate_config(f"{path} platform", platform_cfg)
            platform_values = source_model_kwargs(platform_eval, model_type=FGWirelessWTPProfilePlatform)
            values["platform_config"] = FGWirelessWTPProfilePlatform(**platform_values)
            if values.get("platform") is None and platform_values.get("type") is not None:
                values["platform"] = platform_values["type"]
        config.wtp_profiles.append(FGWirelessWTPProfile(**values))


def _extract_managed_switches(tree, config):
    path = "switch-controller managed-switch"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGManagedSwitch, vdom=source.vdom)
        values["switch_id"] = source.edit.name
        ports_cfg = get_child_config(source.edit, "ports")
        if ports_cfg is not None:
            values["ports"] = []
            for edit in ports_cfg.edits:
                child_eval = evaluate_edit(f"{path} ports", edit)
                child_values = source_model_kwargs(child_eval, model_type=FGManagedSwitchPort)
                child_values["port_name"] = edit.name
                child_values["switch_id"] = source.edit.name
                values["ports"].append(FGManagedSwitchPort(**child_values))
        config.managed_switches.append(FGManagedSwitch(**values))


def _extract_syslog_setting(tree, config, path: str, syslog_name: str):
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGSyslogSetting, vdom=source.vdom)
        values["syslog_name"] = syslog_name
        config.syslog_settings.append(FGSyslogSetting(**values))


def _extract_log_disk_settings(tree, config):
    path = "log disk setting"
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGLogDiskSetting, vdom=source.vdom)
        values["upload_password_configured"] = _secret_present(source.config, "uploadpass")
        values["raw_extra"].pop("uploadpass", None)
        config.log_disk_settings.append(FGLogDiskSetting(**values))


def _extract_guest_users(tree, config):
    path = "user guest"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGUserGuest, vdom=source.vdom)
        values["id"] = source.edit.name
        values["password_configured"] = _secret_present(source.edit, "password")
        values["raw_extra"].pop("password", None)
        config.guest_users.append(FGUserGuest(**values))


def _extract_certificates(tree, config, store: str):
    path = f"vpn certificate {store}"
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGCertificate, name=source.edit.name, vdom=source.vdom)
        values["store"] = store
        values["private_key_configured"] = _secret_present(source.edit, "private-key")
        values["password_configured"] = _secret_present(source.edit, "password") or _secret_present(source.edit, "passphrase")
        for secret_key in ("private-key", "password", "passphrase"):
            values["raw_extra"].pop(secret_key, None)
        config.certificates.append(FGCertificate(**values))


def _extract_fortianalyzer_setting(tree, config, path: str, target_name: str):
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGFortiAnalyzerSetting, vdom=source.vdom)
        values["target_name"] = target_name
        config.fortianalyzer_settings.append(FGFortiAnalyzerSetting(**values))


def _extract_log_threat_weight(tree, config):
    path = "log threat-weight"
    for source in iter_section_configs(tree, path):
        evaluation = evaluate_config(path, source.config)
        values = source_model_kwargs(evaluation, model_type=FGLogThreatWeight, vdom=source.vdom)
        for child_name, model_cls in (
            ("level", FGThreatWeightLevel),
            ("ips", FGThreatWeightIPS),
            ("malware", FGThreatWeightMalware),
        ):
            child_cfg = get_child_config(source.config, child_name)
            if child_cfg is not None:
                child_eval = evaluate_config(f"{path} {child_name}", child_cfg)
                values[child_name] = model_cls(**source_model_kwargs(child_eval, model_type=model_cls))
        for cat_name in ("web", "application"):
            cat_cfg = get_child_config(source.config, cat_name)
            if cat_cfg is not None:
                entries = []
                for edit in cat_cfg.edits:
                    edit_eval = evaluate_edit(f"{path} {cat_name}", edit)
                    edit_vals = source_model_kwargs(edit_eval, model_type=FGThreatWeightCategoryEntry)
                    _assign_numeric_id(edit_vals, edit.name)
                    entries.append(FGThreatWeightCategoryEntry(**edit_vals))
                values[cat_name] = entries
        config.log_threat_weights.append(FGLogThreatWeight(**values))


def _extract_local_in_policies(tree, config, path: str, address_family: str):
    for source in iter_section_edits(tree, path):
        evaluation = evaluate_edit(path, source.edit)
        values = source_model_kwargs(evaluation, model_type=FGLocalInPolicy, vdom=source.vdom)
        values["address_family"] = address_family
        _assign_numeric_id(values, source.edit.name, "policy_id")
        config.local_in_policies.append(FGLocalInPolicy(**values))
