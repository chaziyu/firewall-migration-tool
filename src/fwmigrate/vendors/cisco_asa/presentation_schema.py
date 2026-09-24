"""Explicit source and derived presentation allowlists for Cisco ASA."""

SOURCE_SECTIONS = {
    "Interfaces": ("interfaces", "name source_context interface_type nameif description ip_mode ip mask ipv6_addresses security_level mtu routing_context vrf vlan_id parent_interface channel_group channel_group_mode redundant_interface_members bridge_group management_only shutdown tunnel_source tunnel_destination ipsec_profile extraction_status requires_manual_review review_reasons raw_extra"),
    "Zones": ("traffic_zones", "name source_context members interfaces raw_extra requires_manual_review review_reasons"),
    "Network Objects": ("network_objects", "name source_context type value address_family description raw_extra requires_manual_review review_reasons"),
    "Network Groups": ("network_groups", "name source_context members description raw_extra requires_manual_review review_reasons"),
    "Service Objects": ("service_objects", "name source_context ports description raw_lines raw_extra requires_manual_review review_reasons"),
    "Service Groups": ("service_groups", "name source_context protocol members description raw_extra requires_manual_review review_reasons"),
    "Time Ranges": ("time_ranges", "name source_context clauses raw_lines requires_manual_review review_reasons"),
    "ACL Rules": ("access_rules", "acl_name source_context source_order source_sequence acl_type action protocol protocol_object source_endpoint source_port destination_endpoint destination_port service icmp_type icmp_code user user_group security_group time_range log_enabled log_level log_interval inactive remark raw_line requires_manual_review review_reasons"),
    "NAT Rules": ("nat_rules", "name source_context syntax_family section source_order source_order_within_section sequence source_sequence type translation_semantics source_interface destination_interface real_source mapped_source source_mode mapped_source_mode real_destination mapped_destination destination_mode original_service translated_service service_protocol owning_object access_list pat_pool pat_pool_options identity_nat nat_exemption dns no_proxy_arp route_lookup unidirectional inactive options raw_options raw_line requires_manual_review review_reasons"),
    "Class Maps": ("class_maps", "name source_context class_map_type inspection_protocol typed match_type matches match_any match_all description match_lines requires_manual_review review_reasons"),
    "Policy Maps": ("policy_maps", "name source_context policy_map_type inspection_protocol typed inspection_sections parameter_lines classes description class_sections requires_manual_review review_reasons"),
    "Service Policies": ("service_policies", "name source_context policy_name scope interface global_attachment enabled negated fail_close attachment source_order requires_manual_review review_reasons"),
    "DHCP Servers": ("dhcp_servers", "name source_context interface pool pool_start pool_end dns_servers wins_servers domain_name lease_seconds ping_timeout auto_config dns_update enabled options source_order requires_manual_review review_reasons"),
    "DHCP Reservations": ("dhcp_servers", "reservations", "ip mac interface source_order"),
    "DHCP Relays": ("dhcp_relays", "name source_context server servers server_entries interface enabled_interfaces timeout options enabled source_order requires_manual_review review_reasons"),
    "Route Maps": ("route_maps", "name source_context rules raw_lines"),
    "Policy Routing": ("interfaces", "name source_context policy_route_maps policy_route_cost policy_route_path_monitors"),
    "SLA Monitors": ("sla_monitors", "name source_context sla_id operation frequency target interface raw_lines requires_manual_review review_reasons"),
    "Tracks": ("tracks", "name source_context track_id track_type sla_id target raw_lines requires_manual_review review_reasons"),
    "Local Users": ("local_users", "username source_context privilege authentication_type password_present secret_present encrypted nopassword requires_manual_review review_reasons"),
    "User Groups": ("user_groups", "name source_context members description requires_manual_review review_reasons"),
    "AAA Server Groups": ("aaa_server_groups", "name source_context protocol hosts requires_manual_review review_reasons"),
    "AAA Server Hosts": ("aaa_server_hosts", "group_name source_context host interface protocol authentication_port accounting_port timeout retries key_present password_present server_secret_present ldap_base_dn ldap_scope ldap_naming_attribute ldap_login_dn ldap_over_ssl radius_common_password_present requires_manual_review review_reasons"),
    "AAA Authentication": ("aaa_authentication_rules", "service management_protocol target server_group fallback_local interface options acl_reference user_identity source_context raw_line"),
    "AAA Authorization": ("aaa_authorization_rules", "service management_protocol target server_group fallback_local interface options acl_reference user_identity source_context raw_line"),
    "AAA Accounting": ("aaa_accounting_rules", "service management_protocol target server_group fallback_local interface options acl_reference user_identity source_context raw_line"),
    "Command Privileges": ("command_privileges", "command_form privilege_level cli_mode command source_context source_order raw_line"),
    "IKE Policies": ("ike_policies", "name source_context version number authentication encryption integrity hash_algorithm dh_group lifetime_seconds prf encryption_algorithms hash_algorithms integrity_algorithms prf_algorithms dh_groups raw_options"),
    "IKEv2 Proposals": ("ikev2_proposals", "name source_context encryption_algorithms integrity_algorithms prf_algorithms dh_groups"),
    "IPsec Transform Sets": ("ipsec_transform_sets", "name source_context encryption authentication mode raw_line"),
    "Crypto Maps": ("crypto_maps", "name source_context map_name sequence acl_name peers transform_sets ikev2_proposals pfs_group security_association_lifetime_seconds security_association_lifetime_kilobytes interface_attachment dynamic_map is_dynamic source_order raw_options"),
    "Tunnel Groups": ("tunnel_groups", "name source_context group_type default_group_policy address_pools authentication_method peer_address trustpoint ikev1_psk_present ikev2_local_authentication ikev2_remote_authentication general_attributes ipsec_attributes webvpn_attributes"),
    "Group Policies": ("group_policies", "name source_context policy_type parent address_pools dns_servers split_tunnel_policy split_tunnel_acl vpn_access_hours vpn_filter_acl vpn_simultaneous_logins wins_servers vpn_protocols idle_timeout session_timeout default_domain webvpn_attributes raw_attributes"),
    "VPN Address Pools": ("vpn_address_pools", "name source_context start end mask address_family raw_line"),
    "VPN Address Assignment": ("vpn_address_assignments", "name source_context aaa_enabled dhcp_enabled local_enabled reuse_delay"),
    "WebVPN": ("webvpn_configs", "name source_context enabled_interfaces tunnel_group_list client_images client_profiles trustpoint_references"),
    "DNS": ("dns_server_groups", "name source_context name_servers domain_name interface_lookup retries timeout expire_entry_timer poll_timer child_order raw_settings"),
    "DNS Settings": ("dns_settings", "name_servers command_history domain_name lookup_interfaces default_server_group source_order"),
    "System Settings": ("system_settings", "hostname domain_name timezone_name timezone_offset dst_name management_access_interface same_security_inter same_security_intra"),
    "HTTP Server": ("http_server", "enabled port idle_timeout session_timeout raw_lines source_order"),
    "NTP": ("ntp_servers", "name source_context negated server interface prefer key_id source_order raw_line"),
    "Management Access": ("management_access_rules", "name source_context address_family negated protocol source mask_or_prefix interface port raw_line source_order"),
    "SNMP": ("snmp_settings", "name source_context setting_type host interface community_present version username trap_types location contact source_order raw_line"),
    "Logging": ("logging_settings", "name source_context setting_type enabled host interface severity facility buffer_size timestamp source_order raw_line"),
    "Failover": ("failover_settings", "name source_context setting enabled"),
    "Contexts": ("contexts", "name source_context admin_context resource_class config_url allocated_interfaces allocated_interface_entries requires_manual_review review_reasons"),
}

for _name, _spec in tuple(SOURCE_SECTIONS.items()):
    _fields = _spec[-1].split()
    _fields.extend(field for field in ("extraction_status", "requires_manual_review", "review_reasons", "raw_extra")
                   if field not in _fields)
    SOURCE_SECTIONS[_name] = (*_spec[:-1], " ".join(_fields))

DERIVED_SECTIONS = {
    "ACL Bindings": "acl_relationships.bindings",
    "IPS Actions": "mpf_relationships.external_ips_actions",
    "Routes": "routes.routes",
    "IPsec VPN": "vpn.ipsec_topologies",
    "Remote Access VPN": "vpn.remote_access",
    "Source NAT Pools": "nat.source_nat_pools",
    "Published Services - VIPs": "nat.vips",
}

SHEET_ORDER = (
    "Summary", "Review Required", "Source Inventory", "Interfaces", "Zones",
    "Network Objects", "Network Groups", "Service Objects", "Service Groups", "Time Ranges",
    "ACL Rules", "ACL Bindings", "NAT Rules", "Source NAT Pools", "Published Services - VIPs",
    "Class Maps", "Policy Maps", "Service Policies", "IPS Actions", "DHCP Servers", "DHCP Reservations", "DHCP Relays",
    "Routes", "Route Maps", "Policy Routing", "SLA Monitors", "Tracks",
    "Local Users", "User Groups", "AAA Server Groups", "AAA Server Hosts", "AAA Authentication",
    "AAA Authorization", "AAA Accounting", "Command Privileges", "IKE Policies", "IKEv2 Proposals",
    "IPsec Transform Sets", "Crypto Maps", "Tunnel Groups", "Group Policies", "VPN Address Pools",
    "VPN Address Assignment", "WebVPN", "IPsec VPN", "Remote Access VPN", "DNS", "DNS Settings", "NTP",
    "Management Access", "HTTP Server", "System Settings", "SNMP", "Logging", "Failover", "Contexts",
    "Validation", "Unsupported", "Extraction Coverage",
)

SHEET_HEADERS = {name: tuple(field.replace("_", " ").title() for field in spec[1].split())
                 for name, spec in SOURCE_SECTIONS.items()}
SHEET_HEADERS.update({
    "Summary": ("Field", "Value"),
    "Review Required": ("Domain", "Context", "Object", "Source Status", "Reason", "Source Path / Identity"),
    "Source Inventory": ("Domain", "Source Path", "Source ID", "Status", "Review Required", "Notes"),
    "ACL Bindings": ("ACL", "Context", "Scope", "Interface", "Direction", "Resolved ACL", "Resolved Interface", "Issues"),
    "Zones": ("Name", "Context", "Explicit Members", "Resolved Members", "Unresolved Members", "Additional Settings", "Review Required"),
    "IPS Actions": ("Policy Map", "Class", "Mode", "Failure Mode", "Sensor Reference", "Context", "Service Policy Activation", "Issues"),
    "IPsec VPN": ("Type", "Source Identity", "Crypto Map", "Sequence", "Crypto ACL", "Peers", "Tunnel Groups", "Interface", "Transform Sets", "IKEv2 Proposals", "VTI", "Tunnel Source", "Tunnel Destination", "IPsec Profile", "Resolution Status", "Issues"),
    "Remote Access VPN": ("Connection Profile", "Connection Profile Type", "Group Policy", "Inherited Group Policy", "Authentication Source", "Address Pools", "DHCP Servers", "Address Assignment", "VPN Protocols", "Access Hours", "VPN Filter", "Split Tunnel Policy", "Split Tunnel ACL", "DNS", "WINS", "Default Domain", "Enabled Interfaces", "Trustpoints", "Context", "Resolution Status", "Issues"),
    "Source NAT Pools": ("Source Rule", "Pool Type", "Mapped Source", "Mapped Object", "Mapped Interface", "Address Family", "Translation Semantics", "Source Interface", "Destination Interface", "Context", "Issues"),
    "Published Services - VIPs": ("Source Rule", "Mapped Address", "Real Address", "Mapped Service", "Real Service", "Protocol", "External Interface", "Internal Interface", "NAT Order", "Context", "Issues"),
    "Validation": ("Severity", "Category", "Message", "Context", "Object"),
    "Unsupported": ("Line", "Context", "Command Family", "Reason", "Sanitized Source"),
    "Extraction Coverage": ("Selected Area", "ASA Source Family", "Detected", "Structured", "Partial", "Unsupported", "Parse Errors", "Review Required"),
    "Failover": ("Record Type", "Context", "Source Values"),
    "DHCP Reservations": ("IP", "MAC", "Interface", "Context", "Source Order"),
    "NAT Rules": ("Name", "Source Order", "Effective Order", "Order Status", "Section", "Context", "Syntax Family", "Source Order Within Section", "Source Sequence", "Translation Semantics", "Source Interface", "Destination Interface", "Real Source", "Mapped Source", "Source Mode", "Mapped Source Mode", "Real Destination", "Mapped Destination", "Destination Mode", "Original Service", "Translated Service", "Service Protocol", "Owning Object", "ACL", "PAT Pool", "PAT Pool Options", "Identity NAT", "NAT Exemption", "DNS", "No Proxy ARP", "Route Lookup", "Unidirectional", "Inactive", "Additional Settings", "Issues", "Raw"),
    "Routes": ("Interface", "Destination", "Mask", "Destination Prefix (Normalized)", "Gateway", "Configured Administrative Distance", "Effective Administrative Distance", "Track", "Context", "Raw"),
})
SHEET_HEADERS["Interfaces"] += ("Topology Kind", "Resolved Parent", "Aggregate", "Physical Interfaces", "Topology Issues")
