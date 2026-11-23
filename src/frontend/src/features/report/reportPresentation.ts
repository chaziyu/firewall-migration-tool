export type ReportRow = Record<string, unknown>

const SENSITIVE_KEY = /raw_extra|password(?!_configured$)|secret(?!_configured$)|credential(?!_configured$)|token(?!_configured$)|private.?key(?!_configured$)|psk(?!_configured$)/i
const AUTHENTICATION_METADATA = new Set([
  'password_label', 'save_user_credentials', 'domain_credentials', 'user_credential_or_client_cert_required',
  'fortitoken', 'passwd_policy', 'passwd_time', 'password_policy', 'password_profile', 'admin_password_policy',
  'password_policy_scope', 'password_expiry_warning', 'password_renewal', 'password_encoding', 'reuse_password',
  'login_password_change', 'login_passwd_change', 'password_protected', 'expiration_period',
  'expiration_warning_period', 'post_expiration_grace_period', 'post_expiration_admin_login_count',
  'minimum_length', 'password_history_count', 'new_password_differs_by_characters',
])
function sensitiveKey(key: string, value?: unknown) {
  return SENSITIVE_KEY.test(key) && !(AUTHENTICATION_METADATA.has(key.replaceAll('-', '_')) && (value == null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number'))
}
export function asRecord(value: unknown): ReportRow {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as ReportRow : {}
}
export function asRows(value: unknown): ReportRow[] {
  return Array.isArray(value) ? value.filter((row): row is ReportRow => row !== null && typeof row === 'object' && !Array.isArray(row)) : []
}
export function safeValue(value: unknown, key = ''): unknown {
  if (key && sensitiveKey(key, value)) return undefined
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) {
    let changed = false
    const result: unknown[] = []
    for (let i = 0; i < value.length; i++) {
      const item = value[i]
      const next = safeValue(item)
      if (next !== item) changed = true
      if (next !== undefined) result.push(next)
      else changed = true
    }
    return changed ? result : value
  }
  let changed = false
  const record = value as ReportRow
  const result: ReportRow = {}
  for (const name in record) {
    if (!Object.hasOwn(record, name)) continue
    const item = record[name]
    if (sensitiveKey(name, item)) {
      changed = true
      continue
    }
    const next = safeValue(item, name)
    if (next !== item) changed = true
    result[name] = next
  }
  return changed ? result : value
}

// Rows remain immutable for the lifetime of a source preview.
const reportSearchIndex = new WeakMap<ReportRow, string>()
export function reportSearchText(row: ReportRow): string {
  const cached = reportSearchIndex.get(row)
  if (cached !== undefined) return cached
  const text = JSON.stringify(row, (key, value) => (key && sensitiveKey(key, value) ? undefined : value)).toLowerCase()
  reportSearchIndex.set(row, text)
  return text
}

const SECTION_KEYS: Record<string, string[]> = {
  Interfaces: ['interfaces', 'interface_topology', 'interface_imports', 'management_profiles', 'vlans', 'virtual_wires', 'dns_proxies', 'qos_interfaces', 'qos_profiles', 'zone_protection_profiles', 'monitor_profiles', 'lldp_profiles', 'bfd_profiles', 'switch_port_policies', 'switch_lldp_profiles', 'switch_qos_policies', 'switch_vlan_policies'],
  Objects: [
    'addresses', 'addresses_ipv6', 'address_groups', 'address6_templates', 'wildcard_fqdns',
    'services', 'service_groups', 'service_categories',
    'network_objects', 'network_groups', 'protocol_port_objects',
    'applications', 'application_groups', 'regions', 'dynamic_user_groups', 'device_objects',
    'hip_objects', 'hip_profiles', 'external_lists', 'custom_url_categories', 'data_patterns', 'custom_threats',
    'zones', 'tags',
    'security_profile_groups', 'profile_groups', 'vulnerability_profiles', 'ips_sensors',
    'antivirus_profiles', 'anti_spyware_profiles', 'webfilter_profiles', 'urlfilter_tables',
    'webfilter_local_categories', 'webfilter_local_ratings', 'webfilter_overrides',
    'dnsfilter_profiles', 'application_lists', 'file_filter_profiles', 'emailfilter_profiles',
    'voip_profiles', 'waf_profiles', 'ssl_ssh_profiles',
    'url_filtering_profiles', 'file_blocking_profiles', 'wildfire_profiles', 'data_filtering_profiles',
    'dos_protection_profiles', 'decryption_profiles', 'protocol_options', 'per_ip_shapers',
    'traffic_shapers', 'session_helpers', 'ips_settings', 'external_resources',
    'local_users', 'guest_users', 'local_user_groups', 'user_groups', 'group_mappings',
    'ldap_servers', 'radius_servers', 'tacacs_servers', 'fsso_servers', 'fsso_pollings',
    'fortitokens', 'user_settings', 'password_policies',
    'radius_server_profiles', 'ldap_server_profiles', 'tacplus_server_profiles',
    'kerberos_server_profiles', 'saml_idp_server_profiles', 'mfa_server_profiles',
    'authentication_profiles', 'authentication_sequences', 'certificates', 'ssl_tls_service_profiles',
    'password_complexities', 'password_profiles', 'user_id_agents', 'user_id_settings',
    'administrators', 'admin_roles', 'admin_profiles', 'firewall_regions', 'vendor_macs',
  ],
  Schedules: ['schedules', 'schedule_groups', 'time_ranges'],
  Policies: [
    'policies', 'security_policies', 'security_rules', 'default_security_rules',
    'proxy_policies', 'auth_policies', 'access_control_policies', 'access_rules',
    'nac_policies', 'sdwan_rules', 'qos_rules', 'pbf_rules', 'decryption_rules',
    'tunnel_inspect_rules', 'app_override_rules', 'authentication_rules', 'dos_rules',
  ],
  NAT: ['nat', 'nat_rules', 'translations', 'central_snat', 'vips', 'vip_groups', 'virtual_servers', 'ldb_monitors', 'ip_pools'],
  Routes: [
    'routes', 'static_routes', 'routing_instances', 'virtual_routers', 'logical_routers',
    'router_settings', 'router_bgp', 'router_ospf', 'router_ospf6', 'router_rip',
    'policy_routes', 'prefix_lists', 'route_maps', 'aspath_lists', 'community_lists', 'router_multicast',
  ],
  VPN: [
    'vpn_tunnels', 'vpn_phase2', 'policy_vpn_phase1', 'policy_vpn_phase2',
    'ssl_vpn_settings', 'ssl_vpn_realms', 'ssl_vpn_bookmarks', 'ssl_vpn_portals',
    'ssl_vpn_clients', 'ssl_vpn_host_check_software',
    'ike_gateways', 'ike_crypto_profiles', 'ipsec_crypto_profiles', 'ipsec_tunnels', 'gre_tunnels',
    'globalprotect_portals', 'globalprotect_gateways', 'gp_clientless_apps', 'gp_clientless_app_groups', 'gp_mdms',
    'kmip_servers', 'kerberos_keytabs',
  ],
  References: ['unresolved_references', 'references', 'relationships'],
  Extraction: ['extraction_coverage', 'source_inventory'],
}

export function reportSections(sections: ReportRow) {
  const groups: Array<{ label: string; subsections: Array<{ key: string; rows: ReportRow[] }>; rows: ReportRow[] }> = []
  for (const [key, value] of Object.entries(sections)) {
    if (key === 'validation') continue
    const normalized = key.toLowerCase().replace(/[ -]/g, '_')
    const label = Object.entries(SECTION_KEYS).find(([, keys]) => keys.includes(normalized))?.[0] ?? 'Additional sections'
    let group = groups.find((item) => item.label === label)
    if (!group) { group = { label, subsections: [], rows: [] }; groups.push(group) }
    const values = Array.isArray(value) ? value : [value]
    const rows = values.map((item) => ({ ...asRecord(safeValue(item)), ...(item === null || typeof item !== 'object' || Array.isArray(item) ? { value: safeValue(item) } : {}), 'Source section': key }))
    group.subsections.push({ key, rows })
    group.rows.push(...rows)
  }
  for (const group of groups) {
    const preferred = SECTION_KEYS[group.label] ?? []
    group.subsections.sort((a, b) => {
      const rank = (key: string) => { const index = preferred.indexOf(key.toLowerCase().replace(/[ -]/g, '_')); return index < 0 ? preferred.length : index }
      return rank(a.key) - rank(b.key)
    })
  }
  return groups
}

export function reportSectionRowCount(section: ReturnType<typeof reportSections>[number] | undefined) {
  if (!section) return null
  if (section.label === 'Interfaces') return section.subsections.find((item) => item.key.toLowerCase().replace(/[ -]/g, '_') === 'interfaces')?.rows.length ?? null
  return section.rows.length
}

export function interfaceTopologyRows(inventory: ReportRow[], topology: ReportRow[]) {
  const topologyByName = new Map<unknown, number>()
  for (const item of topology) {
    if (item.name != null) topologyByName.set(item.name, (topologyByName.get(item.name) ?? 0) + 1)
  }
  const inventoryByName = new Map<unknown, ReportRow[]>()
  for (const item of inventory) {
    if (item.name == null) continue
    let list = inventoryByName.get(item.name)
    if (!list) { list = []; inventoryByName.set(item.name, list) }
    list.push(item)
  }
  return topology.map((row) => {
    if (row.name == null) return row
    const candidates = inventoryByName.get(row.name)
    if (!candidates?.length) return row
    const rowScope = row.vdom ?? row.scope
    const uniqueByName = topologyByName.get(row.name) === 1 && candidates.length === 1
    let match: ReportRow | null = null
    for (const item of candidates) {
      const itemScope = item.vdom ?? item.scope
      const matched = rowScope != null && itemScope != null ? rowScope === itemScope : uniqueByName
      if (!matched) continue
      if (match !== null) return row
      match = item
    }
    if (!match) return row
    const merged: ReportRow = { ...row }
    for (const key in match) {
      if (Object.hasOwn(match, key) && key !== 'Source section') merged[key] = match[key]
    }
    merged['Source section'] = row['Source section']
    return merged
  })
}

export function reportCounts(data: { summary?: ReportRow; sections?: ReportRow }) {
  const summary = asRecord(data.summary)
  const objects = asRecord(summary.objects)
  const sections = asRecord(data.sections)
  const count = (keys: string[]) => {
    for (const key of keys) {
      const value = objects[key] ?? summary[key]
      if (typeof value === 'number') return value
    }
    return null
  }
  const objectKeys = ['addresses', 'address_groups', 'services', 'service_groups']
  const configured = objectKeys.map((key) => count([key]))
  const severity = asRecord(asRecord(summary.validation).severity_counts)
  const findings = asRows(sections.validation)
  return {
    policies: count(['policies', 'security_rules', 'access_control_policies']),
    objects: configured.every((value) => value !== null) ? configured.reduce<number>((sum, value) => sum + value!, 0) : null,
    interfaces: count(['interfaces']),
    errors: typeof severity.error === 'number' ? severity.error : findings.filter((row) => String(row.severity).toLowerCase() === 'error').length,
    warnings: typeof severity.warning === 'number' ? severity.warning : findings.filter((row) => String(row.severity).toLowerCase() === 'warning').length,
  }
}

export function compactValue(value: unknown): string {
  if (value === undefined) return 'Unknown / not reported'
  if (value === null) return 'Null / not reported'
  if (value === '') return '(empty string)'
  if (Array.isArray(value)) return value.length ? `${value.length} items` : '(empty list)'
  if (typeof value === 'object') return `${Object.keys(value).length} fields`
  return String(value)
}

const CISCO_FTD_COLUMNS: Record<string, string[]> = {
  policies: ['policy_id', 'policy_name', 'rule_id', 'name', 'position', 'domain_id', 'device_name', 'source_interfaces', 'source_addresses', 'destination_interfaces', 'destination_addresses', 'services', 'action'],
  nat: ['policy_id', 'policy_name', 'rule_id', 'name', 'position', 'sequence', 'domain_id', 'device_name', 'translation_type', 'egress_interfaces', 'translated_addresses'],
  interfaces: ['name', 'device_name', 'device_id', 'domain_id', 'kind', 'ip', 'zone', 'status'],
  interface_topology: ['display_name', 'name', 'device_name', 'device_id', 'domain_id', 'kind', 'ip', 'parent', 'physical_interfaces'],
  addresses: ['name', 'domain_id', 'device_name', 'type', 'value', 'address_family'],
  address_groups: ['name', 'domain_id', 'device_name', 'members'],
  services: ['name', 'domain_id', 'device_name', 'protocol', 'port'],
  service_groups: ['name', 'domain_id', 'device_name', 'members'],
  schedules: ['name', 'domain_id', 'device_name', 'value'],
  routes: ['route_id', 'name', 'domain_id', 'device_name', 'virtual_router_name', 'destination', 'gateway', 'status'],
  vpn_tunnels: ['name', 'domain_id', 'device_name', 'parent_policy_name', 'kind', 'peer'],
}

const FORTIGATE_COLUMNS: Record<string, string[]> = {
  policies: ['policy_id', 'name', 'vdom', 'source_interfaces', 'source_addresses', 'destination_interfaces', 'destination_addresses', 'services', 'action', 'schedule', 'logtraffic', 'status'],
  proxy_policies: ['policy_id', 'name', 'vdom', 'proxy', 'srcintf', 'srcaddr', 'dstintf', 'dstaddr', 'service', 'action', 'status'],
  auth_policies: ['policy_id', 'name', 'vdom', 'srcintf', 'srcaddr', 'dstaddr', 'active_auth_method', 'sso_auth_method', 'status'],
  interfaces: ['name', 'vdom', 'kind', 'ip', 'parent', 'members', 'role', 'status', 'mtu', 'distance', 'priority'],
  interface_topology: ['display_name', 'name', 'vdom', 'kind', 'ip', 'parent'],
  addresses: ['name', 'vdom', 'type', 'value', 'associated_interface'],
  address_groups: ['name', 'vdom', 'members', 'exclude_members'],
  address6_templates: ['name', 'vdom', 'ip6', 'subnet_segment_count'],
  wildcard_fqdns: ['name', 'vdom', 'wildcard_fqdn', 'comment'],
  local_users: ['name', 'vdom', 'type', 'status', 'two_factor', 'ldap_server', 'radius_server', 'fortitoken'],
  administrators: ['name', 'vdom', 'accprofile', 'vdoms', 'trusthosts', 'remote_auth', 'two_factor'],
  services: ['name', 'vdom', 'protocol', 'port', 'source_port'],
  service_groups: ['name', 'vdom', 'members'],
  routes: ['route_id', 'vdom', 'destination', 'gateway', 'device', 'distance', 'status'],
  policy_routes: ['seq_num', 'vdom', 'address_family', 'input_device', 'src', 'dst', 'gateway', 'output_device', 'action', 'status'],
  router_bgp: ['vdom', 'bgp_as', 'router_id', 'ebgp_multipath', 'ibgp_multipath', 'graceful_restart'],
  router_ospf: ['vdom', 'router_id', 'distance', 'abr_type', 'bfd'],
  prefix_lists: ['name', 'vdom', 'address_family', 'comments'],
  route_maps: ['name', 'vdom', 'comments'],
  nat: ['policy_id', 'policy_name', 'vdom', 'translation_type', 'egress_interfaces', 'pool_names', 'translated_addresses'],
  vips: ['name', 'vdom', 'address_family', 'extip', 'extintf', 'mappedip', 'portforward', 'extport', 'mappedport'],
  virtual_servers: ['name', 'vdom', 'extip', 'extintf', 'extport', 'server_type', 'ldb_method', 'monitor', 'status'],
  vip_groups: ['name', 'vdom', 'address_family', 'interface', 'members'],
  ip_pools: ['name', 'vdom', 'address_family', 'type', 'startip', 'endip', 'associated_interface', 'arp_reply'],
  traffic_shapers: ['name', 'vdom', 'guaranteed_bandwidth', 'maximum_bandwidth', 'bandwidth_unit', 'priority', 'per_policy'],
  ldb_monitors: ['name', 'vdom', 'type', 'port', 'interval', 'timeout', 'retry'],
  antivirus_profiles: ['name', 'vdom', 'feature_set', 'inspection_mode', 'scan_mode', 'comment'],
  webfilter_profiles: ['name', 'vdom', 'feature_set', 'inspection_mode', 'urlfilter_table', 'comment'],
  urlfilter_tables: ['id', 'name', 'vdom', 'comment'],
  dnsfilter_profiles: ['name', 'vdom', 'block_action', 'block_botnet', 'safe_search', 'comment'],
  application_lists: ['name', 'vdom', 'other_application_action', 'deep_app_inspection', 'comment'],
  file_filter_profiles: ['name', 'vdom', 'feature_set', 'log', 'scan_archive_contents', 'comment'],
  emailfilter_profiles: ['name', 'vdom', 'feature_set', 'spam_filtering', 'comment'],
  voip_profiles: ['name', 'vdom', 'feature_set', 'sip_status', 'sip_rtp', 'comment'],
  waf_profiles: ['name', 'vdom', 'extended_log', 'external', 'comment'],
  ssl_ssh_profiles: ['name', 'vdom', 'caname', 'server_cert_mode', 'ssl_exemption_ip_rating', 'comment'],
  profile_groups: ['name', 'vdom', 'av_profile', 'webfilter_profile', 'ips_sensor', 'application_list', 'ssl_ssh_profile'],
  ldap_servers: ['name', 'vdom', 'server', 'port', 'cnid', 'dn', 'secure', 'password_configured'],
  radius_servers: ['name', 'vdom', 'server', 'auth_type', 'radius_port', 'secret_configured'],
  tacacs_servers: ['name', 'vdom', 'server', 'port', 'authen_type', 'secret_configured'],
  fsso_servers: ['name', 'vdom', 'server', 'port', 'type', 'ssl', 'password_configured'],
  fortitokens: ['serial_number', 'vdom', 'status', 'license', 'seed_configured', 'comments'],
  password_policies: ['name', 'vdom', 'minimum_length', 'expire_status', 'expire_days', 'reuse_password'],
  wireless_vaps: ['name', 'vdom', 'ssid', 'security', 'vlanid', 'status', 'passphrase_configured'],
  wireless_wtps: ['wtp_id', 'name', 'vdom', 'wtp_profile', 'wtp_mode', 'admin', 'location'],
  wtp_profiles: ['name', 'vdom', 'ap_country', 'dtls_policy', 'led_state', 'comment'],
  managed_switches: ['switch_id', 'name', 'vdom', 'sn', 'switch_profile', 'owner_vdom', 'description'],
  system_global: ['hostname', 'alias', 'timezone', 'vdom_mode', 'admintimeout', 'admin_port', 'admin_sport', 'admin_ssh_port'],
  system_dns: ['vdom', 'primary', 'secondary', 'protocol', 'domain', 'dns_over_tls'],
  system_ntp: ['vdom', 'ntpsync', 'type', 'syncinterval', 'server_mode'],
  ha_config: ['mode', 'group_id', 'group_name', 'priority', 'override', 'schedule', 'monitor', 'password_configured'],
  snmp_communities: ['id', 'vdom', 'status', 'community_configured', 'events', 'vdoms'],
  snmp_users: ['name', 'vdom', 'status', 'security_level', 'auth_proto', 'auth_pwd_configured', 'priv_proto', 'priv_pwd_configured'],
  syslog_settings: ['syslog_name', 'vdom', 'status', 'server', 'mode', 'port', 'facility', 'format'],
  dhcp_servers: ['id', 'vdom', 'interface', 'status', 'default_gateway', 'netmask', 'lease_time'],
  vpn_tunnels: ['name', 'vdom', 'interface', 'remote_gateway', 'ike_version', 'proposal'],
  vpn_phase2: ['name', 'vdom', 'phase1', 'source_range', 'destination_range', 'proposal', 'pfs'],
  ssl_vpn_bookmarks: ['name', 'vdom', 'owner_name', 'apptype', 'host', 'url'],
  ssl_vpn_portals: ['name', 'vdom', 'tunnel_mode', 'web_mode', 'ip_pools', 'split_tunneling'],
  ssl_vpn_clients: ['name', 'vdom', 'interface', 'server', 'port', 'status', 'psk_configured'],
  schedules: ['name', 'vdom', 'type', 'days', 'start', 'end'],
  source_inventory: ['source_path', 'name', 'vdom', 'cli_scope', 'parent_objects', 'extraction_status', 'start_line_number', 'end_line_number'],
  extraction_coverage: ['source_path', 'status', 'source_records', 'typed_objects', 'source_only_records', 'empty_sections', 'model_gaps', 'typed_with_additional_settings'],
}
const CHECKPOINT_COLUMNS: Record<string, string[]> = {
  addresses: ['name', 'scope', 'type', 'address_family', 'ipv4_value', 'ipv4_mask_length', 'ipv4_range_end', 'ipv6_value', 'ipv6_mask_length', 'value'],
}
const PANOS_COLUMNS: Record<string, string[]> = {
  policies: ['rule_order', 'name', 'scope', 'from_zones', 'source_addresses', 'to_zones', 'destination_addresses', 'application', 'services', 'action', 'disabled'],
  default_security_rules: ['name', 'scope', 'action', 'disabled', 'log_start', 'log_end', 'profile_setting'],
  qos_rules: ['rule_order', 'name', 'scope', 'from_zones', 'to_zones', 'source', 'destination', 'application', 'qos_class', 'disabled'],
  pbf_rules: ['rule_order', 'name', 'scope', 'from_zones', 'from_interfaces', 'source', 'destination', 'action', 'egress_interface', 'nexthop', 'disabled'],
  decryption_rules: ['rule_order', 'name', 'scope', 'from_zones', 'to_zones', 'source', 'destination', 'service', 'action', 'profile', 'disabled'],
  tunnel_inspect_rules: ['rule_order', 'name', 'scope', 'from_zones', 'to_zones', 'source', 'destination', 'tunnel_protocol', 'action', 'profile'],
  app_override_rules: ['rule_order', 'name', 'scope', 'from_zones', 'to_zones', 'source', 'destination', 'protocol', 'port', 'application'],
  authentication_rules: ['rule_order', 'name', 'scope', 'from_zones', 'to_zones', 'source_user', 'authentication_enforcement', 'action', 'disabled'],
  dos_rules: ['rule_order', 'name', 'scope', 'from_zones', 'to_zones', 'source', 'destination', 'action', 'protection', 'disabled'],
  nat: ['rule_order', 'name', 'scope', 'from_zones', 'source_addresses', 'to_zones', 'destination_addresses', 'service', 'source_translation', 'destination_translation', 'dynamic_destination_translation', 'disabled'],
  interface_topology: ['name', 'scope', 'kind', 'ip', 'tag', 'zone', 'virtual_routers'],
  management_profiles: ['name', 'scope', 'protocols', 'permitted_ips'],
  interface_imports: ['name', 'scope', 'interfaces', 'virtual_routers'],
  virtual_routers: ['name', 'scope', 'interfaces', 'bgp', 'ospf', 'ecmp', 'admin_dists'],
  logical_routers: ['name', 'scope', 'vrfs'],
  addresses: ['name', 'scope', 'type', 'value', 'tags', 'description'],
  address_groups: ['name', 'scope', 'members', 'dynamic_filter', 'tags'],
  application_groups: ['name', 'scope', 'members', 'disable_override'],
  regions: ['name', 'scope', 'addresses', 'geo_location'],
  dynamic_user_groups: ['name', 'scope', 'filter', 'tags', 'description'],
  external_lists: ['name', 'scope', 'url', 'certificate_profile', 'username', 'password_configured', 'description'],
  custom_url_categories: ['name', 'scope', 'type', 'list_entries', 'description'],
  antivirus_profiles: ['name', 'scope', 'packet_capture', 'decoders', 'description'],
  anti_spyware_profiles: ['name', 'scope', 'cloud_inline_analysis', 'rules', 'description'],
  url_filtering_profiles: ['name', 'scope', 'allow', 'alert', 'block', 'safe_search_enforcement'],
  file_blocking_profiles: ['name', 'scope', 'rules', 'description'],
  wildfire_profiles: ['name', 'scope', 'rules', 'description'],
  data_filtering_profiles: ['name', 'scope', 'data_capture', 'rules', 'description'],
  dos_protection_profiles: ['name', 'scope', 'type', 'flood', 'resource', 'description'],
  decryption_profiles: ['name', 'scope', 'ssl_forward_proxy', 'ssl_inbound_proxy', 'ssl_protocol_settings'],
  log_forwarding_profiles: ['name', 'scope', 'enhanced_application_logging', 'match_list', 'description'],
  authentication_profiles: ['name', 'scope', 'user_domain', 'username_modifier', 'allow_list'],
  authentication_sequences: ['name', 'scope', 'authentication_profiles', 'use_domain_find_profile'],
  vlans: ['name', 'scope', 'virtual_interface', 'interfaces'],
  virtual_wires: ['name', 'scope', 'interface1', 'interface2', 'tag_allowed'],
  gre_tunnels: ['name', 'scope', 'tunnel_interface', 'local_address', 'peer_address', 'ttl', 'disabled'],
  dns_proxies: ['name', 'scope', 'interfaces', 'default_primary', 'default_secondary', 'cache'],
  zone_protection_profiles: ['name', 'scope', 'flood', 'scan', 'discard_ip_spoof', 'tcp_reject_non_syn'],
  monitor_profiles: ['name', 'scope', 'interval', 'threshold', 'action'],
  lldp_profiles: ['name', 'scope', 'mode', 'snmp_syslog_notification'],
  bfd_profiles: ['name', 'scope', 'mode', 'min_tx_interval', 'min_rx_interval', 'multiplier'],
  system_settings: ['hostname', 'scope', 'ip_address', 'netmask', 'default_gateway', 'timezone', 'domain', 'advanced_routing'],
  ha_configs: ['name', 'scope', 'enabled', 'mode', 'group', 'interface'],
  certificates: ['name', 'scope', 'common_name', 'ca', 'not_valid_before', 'not_valid_after', 'private_key_configured'],
  ssl_tls_service_profiles: ['name', 'scope', 'certificate', 'protocol_settings'],
  radius_server_profiles: ['name', 'scope', 'timeout', 'retries', 'servers', 'secret_configured'],
  ldap_server_profiles: ['name', 'scope', 'ldap_type', 'ssl', 'base', 'bind_dn', 'bind_password_configured', 'servers'],
  tacplus_server_profiles: ['name', 'scope', 'protocol', 'timeout', 'servers', 'secret_configured'],
  syslog_server_profiles: ['name', 'scope', 'servers'],
  email_server_profiles: ['name', 'scope', 'servers'],
  snmptrap_server_profiles: ['name', 'scope', 'version'],
  services: ['name', 'scope', 'protocol', 'port', 'source_port'],
  service_groups: ['name', 'scope', 'members'],
  schedules: ['name', 'scope', 'recurring', 'non_recurring'],
  vpn_tunnels: ['name', 'scope', 'interface', 'ike_gateways', 'ipsec_crypto_profile', 'tunnel_monitor'],
  ipsec_tunnels: ['name', 'scope', 'tunnel_interface', 'ike_gateways', 'ipsec_crypto_profile', 'tunnel_monitor'],
  vpn_phase2: ['name', 'tunnel', 'scope', 'address_family', 'local', 'remote', 'protocol', 'local_port', 'remote_port'],
  ike_gateways: ['name', 'scope', 'local_interface', 'peer_address', 'ike_version', 'authentication_method', 'pre_shared_key_configured'],
  extraction_coverage: ['domain', 'status', 'source_records', 'typed_objects', 'unknown_paths'],
  source_inventory: ['name', 'scope', 'kind', 'source_path', 'source_order', 'extraction_status', 'values'],
}
export function fieldLabel(key: string) {
  const labels: Record<string, string> = { policy_id: 'Policy ID', rule_id: 'Rule ID', route_id: 'Route ID',
    domain_id: 'Domain ID', device_id: 'Device ID', device_name: 'Device', virtual_router_name: 'Virtual Router',
    parent_policy_name: 'Parent Policy', vdom: 'VDOM', ip: 'IP / prefix', nat: 'NAT',
    ike_version: 'IKE version', vpn_tunnels: 'VPN tunnels', vpn_phase2: 'VPN phase 2',
    ssl_vpn_bookmarks: 'SSL VPN bookmarks', status: 'Reported status', review: 'Review',
    vips: 'Virtual IPs', vip_groups: 'VIP groups', ip_pools: 'IP pools', wildcard_fqdns: 'Wildcard FQDNs',
    dhcp_servers: 'DHCP servers', ssl_vpn_portals: 'SSL VPN portals',
    extip: 'External IP', extintf: 'External interface', mappedip: 'Mapped IPs',
    extport: 'External port', mappedport: 'Mapped port', startip: 'Start IP', endip: 'End IP',
    arp_reply: 'ARP reply', accprofile: 'Admin profile', trusthosts: 'Trusted hosts', vdoms: 'Allowed VDOMs',
    ipv4_value: 'IPv4 definition', ipv6_value: 'IPv6 definition', address_family: 'Address family',
    ipv4_mask_length: 'IPv4 mask length', ipv4_range_end: 'IPv4 range end', ipv6_mask_length: 'IPv6 mask length',
    rule_order: 'Rule position', source_order: 'Source inventory order', rule_uuid: 'Rule UUID',
    kind: 'Interface type', vlanid: 'VLAN ID', allowaccess: 'Management access',
    secondary_ips: 'Secondary IPs', vrf: 'VRF', issues: 'Topology issues',
    physical_interfaces: 'Underlying ports', mtu: 'MTU', tcp_mss: 'TCP MSS',
    ha_priority: 'HA priority', snmp_index: 'SNMP index', defaultgw: 'Default gateway',
    lacp_mode: 'LACP mode', lacp_speed: 'LACP speed', management_ip: 'Management IP', dhcp_relay_ip: 'DHCP relay IP',
    system_global: 'System global', system_dns: 'System DNS', system_ntp: 'System NTP',
    ha_config: 'HA configuration', snmp_sysinfo: 'SNMP sysinfo', snmp_communities: 'SNMP communities', snmp_users: 'SNMP users',
    fortiguard: 'FortiGuard', router_bgp: 'BGP router', router_ospf: 'OSPF router', router_ospf6: 'OSPFv3 router', router_rip: 'RIP router',
    policy_routes: 'Policy routes', prefix_lists: 'Prefix lists', route_maps: 'Route maps', aspath_lists: 'AS-path lists',
    community_lists: 'Community lists', router_multicast: 'Multicast router', system_ipam: 'System IPAM', fortiextenders: 'FortiExtenders',
    proxy_policies: 'Proxy policies', auth_policies: 'Authentication policies', traffic_shapers: 'Traffic shapers', ldb_monitors: 'Load balance monitors',
    virtual_servers: 'Virtual servers', antivirus_profiles: 'Antivirus profiles', webfilter_profiles: 'Web filter profiles',
    urlfilter_tables: 'URL filter tables', dnsfilter_profiles: 'DNS filter profiles', application_lists: 'Application lists',
    file_filter_profiles: 'File filter profiles', emailfilter_profiles: 'Email filter profiles', voip_profiles: 'VoIP profiles',
    waf_profiles: 'WAF profiles', ssl_ssh_profiles: 'SSL/SSH inspection', ldap_servers: 'LDAP servers', radius_servers: 'RADIUS servers',
    tacacs_servers: 'TACACS+ servers', fsso_servers: 'FSSO servers', fsso_pollings: 'FSSO polling', fortitokens: 'FortiTokens',
    wireless_vaps: 'WiFi SSIDs (VAP)', wireless_wtps: 'Managed FortiAPs', wtp_profiles: 'FortiAP profiles', wids_profiles: 'WIDS profiles',
    managed_switches: 'Managed FortiSwitches', syslog_settings: 'Syslog settings', log_settings: 'Log settings',
    qos_rules: 'QoS policies', pbf_rules: 'PBF rules', decryption_rules: 'Decryption policies',
    tunnel_inspect_rules: 'Tunnel inspection', app_override_rules: 'Application override', authentication_rules: 'Authentication policies', dos_rules: 'DoS policies',
    dynamic_user_groups: 'Dynamic user groups', external_lists: 'External dynamic lists', custom_url_categories: 'Custom URL categories',
    anti_spyware_profiles: 'Anti-Spyware profiles', url_filtering_profiles: 'URL Filtering profiles', file_blocking_profiles: 'File Blocking profiles',
    wildfire_profiles: 'WildFire profiles', data_filtering_profiles: 'Data Filtering profiles', dos_protection_profiles: 'DoS Protection profiles',
    decryption_profiles: 'Decryption profiles', log_forwarding_profiles: 'Log Forwarding profiles',
    virtual_wires: 'Virtual wires', gre_tunnels: 'GRE tunnels', dns_proxies: 'DNS proxies',
    zone_protection_profiles: 'Zone Protection profiles', lldp_profiles: 'LLDP profiles', bfd_profiles: 'BFD profiles',
    ssl_tls_service_profiles: 'SSL/TLS service profiles', radius_server_profiles: 'RADIUS server profiles', ldap_server_profiles: 'LDAP server profiles',
    tacplus_server_profiles: ['TACACS+ server profiles'][0], syslog_server_profiles: 'Syslog server profiles',
    email_server_profiles: 'Email server profiles', snmptrap_server_profiles: 'SNMP trap profiles', http_server_profiles: 'HTTP server profiles',
    extraction_coverage: 'Extraction coverage', source_inventory: 'Source inventory' }
  return labels[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}
export function columnWidth(key: string) {
  if (['policy_id', 'rule_id', 'route_id', 'position', 'sequence', 'action', 'status', 'vdom', 'scope', 'distance', 'pfs', 'nat'].includes(key)) return 'short'
  if (['name', 'policy_name', 'display_name'].includes(key)) return 'identity'
  return 'content'
}

const MONO_COLUMNS = new Set([
  'ip', 'value', 'ipv4_value', 'ipv6_value', 'destination', 'gateway', 'remote_gateway',
  'extip', 'mappedip', 'startip', 'endip', 'port', 'source_port', 'extport', 'mappedport',
  'vlanid', 'tag', 'rule_uuid', 'source_path', 'local', 'remote', 'peer_address', 'peer',
  'policy_id', 'rule_id', 'route_id', 'rule_order', 'source_order', 'start_line_number', 'end_line_number',
])

export function isMonoColumn(key: string): boolean {
  return MONO_COLUMNS.has(key.toLowerCase())
}

export function cellBadgeVariant(key: string, value: unknown): 'allow' | 'deny' | 'warn' | 'info' | 'purple' | 'muted' | null {
  if (value == null || typeof value === 'object') return null
  const col = key.toLowerCase()
  const val = String(value).trim().toLowerCase()
  if (!val) return null

  if (col === 'action') {
    if (val === 'accept' || val === 'allow' || val === 'pass' || val === 'exempt' || val === ' trust') return 'allow'
    if (val === 'deny' || val === 'drop' || val === 'block' || val.startsWith('reset') || val === 'reject') return 'deny'
    if (val === 'alert' || val === 'warning' || val === 'monitor' || val === 'authenticate') return 'warn'
  }
  if (col === 'status' || col === 'extraction_status') {
    if (val === 'enable' || val === 'enabled' || val === 'up' || val === 'online' || val === 'true' || val === 'typed' || val === 'complete' || val === 'success') return 'allow'
    if (val === 'disable' || val === 'disabled' || val === 'down' || val === 'offline' || val === 'false' || val === 'failed') return 'deny'
    if (val === 'partial' || val === 'source_only' || val === 'warning' || val === 'model_gap') return 'warn'
  }
  if (col === 'disabled') {
    if (val === 'yes' || val === 'true') return 'deny'
    if (val === 'no' || val === 'false') return 'allow'
  }
  if (col === 'kind' || col === 'type' || col === 'role') {
    if (val === 'zone') return 'muted'
    if (val.includes('vlan') || val.includes('sub') || val === 'tunnel' || val === 'loopback') return 'purple'
    if (val.includes('switch') || val === 'aggregate' || val === 'redundant' || val === 'ae') return 'info'
  }
  return null
}

export function rowSemanticClass(row: ReportRow, subsection = ''): string {
  const status = String(row.status ?? '').trim().toLowerCase()
  const disabled = String(row.disabled ?? '').trim().toLowerCase()
  const action = String(row.action ?? '').trim().toLowerCase()
  const kind = String(row.kind ?? row.type ?? '').trim().toLowerCase()
  const extraction = String(row.extraction_status ?? '').trim().toUpperCase()

  if (status === 'disable' || status === 'disabled' || row.status === false || disabled === 'yes' || row.disabled === true) {
    return 'row-danger'
  }
  if (action === 'deny' || action === 'drop' || action === 'block' || action.startsWith('reset')) {
    return 'row-danger'
  }
  if ((Array.isArray(row.issues) && row.issues.length > 0) || extraction === 'PARTIAL' || extraction === 'SOURCE_ONLY') {
    return 'row-warn'
  }
  if (subsection === 'interfaces' || subsection === 'interface_topology') {
    if (kind === 'zone') return 'row-zone'
    if (kind.includes('switch') || kind === 'aggregate' || kind === 'redundant' || kind === 'ae') return 'row-info'
    if (kind.includes('vlan') || kind.includes('sub') || kind === 'tunnel' || row.vlanid != null || row.tag != null) return 'row-sub'
  }
  if (action === 'accept' || action === 'allow' || action === 'pass' || action === 'exempt') {
    return 'row-success'
  }
  return ''
}

export function sectionLegend(subsection: string, rows: ReportRow[]): Array<{ label: string; variant: string }> {
  if (!rows.length) return []
  const sub = subsection.toLowerCase()
  if (sub === 'interfaces' || sub === 'interface_topology') {
    return [
      { label: 'Zone', variant: 'muted' },
      { label: 'Switch / Aggregate', variant: 'info' },
      { label: 'VLAN / Tunnel / Sub-interface', variant: 'purple' },
      { label: 'Topology Issue', variant: 'warn' },
      { label: 'Disabled', variant: 'danger' },
    ]
  }
  if (sub.includes('polic') || sub.includes('rule')) {
    return [
      { label: 'Allow / Accept', variant: 'success' },
      { label: 'Deny / Drop / Disabled', variant: 'danger' },
    ]
  }
  if (sub === 'source_inventory' || sub === 'extraction_coverage') {
    return [
      { label: 'Typed / Complete', variant: 'success' },
      { label: 'Source-Only / Partial', variant: 'warn' },
    ]
  }
  const hasDanger = rows.some((r) => rowSemanticClass(r, subsection) === 'row-danger')
  const hasWarn = rows.some((r) => rowSemanticClass(r, subsection) === 'row-warn')
  const items: Array<{ label: string; variant: string }> = []
  if (hasWarn) items.push({ label: 'Attention / Partial', variant: 'warn' })
  if (hasDanger) items.push({ label: 'Disabled / Blocked', variant: 'danger' })
  return items
}
export function rowColumns(rows: ReportRow[], subsection = '', vendor = '') {
  const seen = new Set<string>()
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (
        seen.has(key)
        || key === 'Source section'
        || key === 'review'
        || key === 'unset_fields'
        || (subsection === 'interface_topology' && key === 'display_name')
        || (vendor === 'palo_alto' && key === 'policy_id')
        || (subsection !== 'source_inventory' && (key === 'cli_vdom' || key === 'cli_scope'))
        || sensitiveKey(key, row[key])
      ) continue
      seen.add(key)
    }
  }
  const keys = [...seen]
  if (!keys.length && rows.length) return ['Source section']
  const identity = vendor === 'palo_alto' && PANOS_COLUMNS[subsection] || (subsection === 'interface_topology'
    ? ['name', 'display_name', 'vdom', 'domain_id', 'device_name', 'device_id', 'scope', 'kind', 'role', 'ip', 'vlanid', 'zone', 'virtual_routers', 'vrf', 'status', 'issues', 'prefix', 'parent', 'members', 'aggregate', 'physical_interfaces', 'path', 'topology_path']
    : vendor === 'fortigate' && FORTIGATE_COLUMNS[subsection]
      || vendor === 'cisco_ftd' && CISCO_FTD_COLUMNS[subsection]
      || vendor === 'checkpoint' && CHECKPOINT_COLUMNS[subsection]
      || ['name', 'policy_id', 'rule_id', 'route_id', 'display_name', 'policy_name', 'domain_id', 'device_name', 'device_id', 'vdom', 'scope'])
  return [...identity.filter((key) => keys.includes(key)), ...keys.filter((key) => !identity.includes(key))]
}
const INTERFACE_DEFAULT_COLUMNS = new Set([
  'name', 'vdom', 'domain_id', 'device_name', 'device_id', 'scope',
  'kind', 'role', 'ip', 'vlanid', 'zone', 'virtual_routers', 'vrf', 'status', 'issues',
])
export function defaultColumns(rows: ReportRow[], subsection = '', vendor = '', precomputedColumns?: string[]) {
  const columns = precomputedColumns ?? rowColumns(rows, subsection, vendor)
  if (vendor === 'palo_alto' && PANOS_COLUMNS[subsection]) return columns.filter((key) => PANOS_COLUMNS[subsection].includes(key))
  if (subsection === 'interface_topology') return columns.filter((key) => INTERFACE_DEFAULT_COLUMNS.has(key))
  const preferred = vendor === 'fortigate' ? FORTIGATE_COLUMNS[subsection]
    : vendor === 'cisco_ftd' ? CISCO_FTD_COLUMNS[subsection]
    : vendor === 'checkpoint' ? CHECKPOINT_COLUMNS[subsection]
    : undefined
  const selected = preferred ? columns.filter((key) => preferred.includes(key)) : []
  return selected.length ? selected : columns.slice(0, 8)
}
export function cellSummary(value: unknown): string {
  if (value == null) return 'Not reported'
  if (typeof value !== 'object') return compactValue(value)
  if (Array.isArray(value)) {
    const defined: unknown[] = []
    for (const item of value) {
      if (item !== undefined) defined.push(item)
    }
    if (!defined.length) return '(empty list)'
    const shown = defined.slice(0, 2).map((item) => {
      if (item !== null && typeof item === 'object') return compactValue(safeValue(item))
      return cellSummary(item)
    })
    return `${shown.join(', ')}${defined.length > 2 ? ` +${defined.length - 2} more` : ''}`
  }
  return compactValue(safeValue(value))
}
export function cellTooltip(value: unknown, summaryText: string): string {
  if (value == null) return 'This value was not reported. No default is inferred. See details for the exact value.'
  if (Array.isArray(value) && value.length > 2) {
    const defined = value.filter((item) => item !== undefined)
    if (defined.length > 2) {
      const limit = 25
      const shown = defined.slice(0, limit).map((item) => (item !== null && typeof item === 'object' ? compactValue(safeValue(item)) : cellSummary(item)))
      return `${shown.join(', ')}${defined.length > limit ? ` (+${defined.length - limit} more — open Details)` : ''}`
    }
  }
  return summaryText
}
const FORTIGATE_DETAILS: Record<string, Array<[string, string[]]>> = {
  policies: [
    ['Source', ['source_interfaces', 'source_addresses', 'source_addresses_ipv6', 'source_address_negate_ipv6']],
    ['Destination', ['destination_interfaces', 'destination_addresses', 'destination_addresses_ipv6', 'destination_address_negate_ipv6']],
    ['Services and schedule', ['services', 'schedule']],
    ['Authentication', ['groups', 'users']],
    ['Inspection', ['utm_status', 'inspection_mode', 'profile_type', 'profile_group', 'av_profile', 'ips_sensor', 'webfilter_profile', 'dnsfilter_profile', 'application_list', 'ssl_ssh_profile']],
    ['Logging', ['logtraffic', 'comments']],
    ['Reported action/settings', ['action', 'status', 'nat', 'per_ip_shaper', 'profile_protocol_options']],
  ],
  interfaces: [
    ['Addressing', ['ip', 'secondary_ips', 'management_ip', 'dhcp_relay_ip', 'dhcp_renew_time', 'defaultgw']],
    ['Topology', ['kind', 'type', 'parent', 'members', 'aggregate', 'physical_interfaces', 'topology_path', 'lacp_mode', 'lacp_speed', 'aggregate_type', 'min_links']],
    ['Routing & Link', ['mtu', 'tcp_mss', 'distance', 'priority', 'ha_priority', 'weight', 'snmp_index', 'link_up_delay', 'link_down_delay', 'vrf', 'vlanid']],
    ['Reported settings', ['role', 'status', 'allowaccess', 'mode', 'alias', 'description', 'review']],
  ],
  administrators: [
    ['Identity & Access', ['name', 'vdom', 'accprofile', 'accprofile_override', 'vdoms', 'trusthosts', 'ip6_trusthosts', 'schedule']],
    ['Authentication', ['remote_auth', 'remote_group', 'peer_auth', 'peer_group', 'two_factor', 'two_factor_authentication', 'two_factor_notification', 'fortitoken', 'email_to', 'sms_phone', 'sms_server', 'sms_custom_server', 'ssh_certificate', 'guest_auth', 'guest_usergroups', 'ssh_key_configured', 'password_configured']],
    ['Reported settings', ['comments', 'review']],
  ],
  interface_topology: [['Addressing', ['ip']], ['Derived topology', ['kind', 'type', 'parent', 'members', 'aggregate', 'physical_interfaces', 'topology_path']], ['Reported settings', ['role', 'status', 'review']]],
  addresses: [['Address definition', ['type', 'value', 'address_family', 'associated_interface']], ['Reported settings', ['comment', 'review']]],
  address_groups: [['Membership', ['members', 'exclude_members', 'address_family']], ['Reported settings', ['comment', 'review']]],
  service_groups: [['Membership', ['members']], ['Reported settings', ['generated', 'comment', 'review']]],
  services: [['Protocol and ports', ['protocol', 'protocol_number', 'port', 'source_port', 'icmp_code', 'icmp_type']], ['Reported settings', ['generated', 'comment', 'review']]],
  routes: [['Routing', ['address_family', 'destination', 'destination_address', 'gateway', 'device', 'distance', 'priority']], ['Reported settings', ['status', 'review']]],
  nat: [['Translation', ['translation_type', 'egress_interfaces', 'pool_names', 'translated_addresses']], ['Reported settings', ['review']]],
  vpn_tunnels: [['Endpoints', ['interface', 'remote_gateway', 'physical_interfaces', 'topology_path', 'aggregate']], ['Reported protection', ['ike_version', 'proposal', 'type', 'review']]],
  vpn_phase2: [['Selectors', ['phase1', 'source_range', 'source_range6', 'destination_range', 'destination_range6']], ['Reported protection', ['proposal', 'pfs', 'dh_groups', 'review']]],
}
export function detailGroups(row: ReportRow, subsection = '', vendor = '') {
  const definitions: Array<[string, string[]]> = [
    ['Identity', ['name', 'policy_id', 'rule_id', 'rule_uuid', 'rule_order', 'source_order', 'source_id', 'route_id', 'policy_name', 'display_name', 'object_name', 'source_name', 'vdom', 'scope', 'Source section']],
    ...(vendor === 'cisco_ftd' ? [['Source scope', ['source_context', 'domain_id', 'device_id', 'device_name',
        'virtual_router_id', 'virtual_router_name', 'parent_policy_id', 'parent_policy_name']]] as Array<[string, string[]]> : []),
    ...(vendor === 'fortigate' && FORTIGATE_DETAILS[subsection] || [['Reported fields', defaultColumns([row], subsection, vendor)]] as Array<[string, string[]]>),
    ['Additional fields', Object.keys(row)],
  ]
  const used = new Set<string>()
  const empty: Array<[string, unknown]> = []
  const groups = definitions.map(([title, keys]) => ({ title, fields: keys.flatMap((key): Array<[string, unknown]> => {
    if (used.has(key) || !Object.hasOwn(row, key) || sensitiveKey(key, row[key]) || (vendor === 'palo_alto' && key === 'policy_id')) return []
    used.add(key)
    const value = safeValue(row[key], key)
    if (value == null || value === '' || (typeof value === 'object' && Object.keys(value).length === 0)) { empty.push([key, value]); return [] }
    return [[key, value]]
  }) })).filter((group) => group.fields.length)
  if (empty.length) groups.push({ title: 'Empty / not reported fields', fields: empty })
  return groups
}
export function findingGroupKey(row: ReportRow) {
  return JSON.stringify([row.severity, row.domain, row.field, row.message])
}
export function findingGroups(rows: ReportRow[]) {
  const groups = new Map<string, { key: string; row: ReportRow; count: number }>()
  for (const row of rows) {
    const key = findingGroupKey(row)
    const group = groups.get(key) ?? { key, row, count: 0 }
    group.count++
    groups.set(key, group)
  }
  const rank = (row: ReportRow) => String(row.severity).toLowerCase() === 'error' ? 0 : String(row.severity).toLowerCase() === 'warning' ? 1 : 2
  return [...groups.values()].sort((a, b) => rank(a.row) - rank(b.row) || b.count - a.count)
}

export function activeSubsection(subsections: Array<{ key: string; rows: ReportRow[] }>, requested: string) {
  return subsections.find((item) => item.key === requested) ?? subsections.find((item) => item.rows.length > 0) ?? subsections[0]
}

export function matchingSourceRows(rows: ReportRow[], finding: ReportRow) {
  if (Array.isArray(finding.source_identity) && finding.source_identity.length) {
    const identity = JSON.stringify(finding.source_identity)
    return rows.filter((row) => JSON.stringify(row.source_identity) === identity)
  }
  const scope = finding.scope ?? finding.vdom
  const stableIds = [finding.source_id, finding.rule_id].filter((value) => value != null).map(String)
  const findingNames = [finding.object_name, finding.policy_id,
    String(finding.object_name ?? '').replace(/^policy\s+/i, '')].filter((value) => value != null).map(String)
  return rows.filter((row) => {
    const rowIds = [row.source_id, row.rule_id].filter((value) => value != null).map(String)
    const names = [row.name, row.display_name, row.object_name, row.policy_name, row.policy_id,
      row.source_policy_id, row.route_id].filter((value) => value != null).map(String)
    const identityMatches = stableIds.length
      ? stableIds.some((id) => rowIds.includes(id))
      : findingNames.some((name) => names.includes(name))
    return identityMatches && (scope == null || (row.scope ?? row.vdom) === scope)
  })
}
