export type ReportRow = Record<string, unknown>

export const SENSITIVE_KEY = /raw_extra|password(?!_configured$)|secret(?!_configured$)|credential|token|private.?key(?!_configured$)|psk(?!_configured$)/i
export function asRecord(value: unknown): ReportRow {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as ReportRow : {}
}
export function asRows(value: unknown): ReportRow[] {
  return Array.isArray(value) ? value.filter((row): row is ReportRow => row !== null && typeof row === 'object' && !Array.isArray(row)) : []
}
export function safeValue(value: unknown, key = ''): unknown {
  if (SENSITIVE_KEY.test(key)) return undefined
  if (Array.isArray(value)) return value.map((item) => safeValue(item)).filter((item) => item !== undefined)
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .filter(([name]) => !SENSITIVE_KEY.test(name)).map(([name, item]) => [name, safeValue(item, name)]))
  return value
}

// Rows remain immutable for the lifetime of a source preview.
const reportSearchIndex = new WeakMap<ReportRow, string>()
export function reportSearchText(row: ReportRow): string {
  const cached = reportSearchIndex.get(row)
  if (cached !== undefined) return cached
  const text = JSON.stringify(safeValue(row)).toLowerCase()
  reportSearchIndex.set(row, text)
  return text
}

const SECTION_KEYS: Record<string, string[]> = {
  Interfaces: ['interfaces', 'interface_topology'],
  Objects: ['addresses', 'addresses_ipv6', 'address_groups', 'services', 'service_groups', 'network_objects', 'network_groups', 'protocol_port_objects', 'applications', 'zones', 'vulnerability_profiles', 'local_users', 'local_user_groups', 'group_mappings'],
  Schedules: ['schedules', 'schedule_groups', 'time_ranges'],
  Policies: ['policies', 'security_policies', 'security_rules', 'access_control_policies', 'access_rules', 'nac_policies', 'sdwan_rules'],
  NAT: ['nat', 'nat_rules', 'translations', 'central_snat', 'vips', 'ip_pools'],
  Routes: ['routes', 'static_routes', 'routing_instances'],
  VPN: ['vpn_tunnels', 'vpn_phase2', 'policy_vpn_phase1', 'policy_vpn_phase2', 'ssl_vpn_realms', 'ssl_vpn_bookmarks', 'ike_gateways', 'ipsec_tunnels', 'globalprotect_portals', 'globalprotect_gateways'],
  References: ['unresolved_references', 'references', 'relationships'],
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
  return topology.map((row) => {
    if (row.name == null) return row
    const rowScope = row.vdom ?? row.scope
    const topologyNameRows = topology.filter((item) => item.name === row.name)
    const inventoryNameRows = inventory.filter((item) => item.name === row.name)
    const matches = inventory.filter((item) => {
      if (item.name !== row.name) return false
      const itemScope = item.vdom ?? item.scope
      if (rowScope != null && itemScope != null) return rowScope === itemScope
      return topologyNameRows.length === 1 && inventoryNameRows.length === 1
    })
    if (matches.length !== 1) return row
    return { ...row, ...Object.fromEntries(Object.entries(matches[0]).filter(([key]) => key !== 'Source section')), 'Source section': row['Source section'] }
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
  policies: ['policy_id', 'name', 'vdom', 'source_interfaces', 'source_addresses', 'destination_interfaces', 'destination_addresses', 'services', 'action', 'status'],
  interfaces: ['name', 'vdom', 'kind', 'ip', 'parent', 'members', 'role', 'status'],
  interface_topology: ['display_name', 'name', 'vdom', 'kind', 'ip', 'parent', 'physical_interfaces'],
  addresses: ['name', 'vdom', 'type', 'value', 'associated_interface', 'review'],
  address_groups: ['name', 'vdom', 'members', 'exclude_members', 'review'],
  services: ['name', 'vdom', 'protocol', 'port', 'source_port', 'review'],
  service_groups: ['name', 'vdom', 'members', 'review'],
  routes: ['route_id', 'vdom', 'destination', 'gateway', 'device', 'distance', 'status'],
  nat: ['policy_id', 'policy_name', 'vdom', 'translation_type', 'egress_interfaces', 'pool_names', 'translated_addresses', 'review'],
  vpn_tunnels: ['name', 'vdom', 'interface', 'remote_gateway', 'ike_version', 'proposal', 'review'],
  vpn_phase2: ['name', 'vdom', 'phase1', 'source_range', 'destination_range', 'proposal', 'pfs', 'review'],
  ssl_vpn_bookmarks: ['name', 'vdom', 'owner_name', 'apptype', 'host', 'url'],
  schedules: ['name', 'vdom', 'type', 'days', 'start', 'end'],
}
export function fieldLabel(key: string) {
  const labels: Record<string, string> = { policy_id: 'Policy ID', rule_id: 'Rule ID', route_id: 'Route ID',
    domain_id: 'Domain ID', device_id: 'Device ID', device_name: 'Device', virtual_router_name: 'Virtual Router',
    parent_policy_name: 'Parent Policy', vdom: 'VDOM', ip: 'IP / prefix', nat: 'NAT',
    ike_version: 'IKE version', vpn_tunnels: 'VPN tunnels', vpn_phase2: 'VPN phase 2',
    ssl_vpn_bookmarks: 'SSL VPN bookmarks', status: 'Reported status', review: 'Review' }
  return labels[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}
export function columnWidth(key: string) {
  if (['policy_id', 'route_id', 'action', 'status', 'vdom', 'scope', 'distance', 'pfs', 'nat'].includes(key)) return 'short'
  if (['name', 'policy_name', 'display_name'].includes(key)) return 'identity'
  return 'content'
}
export function rowColumns(rows: ReportRow[], subsection = '', vendor = '') {
  const keys = [...new Set(rows.flatMap(Object.keys))].filter((key) => key !== 'Source section' && !(subsection === 'interface_topology' && key === 'display_name') && !SENSITIVE_KEY.test(key))
  if (!keys.length && rows.length) return ['Source section']
  const identity = subsection === 'interface_topology'
    ? ['name', 'display_name', 'vdom', 'domain_id', 'device_name', 'device_id', 'scope', 'kind', 'ip', 'prefix', 'parent', 'members', 'aggregate', 'physical_interfaces', 'path', 'topology_path', 'issues']
    : vendor === 'fortigate' && FORTIGATE_COLUMNS[subsection]
      || vendor === 'cisco_ftd' && CISCO_FTD_COLUMNS[subsection]
      || ['name', 'policy_id', 'rule_id', 'route_id', 'display_name', 'policy_name', 'domain_id', 'device_name', 'device_id', 'vdom', 'scope']
  return [...identity.filter((key) => keys.includes(key)), ...keys.filter((key) => !identity.includes(key))]
}
export function defaultColumns(rows: ReportRow[], subsection = '', vendor = '') {
  const columns = rowColumns(rows, subsection, vendor)
  if (subsection === 'interface_topology') return columns.filter((key) => !['type', 'parent', 'members', 'aggregate', 'path', 'topology_path'].includes(key))
  const preferred = vendor === 'fortigate' ? FORTIGATE_COLUMNS[subsection]
    : vendor === 'cisco_ftd' ? CISCO_FTD_COLUMNS[subsection]
    : undefined
  const selected = preferred ? columns.filter((key) => preferred.includes(key)) : []
  return selected.length ? selected : columns.slice(0, 8)
}
export function cellSummary(value: unknown): string {
  const safe = safeValue(value)
  if (safe == null) return 'Not reported'
  if (Array.isArray(safe) && safe.length) {
    const shown = safe.slice(0, 2).map((item) => Array.isArray(item) || (item !== null && typeof item === 'object') ? compactValue(item) : cellSummary(item))
    return `${shown.join(', ')}${safe.length > 2 ? ` +${safe.length - 2} more` : ''}`
  }
  return compactValue(safe)
}
const FORTIGATE_DETAILS: Record<string, Array<[string, string[]]>> = {
  policies: [
    ['Source', ['source_interfaces', 'source_addresses', 'source_addresses_ipv6', 'source_address_negate_ipv6']],
    ['Destination', ['destination_interfaces', 'destination_addresses', 'destination_addresses_ipv6', 'destination_address_negate_ipv6']],
    ['Services and schedule', ['services', 'schedule']],
    ['Reported action/settings', ['action', 'status', 'nat', 'per_ip_shaper', 'profile_protocol_options']],
  ],
  interfaces: [['Addressing', ['ip']], ['Topology', ['kind', 'type', 'parent', 'members', 'aggregate', 'physical_interfaces', 'topology_path']], ['Reported settings', ['role', 'status', 'review']]],
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
    ['Identity', ['name', 'policy_id', 'rule_id', 'source_id', 'route_id', 'policy_name', 'display_name', 'object_name', 'source_name', 'vdom', 'scope', 'Source section']],
    ...(vendor === 'cisco_ftd' ? [['Source scope', ['source_context', 'domain_id', 'device_id', 'device_name',
        'virtual_router_id', 'virtual_router_name', 'parent_policy_id', 'parent_policy_name']]] as Array<[string, string[]]> : []),
    ...(vendor === 'fortigate' && FORTIGATE_DETAILS[subsection] || [['Reported fields', defaultColumns([row], subsection, vendor)]] as Array<[string, string[]]>),
    ['Additional fields', Object.keys(row)],
  ]
  const used = new Set<string>()
  const empty: Array<[string, unknown]> = []
  const groups = definitions.map(([title, keys]) => ({ title, fields: keys.flatMap((key): Array<[string, unknown]> => {
    if (used.has(key) || !Object.hasOwn(row, key) || SENSITIVE_KEY.test(key)) return []
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
