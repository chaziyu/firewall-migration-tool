import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/report/reportPresentation.ts'
import { activeSubsection, interfaceTopologyRows, matchingSourceRows, reportSections, reportSectionRowCount, reportCounts, reportSearchText, compactValue, rowColumns, safeValue, defaultColumns, cellSummary, detailGroups, findingGroups, findingGroupKey, fieldLabel } from '../src/features/report/reportPresentation.ts'

test('configuration summary renders each count once, preserves missing and zero values, and keeps informational rows plain', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { SourceReport } = await server.ssrLoadModule('/src/features/report/SourceReport.tsx')
    const render = (data) => renderToStaticMarkup(createElement(SourceReport, {
      data, excelProfile: 'fast', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {},
    }))
    const data = { vendor: 'fortigate', summary: { objects: { policies: 1724, interfaces: 83, addresses: 6000, address_groups: 100, services: 100, service_groups: 56 }, unsupported_count: 2 }, sections: { schedules: [], nat: [{}, {}], routes: [{}], vpn_tunnels: [{}], unresolved_references: [] } }
    const before = structuredClone(data)
    const html = render(data)
    const table = html.match(/<table class="configuration-summary"[\s\S]*?<\/table>/)[0]
    const rows = [...table.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/g)].slice(1).map((match) => match[1])
    const labels = ['Policies', 'Address/service objects', 'Interfaces', 'Schedules', 'NAT', 'Routes', 'VPN', 'Unresolved references', 'Unsupported / source-only']
    const values = [1724, 6256, 83, 0, 2, 1, 1, 0, 2]
    assert.equal(rows.length, labels.length)
    rows.forEach((row, index) => {
      assert.ok(row.includes(`>${labels[index]}<`))
      assert.ok(row.includes(`<td>${values[index].toLocaleString()}</td>`))
      assert.equal(row.includes('<button'), index < 8)
      assert.equal(row.includes('›'), index < 8)
    })
    assert.match(html, /<summary>About these counts<\/summary>/)
    assert.ok(!table.includes('Review findings'))
    assert.ok(!table.includes('configuration-summary-warning'))
    const missing = render({ vendor: 'fortigate' })
    const missingTable = missing.match(/<table class="configuration-summary"[\s\S]*?<\/table>/)[0]
    assert.equal((missingTable.match(/Not reported/g) ?? []).length, 7)
    assert.ok(!missingTable.includes('Unresolved references'))
    assert.ok(!missingTable.includes('Unsupported / source-only'))
    assert.match(render({ vendor: 'fortigate', sections: { unresolved_references: [{}] } }), /class="configuration-summary-warning"/)
    assert.deepEqual(data, before)
    const { SourceOverview } = await server.ssrLoadModule('/src/features/source/SourceOverview.tsx')
    for (const count of [0, 1, 2]) {
      const sections = { validation: ['error', 'warning'].flatMap((severity) => Array.from({ length: count }, (_, index) => ({ severity, message: `${severity}-${index}` }))) }
      const label = `${count} ${count === 1 ? 'error' : 'errors'} · ${count} ${count === 1 ? 'warning' : 'warnings'}`
      assert.ok(render({ vendor: 'fortigate', sections }).includes(`${label} <small>`))
      assert.ok(render({ vendor: 'fortigate', sections }).includes(`${count} warning ${count === 1 ? 'group' : 'groups'}</small>`))
      const overview = renderToStaticMarkup(createElement(SourceOverview, { vendor: 'fortigate', vendorName: 'FortiGate', file: null, preview: { sections } }))
      assert.ok(overview.includes(`${label}</span>`))
    }
    assert.match(missing, /report-validation-attention[^]*?Not reported/)
  } finally {
    await server.close()
  }
})

test('summary buttons retain their section and subsection destinations', () => {
  const slots = []
  let cursor = 0
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) slots[index] = initial
      return [slots[index], (value) => { slots[index] = typeof value === 'function' ? value(slots[index]) : value }]
    },
    useMemo: (factory) => factory(),
    useRef: () => ({ current: null }),
    useEffect() {},
  }
  const source = readFileSync(new URL('../src/features/report/SourceReport.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const exports = {}
  const modules = { react: hooks, 'react/jsx-runtime': jsxRuntime, './reportPresentation': presentation, './ReportDetails': {}, './ExcelExportControls': {}, '../../components/common/tabKeyboard': {}, '../../components/common/ErrorBanner': {} }
  new Function('require', 'exports', compiled)((name) => { assert.ok(name in modules); return modules[name] }, exports)
  function nodes(node) {
    if (Array.isArray(node)) return node.flatMap(nodes)
    return node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : []
  }
  const data = { sections: { addresses: [], address_groups: [{}], interfaces: [{}], unresolved_references: [] } }
  function render() {
    cursor = 0
    return nodes(exports.SourceReport({ data, excelProfile: 'fast', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {} }))
  }
  for (const [label, section, subsection] of [
    ['Policies', 'Policies'], ['Address/service objects', 'Objects', 'addresses'], ['Interfaces', 'Interfaces', 'interface_topology'],
    ['Schedules', 'Schedules'], ['NAT', 'NAT'], ['Routes', 'Routes'], ['VPN', 'VPN'], ['Unresolved references', 'References'],
  ]) {
    const tree = render()
    tree.find((node) => node.type === 'button' && node.props.children === label).props.onClick()
    const next = render()
    assert.ok(next.some((node) => node.props.role === 'tab' && node.props.children === section && node.props['aria-selected']))
    if (subsection) assert.ok(next.some((node) => node.props.id === `subsection-tab-${subsection}` && node.props['aria-selected']))
    next.find((node) => node.props.role === 'tab' && node.props.children === 'Overview').props.onClick()
  }
})

test('each section is reachable once; inventory, topology, plural policies, and VPN retain their boundaries', () => {
  const sections = { policies: [{ policy_id: 1 }, { policy_id: 1 }], security_policies: [], interfaces: [{ name: 'same', vdom: 'a' }, { name: 'same', vdom: 'b' }], interface_topology: [{ name: 'same' }], policy_vpn_phase1: [{}], unknown_section: [null, 'unsupported', { unknown: [] }], metadata: { complete: false }, validation: [] }
  const groups = reportSections(sections)
  assert.deepEqual(groups.flatMap((group) => group.subsections.map((section) => section.key)).sort(), Object.keys(sections).filter((key) => key !== 'validation').sort())
  assert.equal(groups.find((group) => group.label === 'Policies').rows.length, 2)
  const interfaces = groups.find((group) => group.label === 'Interfaces')
  assert.equal(reportSectionRowCount(interfaces), 2)
  assert.deepEqual(interfaces.subsections.map((item) => item.key), ['interfaces', 'interface_topology'])
  assert.equal(interfaces.subsections[1].rows.length, 1)
  assert.equal(groups.some((group) => group.label === 'Topology'), false)
  assert.equal(groups.find((group) => group.label === 'VPN').rows.length, 1)
  assert.equal(groups.find((group) => group.label === 'Additional sections').rows.length, 4)
  assert.equal(groups.find((group) => group.label === 'Interfaces').rows[1].vdom, 'b')
  assert.deepEqual(reportSections({ 'Security Policies': [] })[0].label, 'Policies')
})

test('combined interface views retain separate rows and counts, including empty and missing inventory', () => {
  const sections = { interface_topology: [{ name: 'same', kind: 'physical', vdom: 'a' }, { name: 'vpn', kind: 'vpn', vdom: 'a' }], interfaces: [{ name: 'same', vdom: 'a', status: false }] }
  const before = structuredClone(sections)
  const [group] = reportSections(sections)
  assert.equal(group.label, 'Interfaces')
  assert.equal(reportSectionRowCount(group), 1)
  assert.equal(group.subsections[1].rows.length, 2)
  assert.equal(activeSubsection(group.subsections, '').key, 'interfaces')
  assert.equal(activeSubsection(group.subsections, 'interface_topology').rows[1].kind, 'vpn')
  assert.equal(group.subsections[0].rows[0].status, false)
  assert.equal(reportSectionRowCount(reportSections({ interfaces: [], interface_topology: sections.interface_topology })[0]), 0)
  assert.equal(reportSectionRowCount(reportSections({ interface_topology: sections.interface_topology })[0]), null)
  assert.equal(reportSectionRowCount(undefined), null)
  assert.equal(reportSectionRowCount(reportSections({ 'Interface Topology': [], Interfaces: [] })[0]), 0)
  assert.equal(reportSectionRowCount(reportSections({ routes: [{}] })[0]), 1)
  assert.deepEqual(sections, before)
})

test('FortiGate source sections are reachable with useful columns and preserve scope and missing values', () => {
  const sections = {
    vips: [{ name: 'public', vdom: 'branch', extip: '198.51.100.10', mappedip: ['10.0.0.10'] }],
    vip_groups: [{ name: 'group', vdom: 'branch', members: ['public'] }],
    ip_pools: [{ name: 'snat', vdom: 'branch', type: null, startip: '198.51.100.20', arp_reply: 'disable' }],
    wildcard_fqdns: [{ name: 'wildcard', vdom: 'branch', wildcard_fqdn: '*.example.test' }],
    local_users: [{ name: 'alice', vdom: 'branch', type: 'password', status: 'disable' }],
    administrators: [{ name: 'operator', vdom: null, accprofile: 'read-only', vdoms: ['branch'] }],
    dhcp_servers: [{ id: 1, vdom: 'branch', interface: 'lan', lease_time: 0 }],
    ssl_vpn_portals: [{ name: 'remote', vdom: 'branch', tunnel_mode: 'disable', ip_pools: ['SSLVPN'] }],
  }
  const before = structuredClone(sections)
  const groups = reportSections(sections)
  for (const [key, label, column] of [
    ['vips', 'NAT', 'extip'], ['vip_groups', 'NAT', 'members'], ['ip_pools', 'NAT', 'startip'],
    ['wildcard_fqdns', 'Objects', 'wildcard_fqdn'], ['local_users', 'Objects', 'status'],
    ['administrators', 'Objects', 'vdoms'], ['dhcp_servers', 'Additional sections', 'lease_time'],
    ['ssl_vpn_portals', 'VPN', 'ip_pools'],
  ]) {
    const subsection = groups.find((group) => group.label === label).subsections.find((item) => item.key === key)
    assert.equal(subsection.rows.length, 1)
    assert.ok(defaultColumns(subsection.rows, key, 'fortigate').includes(column))
    const fields = detailGroups(subsection.rows[0], key, 'fortigate').flatMap((group) => group.fields)
    assert.ok(fields.some(([name]) => name === column))
    assert.ok(reportSearchText(subsection.rows[0]).includes(key === 'administrators' ? 'operator' : 'branch'))
  }
  assert.equal(cellSummary(sections.ip_pools[0].type), 'Not reported')
  assert.equal(cellSummary(sections.dhcp_servers[0].lease_time), '0')
  assert.equal(fieldLabel('vips'), 'Virtual IPs')
  assert.deepEqual(sections, before)
})

test('interface topology rows retain topology relationships and enrich only unique scope-aware matches', () => {
  const inventory = [
    { name: 'port1', vdom: 'root', ip: '192.0.2.1/24', kind: null, status: false, 'Source section': 'interfaces' },
    { name: 'same', vdom: 'branch' },
    { name: 'ambiguous', status: true },
  ]
  const topology = [
    { name: 'port1', vdom: 'root', kind: 'physical', parent: null, physical_interfaces: ['port1'], path: ['port1'] },
    { name: 'port1', vdom: 'other', kind: 'physical' },
    { name: 'same', vdom: 'root', kind: 'aggregate' },
    { name: 'same', vdom: 'branch', kind: 'physical' },
    { name: 'ambiguous', vdom: 'one', kind: 'physical' },
    { name: 'ambiguous', vdom: 'two', kind: 'physical' },
    { name: 'topology-only', vdom: 'root', kind: 'vpn' },
  ]
  const before = structuredClone(inventory)
  const rows = interfaceTopologyRows(inventory, topology)
  assert.equal(rows.length, topology.length)
  assert.equal(rows[0].kind, null)
  assert.equal(rows[0].status, false)
  assert.equal(rows[0].ip, '192.0.2.1/24')
  assert.equal(rows[0].parent, null)
  assert.deepEqual(rows[0].physical_interfaces, ['port1'])
  assert.equal(rows[1].kind, 'physical')
  assert.equal(rows[3].kind, 'physical')
  assert.equal(rows[4].status, undefined)
  assert.equal(rows[6].name, 'topology-only')
  assert.deepEqual(inventory, before)
  assert.ok(defaultColumns(rows, 'interface_topology').includes('physical_interfaces'))
})

test('finding navigation preserves duplicate names across scopes and resolves NAT policy and route identities', () => {
  const rows = [{ name: 'same', vdom: 'a' }, { name: 'same', vdom: 'b' }]
  assert.deepEqual(matchingSourceRows(rows, { object_name: 'same', vdom: 'b' }), [rows[1]])
  const nat = [{ policy_name: 'named-policy', policy_id: 123, vdom: 'a' }, { policy_name: 'named-policy', policy_id: 123, vdom: 'b' }]
  assert.deepEqual(matchingSourceRows(nat, { object_name: 'Policy 123', vdom: 'b' }), [nat[1]])
  assert.equal(matchingSourceRows([{ policy_id: 0, vdom: '' }], { object_name: 0, vdom: '' }).length, 1)
  assert.equal(matchingSourceRows([{ route_id: 12, vdom: 'a' }], { object_name: 12, vdom: 'a' }).length, 1)
  assert.equal(matchingSourceRows([{ name: 'same' }], { object_name: 'same', scope: '' }).length, 0)
})

test('alphabetically returned empty subsections do not hide populated policies; explicit empty selections remain reachable', () => {
  const group = reportSections({ nac_policies: [], policies: [{ policy_id: 1 }], security_policies: [] })[0]
  assert.equal(activeSubsection(group.subsections, '').key, 'policies')
  assert.equal(activeSubsection(group.subsections, 'security_policies').rows.length, 0)
  assert.equal(activeSubsection(group.subsections, 'obsolete-key').key, 'policies')
  assert.equal(activeSubsection([], ''), undefined)
})

test('configured counts exclude overlapping categories and expanded rows; explicit zero stays zero', () => {
  const data = { summary: { objects: { policies: 1724, interfaces: 83, addresses: 6000, address_groups: 100, services: 100, service_groups: 56, expanded_services: 1000, all_objects: 9000 }, validation: { severity_counts: { error: 0, warning: 0 } } }, sections: { services: Array.from({ length: 400 }, () => ({})), validation: [{ severity: 'error' }, { severity: 'warning' }] } }
  assert.deepEqual(reportCounts(data), { policies: 1724, interfaces: 83, objects: 6256, errors: 0, warnings: 0 })
  assert.equal(reportCounts({ summary: { objects: { addresses: 0, address_groups: 0, services: 0, service_groups: 0 } } }).objects, 0)
  assert.equal(reportCounts({}).objects, null)
  assert.equal(reportCounts({ sections: { validation: [{ severity: 'error' }, { severity: 'warning' }, { severity: 'info' }] } }).warnings, 1)
})

test('columns use the whole subsection and cells preserve empty, false, unknown, and safe presence metadata', () => {
  const rows = [{ name: 'one', password: 'synthetic-secret', members: [] }, { name: 'two', late_field: false, password_configured: true }]
  assert.deepEqual(rowColumns(rows), ['name', 'members', 'late_field', 'password_configured'])
  assert.equal(compactValue([]), '(empty list)')
  assert.equal(compactValue(''), '(empty string)')
  assert.equal(compactValue(false), 'false')
  assert.equal(compactValue(undefined), 'Unknown / not reported')
  assert.equal(compactValue(Array(1000).fill('member')), '1000 items')
  assert.deepEqual(safeValue({ password: 'synthetic-secret', nested: { token: 'synthetic-token', psk_configured: true }, password_configured: false }), { nested: { psk_configured: true }, password_configured: false })
})

test('search retains JSON keys and values, excludes nested secrets, and caches immutable rows', () => {
  let reads = 0
  const row = { get name() { reads++; return 'Branch Édge' }, nested: [{ password: 'secret-password', raw_extra: { value: 'secret-raw' }, token: 'secret-token', credential: 'secret-credential', private_key: 'secret-key', psk: 'secret-psk', password_configured: false, psk_configured: true, private_key_configured: true, secret_configured: true, members: ['HTTPS'], unknown: null, empty: [], enabled: false }] }
  const text = reportSearchText(row)
  assert.equal(reads, 1)
  assert.equal(reportSearchText(row), text)
  assert.equal(reads, 1)
  assert.equal(text.includes('secret-'), false)
  for (const query of ['branch éDGE', 'https', 'members', '"password_configured":false', '"psk_configured":true', '"private_key_configured":true', '"secret_configured":true', '"unknown":null', '"empty":[]', '"enabled":false']) assert.ok(text.includes(query.toLowerCase()), query)
  assert.equal(reportSearchText({}), '{}')
})

test('cached search preserves source and validation filtering across scopes and pages', () => {
  const rows = Array.from({ length: 125 }, (_, i) => ({ name: `policy${i}`, vdom: i % 2 ? 'branch' : 'root', severity: i % 2 ? 'warning' : 'error', ...(i === 124 ? { late_column: true } : {}) }))
  const subsection = reportSections({ policies: rows })[0].subsections[0]
  assert.ok(rowColumns(subsection.rows).includes('late_column'))
  for (const candidates of [rows, subsection.rows]) {
    for (const search of ['', 'POLICY1', 'name', 'unmatched']) {
      const query = search.toLowerCase()
      const filter = (text) => candidates.filter((row) => row.vdom === 'branch' && row.severity === 'warning' && (!query || text(row).includes(query)))
      assert.deepEqual(filter(reportSearchText), filter((row) => JSON.stringify(safeValue(row)).toLowerCase()))
    }
    const matches = candidates.filter((row) => reportSearchText(row).includes('policy'))
    assert.deepEqual([matches.slice(0, 50).length, matches.slice(50, 100).length, matches.slice(100, 150).length], [50, 50, 25])
  }
})

test('preferred columns are vendor/subsection specific; all safe late fields stay selectable without changing rule order', () => {
  const rows = [{ policy_id: 9, vdom: 'root', name: 'first', source_addresses: ['all'], nat: false, password: 'synthetic-secret' }, { policy_id: 1, late_field: 0, status: null }]
  const before = structuredClone(rows)
  assert.deepEqual(defaultColumns(rows, 'policies', 'fortigate'), ['policy_id', 'name', 'vdom', 'source_addresses', 'status'])
  assert.ok(rowColumns(rows, 'policies', 'fortigate').includes('late_field'))
  assert.ok(rowColumns(rows, 'policies', 'fortigate').includes('nat'))
  assert.ok(!rowColumns(rows, 'policies', 'fortigate').includes('password'))
  assert.deepEqual(defaultColumns(rows, 'policies', 'unknown'), rowColumns(rows).slice(0, 8))
  assert.deepEqual(rowColumns([{ 'Source section': 'unknown' }]), ['Source section'])
  assert.deepEqual(rows, before)
})

test('cell summaries show useful list values and retain explicit empty/false/zero values', () => {
  assert.equal(cellSummary(['all']), 'all')
  assert.equal(cellSummary(['HTTPS', 'DNS', 'SSH', 'PING']), 'HTTPS, DNS +2 more')
  for (const value of [false, 0, '', []]) assert.equal(cellSummary(value), compactValue(value))
  assert.equal(cellSummary(null), 'Not reported')
  assert.equal(cellSummary(undefined), 'Not reported')
  assert.notEqual(compactValue(null), compactValue(undefined))
  assert.equal(cellSummary([{ name: 'safe', token: 'synthetic-secret' }]), '1 fields')
})

test('details group every safe field exactly once, preserve unknowns and nested evidence without mutation', () => {
  const row = { policy_id: 0, name: '', vdom: 'branch', source_addresses: ['all'], destination_interfaces: [], services: ['ALL'], action: null, status: false, nat: 0, future_field: { token: 'synthetic-secret', explicit: [] }, password: 'synthetic-secret' }
  const before = structuredClone(row)
  const groups = detailGroups(row, 'policies', 'fortigate')
  const fields = groups.flatMap((group) => group.fields)
  assert.deepEqual(fields.map(([key]) => key).sort(), Object.keys(row).filter((key) => key !== 'password').sort())
  assert.equal(new Set(fields.map(([key]) => key)).size, fields.length)
  assert.deepEqual(groups.find((group) => group.title === 'Source').fields, [['source_addresses', ['all']]])
  assert.ok(groups.find((group) => group.title === 'Empty / not reported fields').fields.some(([key, value]) => key === 'action' && value === null))
  assert.deepEqual(fields.find(([key]) => key === 'future_field')[1], { explicit: [] })
  assert.equal(JSON.stringify(groups).includes('synthetic-secret'), false)
  assert.deepEqual(row, before)
  assert.equal(detailGroups(row, 'unknown', 'unknown').flatMap((group) => group.fields).length, fields.length)
})

test('subsection ordering is deliberate and explicit empty selections remain reachable', () => {
  const groups = reportSections({ ssl_vpn_bookmarks: [{}], vpn_phase2: [{}], vpn_tunnels: [{}], address_groups: [{}], addresses: [], future_objects: [{}] })
  assert.deepEqual(groups.find((group) => group.label === 'VPN').subsections.map((item) => item.key), ['vpn_tunnels', 'vpn_phase2', 'ssl_vpn_bookmarks'])
  const objects = groups.find((group) => group.label === 'Objects').subsections
  assert.equal(objects[0].key, 'addresses')
  assert.equal(activeSubsection(objects, 'addresses').rows.length, 0)
})

test('validation retains exact severity/domain/field/message groups and every occurrence', () => {
  const rows = [...Array.from({ length: 204 }, (_, i) => ({ severity: 'warning', domain: 'nat', field: 'ip', message: 'Reported wan1 IP', object_name: `Policy ${i}`, vdom: 'a' })), ...Array.from({ length: 5 }, () => ({ severity: 'warning', domain: 'nat', field: 'egress', message: 'Non-specific egress', vdom: 'b' }))]
  const before = structuredClone(rows)
  assert.deepEqual(findingGroups(rows).map((group) => group.count), [204, 5])
  assert.equal(rows.filter((row) => findingGroupKey(row) === findingGroups(rows)[0].key).length, 204)
  assert.equal(findingGroups([...rows, { ...rows[0], field: 'different' }, { ...rows[0], severity: 'info' }, { ...rows[0], message: 'Different evidence' }, { ...rows[0], domain: 'interface' }]).length, 6)
  assert.deepEqual(findingGroups([]), [])
  assert.deepEqual(rows, before)
})


test('Cisco FTD columns preserve policy rule and source scope identity', () => {
  const row = {
    policy_id: 'policy-1', policy_name: 'Corporate ACP', rule_id: 'rule-7', name: 'Allow HTTPS',
    position: 7, domain_id: 'domain-1', device_id: 'device-1', device_name: 'FTD-A',
    source_context: 'fmc:Global', source_addresses: ['inside'], destination_addresses: ['server'],
    source_interfaces: ['inside-zone'], destination_interfaces: ['dmz-zone'], services: ['HTTPS'], action: 'ALLOW',
  }
  assert.deepEqual(defaultColumns([row], 'policies', 'cisco_ftd'), [
    'policy_id', 'policy_name', 'rule_id', 'name', 'position', 'domain_id', 'device_name',
    'source_interfaces', 'source_addresses', 'destination_interfaces', 'destination_addresses', 'services', 'action',
  ])
  const scope = detailGroups(row, 'policies', 'cisco_ftd').find((group) => group.title === 'Source scope')
  assert.deepEqual(scope.fields, [
    ['source_context', 'fmc:Global'], ['domain_id', 'domain-1'],
    ['device_id', 'device-1'], ['device_name', 'FTD-A'],
  ])
})

test('finding navigation prefers stable Cisco FTD source IDs over duplicate names', () => {
  const rows = [
    { source_id: 'rule-a', rule_id: 'rule-a', name: 'Same', scope: 'fmc:Global' },
    { source_id: 'rule-b', rule_id: 'rule-b', name: 'Same', scope: 'fmc:Global' },
  ]
  assert.deepEqual(matchingSourceRows(rows, {
    source_id: 'rule-b', object_name: 'Same', scope: 'fmc:Global',
  }), [rows[1]])
})

test('Check Point addresses show explicit IPv4 and IPv6 definitions', () => {
  const row = { name: 'Dual', scope: 'Domain A', type: 'hosts', address_family: 'Dual Stack',
    ipv4_value: '192.0.2.4', ipv6_value: '2001:db8::4', value: '192.0.2.4' }
  assert.deepEqual(defaultColumns([row], 'addresses', 'checkpoint'), [
    'name', 'scope', 'type', 'address_family', 'ipv4_value', 'ipv6_value', 'value',
  ])
  assert.equal(fieldLabel('ipv4_value'), 'IPv4 definition')
  assert.equal(fieldLabel('ipv6_value'), 'IPv6 definition')
})
test('native finding identity matches the exact rulebase owner without name fallback', () => {
  const rows = [
    { name: 'same', scope: 'vsys:a', source_identity: ['vsys:a', 'security', 'same', 1, 'pre'] },
    { name: 'same', scope: 'vsys:a', source_identity: ['vsys:a', 'security', 'same', 2, 'post'] },
    { name: 'same', scope: 'vsys:b', source_identity: ['vsys:b', 'security', 'same', 1, 'pre'] },
  ]
  assert.deepEqual(matchingSourceRows(rows, { object_name: 'same', source_identity: [...rows[1].source_identity] }), [rows[1]])
  assert.deepEqual(matchingSourceRows(rows, { object_name: 'same', source_identity: ['missing'] }), [])
  assert.deepEqual(matchingSourceRows(rows, { object_name: 'same', scope: 'vsys:a', source_identity: [] }), rows.slice(0, 2))
})

test('FortiGate restored sections and inspection details retain full nested source data', () => {
  const policy = { name: 'review', vdom: 'branch', groups: ['staff'], logtraffic: 'all', comments: 'original',
    ips_sensor: 'sensor', source_addresses: null, services: [], additional_settings: { unknown: 0, password: 'SECRET_SENTINEL' } }
  const fields = detailGroups(policy, 'policies', 'fortigate').flatMap((group) => group.fields)
  assert.equal(fields.find(([key]) => key === 'logtraffic')[1], 'all')
  assert.deepEqual(fields.find(([key]) => key === 'groups')[1], ['staff'])
  assert.equal(fields.find(([key]) => key === 'source_addresses')[1], null)
  assert.deepEqual(fields.find(([key]) => key === 'services')[1], [])
  assert.ok(!JSON.stringify(fields).includes('SECRET_SENTINEL'))
  const sections = reportSections({ zones: [{}], user_groups: [{}], admin_profiles: [{}], ips_sensors: [{}],
    external_resources: [{}], ssl_vpn_settings: [{ authentication_rules: [{ id: 1, groups: ['staff'] }] }] })
  assert.equal(sections.find((group) => group.label === 'Objects').rows.length, 5)
  assert.deepEqual(sections.find((group) => group.label === 'VPN').rows[0].authentication_rules[0].groups, ['staff'])
})
