import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import * as presentation from '../src/features/report/reportPresentation.ts'
import { activeSubsection, applianceHeroInfo, interfaceTopologyRows, matchingSourceRows, reportSections, reportSectionRowCount, reportCounts, reportSearchText, compactValue, rowColumns, safeValue, defaultColumns, cellSummary, detailGroups, extendedSystemOverviewItems, findingGroups, findingGroupKey, fieldLabel, haOverviewInfo, systemOverviewItems } from '../src/features/report/reportPresentation.ts'
import { createHookHarness, createSharedVite, loadSourceReport, nodes } from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

test('configuration summary renders each count once, preserves missing and zero values, and keeps informational rows plain', async () => {
  const { SourceReport } = await vite.load('/src/features/report/SourceReport.tsx')
  const render = (data) => renderToStaticMarkup(createElement(SourceReport, {
    data, excelProfile: 'fast', onExcelProfileChange() { }, exporting: false, exportStatus: '', onExport() { },
  }))
  const data = { vendor: 'fortigate', summary: { objects: { policies: 1724, interfaces: 83, addresses: 6000, address_groups: 100, services: 100, service_groups: 56 }, unsupported_count: 2 }, sections: { schedules: [], nat: [{}, {}], routes: [{}], vpn_tunnels: [{}], unresolved_references: [] } }
  const beforeData = structuredClone(data)
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
  assert.ok(!html.includes('About these counts'))
  assert.ok(!table.includes('Review findings'))
  assert.ok(!table.includes('configuration-summary-warning'))
  const missing = render({ vendor: 'fortigate' })
  const missingTable = missing.match(/<table class="configuration-summary"[\s\S]*?<\/table>/)[0]
  assert.equal((missingTable.match(/Not reported/g) ?? []).length, 7)
  assert.ok(!missingTable.includes('Unresolved references'))
  assert.ok(!missingTable.includes('Unsupported / source-only'))
  assert.match(render({ vendor: 'fortigate', sections: { unresolved_references: [{}] } }), /class="configuration-summary-warning"/)
  assert.deepEqual(data, beforeData)
  const { SourceOverview } = await vite.load('/src/features/source/SourceOverview.tsx')
  for (const count of [0, 1, 2]) {
    const sections = { validation: ['error', 'warning'].flatMap((severity) => Array.from({ length: count }, (_, index) => ({ severity, message: `${severity}-${index}` }))) }
    const label = `${count} ${count === 1 ? 'error' : 'errors'} · ${count} ${count === 1 ? 'warning' : 'warnings'}`
    const rendered = render({ vendor: 'fortigate', sections })
    assert.ok(!rendered.includes('report-validation-attention'))
    if (count > 0) {
      assert.ok(rendered.includes(`Config Warnings: ${(count * 2).toLocaleString()}`))
    }
    const overview = renderToStaticMarkup(createElement(SourceOverview, { vendor: 'fortigate', vendorName: 'FortiGate', file: null, preview: { sections } }))
    assert.ok(overview.includes(`${label}</span>`))
  }
  assert.ok(!missing.includes('report-validation-attention'))
})

test('summary buttons retain their section and subsection destinations', () => {
  const { hooks, resetCursor } = createHookHarness()
  const exports = loadSourceReport(hooks)
  const data = { sections: { policies: [], addresses: [], address_groups: [{}], interfaces: [{}], schedules: [], nat: [], routes: [], unresolved_references: [] } }
  let activeSection = 'Overview'
  function render() {
    resetCursor()
    return nodes(exports.SourceReport({
      data,
      activeSection,
      onSectionChange(next) { activeSection = next },
      excelProfile: 'fast',
      onExcelProfileChange() { },
      exporting: false,
      exportStatus: '',
      onExport() { },
    }))
  }
  for (const [label, section, subsection] of [
    ['Policies', 'Policies & NAT', 'policies'], ['Address/service objects', 'Objects', 'addresses'], ['Interfaces', 'Interfaces & Network', 'interfaces'],
    ['Schedules', 'Objects', 'schedules'], ['NAT', 'Policies & NAT', 'nat'], ['Routes', 'Interfaces & Network', 'routes'], ['VPN', 'VPN'], ['Unresolved references', 'Diagnostics & Coverage', 'unresolved_references'],
  ]) {
    const tree = render()
    tree.find((node) => node.type === 'button' && node.props.children === label).props.onClick()
    assert.equal(activeSection, section)
    const next = render()
    assert.ok(next.some((node) => node.props.role === 'tabpanel' && node.props['aria-label'] === section))
    if (subsection) assert.ok(next.some((node) => node.props.id === `subsection-tab-${subsection}` && node.props['aria-selected']))
    activeSection = 'Overview'
  }
})

test('each section is reachable once; inventory, topology, plural policies, and VPN retain their boundaries', () => {
  const sections = { policies: [{ policy_id: 1 }, { policy_id: 1 }], security_policies: [], interfaces: [{ name: 'same', vdom: 'a' }, { name: 'same', vdom: 'b' }], interface_topology: [{ name: 'same' }], policy_vpn_phase1: [{}], unknown_section: [null, 'unsupported', { unknown: [] }], metadata: { complete: false }, validation: [] }
  const groups = reportSections(sections)
  assert.deepEqual(groups.flatMap((group) => group.subsections.map((section) => section.key)).sort(), Object.keys(sections).filter((key) => key !== 'validation').sort())
  assert.equal(groups.find((group) => group.label === 'Policies & NAT').rows.length, 2)
  const interfaces = groups.find((group) => group.label === 'Interfaces & Network')
  assert.equal(reportSectionRowCount(interfaces), 2)
  assert.deepEqual(interfaces.subsections.map((item) => item.key), ['interfaces', 'interface_topology'])
  assert.equal(interfaces.subsections[1].rows.length, 1)
  assert.equal(groups.some((group) => group.label === 'Topology'), false)
  assert.equal(groups.find((group) => group.label === 'VPN').rows.length, 1)
  assert.equal(groups.find((group) => group.label === 'Additional sections').rows.length, 4)
  assert.equal(groups.find((group) => group.label === 'Interfaces & Network').rows[1].vdom, 'b')
  assert.deepEqual(reportSections({ 'Security Policies': [] })[0].label, 'Policies & NAT')
})

test('combined interface views retain separate rows and counts, including empty and missing inventory', () => {
  const sections = { interface_topology: [{ name: 'same', kind: 'physical', vdom: 'a' }, { name: 'vpn', kind: 'vpn', vdom: 'a' }], interfaces: [{ name: 'same', vdom: 'a', status: false }] }
  const before = structuredClone(sections)
  const [group] = reportSections(sections)
  assert.equal(group.label, 'Interfaces & Network')
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
    ['vips', 'Policies & NAT', 'extip'], ['vip_groups', 'Policies & NAT', 'members'], ['ip_pools', 'Policies & NAT', 'startip'],
    ['wildcard_fqdns', 'Objects', 'wildcard_fqdn'], ['local_users', 'Users & Auth', 'status'],
    ['administrators', 'Users & Auth', 'vdoms'], ['dhcp_servers', 'Interfaces & Network', 'lease_time'],
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
  assert.ok(rowColumns(rows, 'interface_topology').includes('physical_interfaces'))
  assert.ok(!defaultColumns(rows, 'interface_topology').includes('physical_interfaces'))
  assert.equal(fieldLabel('kind'), 'Interface type')
  assert.equal(fieldLabel('vlanid'), 'VLAN ID')
  assert.equal(fieldLabel('allowaccess'), 'Management access')
  assert.equal(fieldLabel('issues'), 'Topology issues')
  assert.equal(fieldLabel('physical_interfaces'), 'Underlying ports')
})

test('object subsections pin top 4 pills and place remaining types in a More menu', async () => {
  const { SourceReport } = await vite.load('/src/features/report/SourceReport.tsx')
  const html = renderToStaticMarkup(createElement(SourceReport, {
    data: {
      vendor: 'fortigate',
      sections: {
        addresses: [{ name: 'a1' }],
        address_groups: [{ name: 'g1' }],
        wildcard_fqdns: [{ name: 'w1' }],
        services: [{ name: 's1' }],
        service_groups: [{ name: 'sg1' }],
        zones: [{ name: 'z1' }],
        local_users: [{ name: 'u1' }],
      },
    },
    excelProfile: 'fast', onExcelProfileChange() { }, exporting: false, exportStatus: '', onExport() { },
  }))
  assert.ok(html.includes('Overview'))
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
  const group = reportSections({ local_in_policies: [], policies: [{ policy_id: 1 }], security_policies: [] })[0]
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
  const row = {
    name: 'Dual', scope: 'Domain A', type: 'hosts', address_family: 'Dual Stack',
    ipv4_value: '192.0.2.4', ipv6_value: '2001:db8::4', value: '192.0.2.4'
  }
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
  const policy = {
    name: 'review', vdom: 'branch', groups: ['staff'], logtraffic: 'all', comments: 'original',
    ips_sensor: 'sensor', source_addresses: null, services: [], additional_settings: { unknown: 0, password: 'SECRET_SENTINEL' }
  }
  const fields = detailGroups(policy, 'policies', 'fortigate').flatMap((group) => group.fields)
  assert.equal(fields.find(([key]) => key === 'logtraffic')[1], 'all')
  assert.deepEqual(fields.find(([key]) => key === 'groups')[1], ['staff'])
  assert.equal(fields.find(([key]) => key === 'source_addresses')[1], null)
  assert.deepEqual(fields.find(([key]) => key === 'services')[1], [])
  assert.ok(!JSON.stringify(fields).includes('SECRET_SENTINEL'))
  const sections = reportSections({
    zones: [{}], user_groups: [{}], admin_profiles: [{}], ips_sensors: [{}],
    external_resources: [{}], ssl_vpn_settings: [{ authentication_rules: [{ id: 1, groups: ['staff'] }] }]
  })
  assert.equal(sections.find((group) => group.label === 'Interfaces & Network').rows.length, 1)
  assert.equal(sections.find((group) => group.label === 'Users & Auth').rows.length, 2)
  assert.equal(sections.find((group) => group.label === 'Security Profiles').rows.length, 1)
  assert.equal(sections.find((group) => group.label === 'Objects').rows.length, 1)
  assert.deepEqual(sections.find((group) => group.label === 'VPN').rows[0].authentication_rules[0].groups, ['staff'])
})

test('FortiGate cli_vdom and cli_scope are omitted from interface table columns but retained in Details and source_inventory', () => {
  const row = { name: 'port1', vdom: 'corp', cli_vdom: null, cli_scope: 'global', ip: '192.0.2.1/24' }
  for (const subsection of ['interface_topology', 'interfaces']) {
    const columns = rowColumns([row], subsection, 'fortigate')
    assert.equal(columns.includes('cli_vdom'), false)
    assert.equal(columns.includes('cli_scope'), false)
    const detailFields = detailGroups(row, subsection, 'fortigate').flatMap((group) => group.fields)
    assert.equal(detailFields.find(([key]) => key === 'cli_scope')?.[1], 'global')
    assert.equal(detailFields.find(([key]) => key === 'cli_vdom')?.[1], null)
  }
  const inventoryColumns = rowColumns([{ source_path: 'system interface', name: 'port1', vdom: 'corp', cli_scope: 'global' }], 'source_inventory', 'fortigate')
  assert.equal(inventoryColumns.includes('cli_scope'), true)
})

test('semantic badges, row classes, legends, and monospace column helpers classify firewall objects accurately', () => {
  assert.equal(presentation.cellBadgeVariant('action', 'accept'), 'allow')
  assert.equal(presentation.cellBadgeVariant('action', 'deny'), 'deny')
  assert.equal(presentation.cellBadgeVariant('status', 'enable'), 'allow')
  assert.equal(presentation.cellBadgeVariant('status', 'disable'), 'deny')
  assert.equal(presentation.cellBadgeVariant('disabled', 'yes'), 'deny')
  assert.equal(presentation.cellBadgeVariant('disabled', 'no'), 'allow')
  assert.equal(presentation.cellBadgeVariant('kind', 'vlan'), 'purple')
  assert.equal(presentation.cellBadgeVariant('kind', 'aggregate'), 'info')
  assert.equal(presentation.cellBadgeVariant('kind', 'zone'), 'muted')
  assert.equal(presentation.isMonoColumn('ip'), true)
  assert.equal(presentation.isMonoColumn('destination'), true)
  assert.equal(presentation.isMonoColumn('comments'), false)

  assert.equal(presentation.rowSemanticClass({ status: 'disable', kind: 'physical' }, 'interfaces'), 'row-danger')
  assert.equal(presentation.rowSemanticClass({ status: 'enable', kind: 'zone' }, 'interfaces'), 'row-zone')
  assert.equal(presentation.rowSemanticClass({ status: 'enable', kind: 'aggregate' }, 'interfaces'), 'row-info')
  assert.equal(presentation.rowSemanticClass({ status: 'enable', kind: 'vlan', vlanid: 10 }, 'interfaces'), 'row-sub')
  assert.equal(presentation.rowSemanticClass({ action: 'accept' }, 'policies'), 'row-success')
  assert.equal(presentation.rowSemanticClass({ action: 'deny' }, 'policies'), 'row-danger')

  const ifaceLegend = presentation.sectionLegend('interfaces', [{ name: 'port1' }])
  assert.equal(ifaceLegend.length, 5)
  const policyLegend = presentation.sectionLegend('policies', [{ name: 'rule1' }])
  assert.equal(policyLegend.length, 2)
})

test('extended FortiGate and PAN-OS subsections route properly and preserve safe auth metadata', () => {
  const safe = safeValue({
    fortitoken: 'FTKMOB123',
    passwd_policy: 'strict-pw',
    password_configured: true,
    password: 'RAW_PASSWORD',
    secret: 'RAW_SECRET',
    token: 'RAW_TOKEN',
  })
  assert.equal(safe.fortitoken, 'FTKMOB123')
  assert.equal(safe.passwd_policy, 'strict-pw')
  assert.equal(safe.password_configured, true)
  assert.equal(safe.password, undefined)
  assert.equal(safe.secret, undefined)
  assert.equal(safe.token, undefined)

  const groups = reportSections({
    proxy_policies: [{ policy_id: 1, name: 'proxy-1' }],
    antivirus_profiles: [{ name: 'av-1', vdom: 'root' }],
    router_bgp: [{ vdom: 'root', bgp_as: 65001 }],
    virtual_servers: [{ name: 'vs-1', vdom: 'root' }],
    system_global: [{ hostname: 'fg-1' }],
    pbf_rules: [{ name: 'pbf-1', scope: 'vsys1' }],
    management_profiles: [{ name: 'mgmt-1', scope: 'shared' }],
    virtual_routers: [{ name: 'vr-1', scope: 'shared' }],
  })
  const byLabel = Object.fromEntries(groups.map((g) => [g.label, g.subsections.map((s) => s.key)]))
  assert.ok(byLabel['Policies & NAT'].includes('proxy_policies'))
  assert.ok(byLabel['Policies & NAT'].includes('pbf_rules'))
  assert.ok(byLabel['Security Profiles'].includes('antivirus_profiles'))
  assert.ok(byLabel['Interfaces & Network'].includes('router_bgp'))
  assert.ok(byLabel['Interfaces & Network'].includes('virtual_routers'))
  assert.ok(byLabel.Objects.includes('virtual_servers'))
  assert.ok(byLabel['Interfaces & Network'].includes('management_profiles'))
  assert.ok(byLabel['System & Logs'].includes('system_global'))
  assert.ok(defaultColumns([{ name: 'port1', vdom: 'root', mtu: 1500 }], 'interfaces', 'fortigate').includes('mtu'))

  const extGroups = reportSections({
    guest_users: [{ id: '1', user_id: 'guest1' }],
    switch_port_policies: [{ name: 'sp-1' }],
    device_objects: [{ name: 'dev-1' }],
    user_id_settings: [{ name: 'user-identification' }],
  })
  const extByLabel = Object.fromEntries(extGroups.map((g) => [g.label, g.subsections.map((s) => s.key)]))
  assert.ok(extByLabel['Users & Auth'].includes('guest_users'))
  assert.ok(extByLabel.Objects.includes('device_objects'))
  assert.ok(extByLabel['Users & Auth'].includes('user_id_settings'))
  assert.ok(extByLabel['WiFi & Switch'].includes('switch_port_policies'))

  const addrTabs = presentation.subtypeFilterTabs('addresses', [
    { name: 'net1', type: 'ipmask' },
    { name: 'rng1', type: 'iprange' },
    { name: 'fqdn1', type: 'fqdn' },
  ])
  assert.deepEqual(addrTabs.map((t) => t.id), ['all', 'subnet', 'range', 'fqdn'])
})

test('systemOverviewItems extracts FortiGate, PAN-OS, and missing system metadata without guessing', () => {
  const fortigateData = {
    vendor: 'fortigate',
    summary: {
      source_metadata: {
        fortios_version: '7.2.13',
        serial_number: 'FG100E4Q17003638',
      },
    },
    sections: {
      system_global: [{ hostname: 'myinfuatforti1' }],
      system_dns: [{ primary: '1.1.1.1', secondary: '8.8.8.8' }],
      interfaces: [
        { name: 'port1', role: 'lan', ip: '192.168.1.99 255.255.255.0', status: 'up' },
        { name: 'wan1', role: 'wan', ip: '103.230.127.147 255.255.255.0', status: 'up' },
      ],
    },
  }
  assert.deepEqual(systemOverviewItems(fortigateData), [
    { label: 'Hostname', value: 'myinfuatforti1' },
    { label: 'WAN IP / Netmask', value: '103.230.127.147/255.255.255.0', detail: null },
    { label: 'Primary DNS', value: '1.1.1.1', detail: 'Secondary: 8.8.8.8' },
    { label: 'Serial Number', value: 'FG100E4Q17003638' },
    { label: 'Firmware Version', value: '7.2.13' },
  ])

  const multiWanFallback = {
    vendor: 'fortigate',
    sections: {
      interfaces: [
        { name: 'wan1', ip: '0.0.0.0 0.0.0.0', status: 'down' },
        { name: 'wan2', ip: '198.51.100.2 255.255.255.252', status: 'up' },
      ],
    },
  }
  assert.equal(systemOverviewItems(multiWanFallback)[1].value, '198.51.100.2/255.255.255.252')

  const panosData = {
    vendor: 'palo_alto',
    hostname: 'pa-edge',
    source_version: '11.1.0',
    scopes: [{ device_serial: '007200001234' }],
    sections: {
      system_settings: [{
        hostname: 'pa-edge',
        ip_address: '198.51.100.10',
        netmask: '255.255.255.0',
        dns_setting: { servers: { primary: '9.9.9.9', secondary: '1.0.0.1' } },
      }],
    },
  }
  assert.deepEqual(systemOverviewItems(panosData), [
    { label: 'Hostname', value: 'pa-edge' },
    { label: 'Mgmt IP / Netmask', value: '198.51.100.10/255.255.255.0' },
    { label: 'Primary DNS', value: '9.9.9.9', detail: 'Secondary: 1.0.0.1' },
    { label: 'Serial Number', value: '007200001234' },
    { label: 'Firmware Version', value: '11.1.0' },
  ])

  assert.deepEqual(systemOverviewItems({ vendor: 'fortigate' }), [
    { label: 'Hostname', value: null },
    { label: 'WAN IP / Netmask', value: null },
    { label: 'Primary DNS', value: null },
    { label: 'Serial Number', value: null },
    { label: 'Firmware Version', value: null },
  ])
})

test('SourceReport Overview renders System Overview and HA without Validation card', async () => {
  const { SourceReport } = await vite.load('/src/features/report/SourceReport.tsx')
  const html = renderToStaticMarkup(createElement(SourceReport, {
    data: {
      vendor: 'fortigate',
      summary: {
        source_metadata: {
          fortios_version: '7.2.13',
          serial_number: 'FG100E4Q17003638',
        },
      },
      sections: {
        system_global: [{ hostname: 'myinfuatforti1' }],
        system_dns: [{ primary: '1.1.1.1', secondary: '8.8.8.8' }],
        interfaces: [{ name: 'wan1', role: 'wan', ip: '103.230.127.147 255.255.255.0' }],
      },
    },
    excelProfile: 'fast', onExcelProfileChange() { }, exporting: false, exportStatus: '', onExport() { },
  }))
  assert.ok(html.includes('id="system-overview-title"'), 'Overview renders System & Network')
  assert.ok(!html.includes('fw-overview-validation-panel'), 'Overview omits Validation card')
  for (const expected of ['myinfuatforti1', '103.230.127.147/255.255.255.0', '1.1.1.1', 'Secondary: 8.8.8.8', 'FG100E4Q17003638', '7.2.13']) {
    assert.ok(html.includes(expected), `Missing expected value: ${expected}`)
  }
  for (const dupLabel of ['>Hostname<', '>Model<', '>Firmware Version<']) {
    assert.ok(!html.includes(dupLabel), `Duplicate hero label should be omitted from System & Network list: ${dupLabel}`)
  }
  assert.ok(html.includes('fw-hero-card'), 'Overview renders Appliance Hero banner')
  assert.ok(html.includes('id="ha-overview-title"'), 'Overview renders High Availability section')
})

test('Overview renders LifecycleCard and HA details; extendedSystemOverviewItems includes posture and admin ports', async () => {
  const { SourceReport } = await vite.load('/src/features/report/SourceReport.tsx')

  const fgData = {
    vendor: 'fortigate',
    source_evidence: { vendor: 'fortigate', source_text: '' },
    summary: {
      source_metadata: { hardware_model: 'FG-60F', fortios_version: '7.4.4', serial_number: 'FGT60F123' },
      lifecycle: {
        id: 'fg_lifecycle_card',
        vendor: 'fortigate',
        title: 'Lifecycle & Firmware',
        subtitle: 'Snapshot',
        source_label: 'Offline snapshot',
        needs_live_refresh: false,
        badge: { id: 'fg_lifecycle_badge', text: 'Lifecycle OK · Up to Date', variant: 'allow' },
        rows: [{ label: 'Hardware Model', value: 'FortiGate-60F' }],
      },
    },
    sections: {
      system_global: [{ hostname: 'fg-ha', admin_port: 8080, admin_sport: 8443, admin_ssh_port: 2222 }],
      ha_config: [{ mode: 'a-p', group_name: 'PROD-HA', priority: 200, session_pickup: 'enable', hbdev: 'port7' }],
      interfaces: [{ name: 'mgmt', role: 'mgmt', ip: '192.168.10.1/24' }],
    },
  }

  const ha = haOverviewInfo(fgData)
  assert.equal(ha.enabled, true)
  assert.equal(ha.title, 'a-p Cluster')
  assert.equal(ha.items.find((i) => i.label === 'Heartbeat Interfaces').value, 'port7')

  const extItems = extendedSystemOverviewItems(fgData, {
    posture: { internet: 'Connected (Direct Public IP)', internet_sub: '0.0.0.0/0 route', disk: 'Yes (Onboard SSD)', disk_sub: 'Disk logging enabled' },
  }, fgData.summary.lifecycle)
  assert.equal(extItems.find((i) => i.label === 'Model').value, 'FortiGate-60F')
  assert.equal(extItems.find((i) => i.label === 'Admin Ports').value, 'HTTPS 8443 · SSH 2222')
  assert.equal(extItems.find((i) => i.label === 'Internet Connectivity').value, 'Connected (Direct Public IP)')
  assert.equal(extItems.find((i) => i.label === 'Local Hard Disk').value, 'Yes (Onboard SSD)')

  const html = renderToStaticMarkup(createElement(SourceReport, {
    data: fgData,
    excelProfile: 'fast', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {},
  }))
  assert.ok(html.includes('id="fg_lifecycle_card"'), 'Overview renders LifecycleCard')
  assert.ok(html.includes('id="fg_lifecycle_badge"'), 'LifecycleCard renders unique lifecycle badge id')
  assert.ok(html.includes('PROD-HA'), 'Overview renders HA cluster info')
  assert.ok(!html.includes('Global IP / Object'), 'Inline Where-Used expander moved to top-right Ctrl+K modal')
})

test('reportPresentation parity: PA HA group.mode, device_setup advanced_routing, FG dedicated_to mgmt IP, and System & Logs grouping', () => {
  const paData = {
    vendor: 'palo_alto',
    source_version: '11.1.0',
    sections: {
      system_settings: [{
        hostname: 'pa-gw',
        ip_address: '10.0.0.1',
        route: { entry: { nexthop: { 'ip-address': '10.0.0.254' } } },
      }],
      device_setup_settings: [{
        advanced_routing: { enable: 'yes' },
        management: { 'enable-duplicate-mac-detect': 'yes' },
      }],
      ha_configs: [{
        enabled: 'yes',
        group: { 'group-id': '7', 'peer-ip': '169.254.1.2', mode: { 'active-active': {} } },
        interface: { ha1: { port: 'ha1-a', 'ip-address': '169.254.1.1' }, ha2: { 'ip-address': '169.254.2.1' } },
      }],
    },
  }
  const ha = haOverviewInfo(paData)
  assert.equal(ha.enabled, true)
  assert.equal(ha.title, 'Active-Active Cluster')
  assert.equal(ha.items.find((i) => i.label === 'HA2 IP').value, '169.254.2.1')

  const paExt = extendedSystemOverviewItems(paData)
  assert.equal(paExt.find((i) => i.label === 'Default Gateway').value, '10.0.0.254')

  const hero = applianceHeroInfo(paData, 'Palo Alto PAN-OS')
  assert.ok(hero.badges.some((b) => b.text === 'Advanced Routing: On'))
  assert.ok(hero.badges.some((b) => b.text === 'Duplicate IP: Enable'))

  const fgMgmtData = {
    vendor: 'fortigate',
    sections: {
      ha_config: [{ mode: 'a-p', ha_mgmt_status: 'enable', ha_mgmt_interfaces: [{ interface: 'mgmt2' }] }],
      interfaces: [
        { name: 'mgmt1', role: 'mgmt', ip: '10.1.1.1/24', status: 'enable' },
        { name: 'mgmt2', dedicated_to: 'management', ip: '10.2.2.2/24', status: 'enable' },
      ],
    },
  }
  const fgExt = extendedSystemOverviewItems(fgMgmtData)
  assert.equal(fgExt.find((i) => i.label === 'Management IP').value, '10.2.2.2/24')

  const grouped = reportSections({
    fortianalyzer_settings: [{}],
    log_fortiguard_settings: [{}],
    system_password_policies: [{}],
    local_in_policies: [{}],
    saml_servers: [{}],
  })
  assert.equal(grouped.find((g) => g.label === 'System & Logs').subsections.length, 3)
  assert.equal(grouped.find((g) => g.label === 'Policies & NAT').subsections.length, 1)
  assert.equal(grouped.find((g) => g.label === 'Users & Auth').subsections.length, 1)
})

test('WiFi & Switch groups all seven FCR-parity tabs in order with NAC moved out of Policies & NAT', () => {
  const wifiSections = reportSections({
    nac_policies: [{ name: 'nac-1', assign_vlan: '200', status: 'enable' }],
    switch_port_policies: [{ name: 'port-1', mac_auth_bypass: 'enable' }],
    managed_switches: [{ switch_id: 'SW1', switch_group: 'Edge', status: 'enable' }],
    wids_profiles: [{ name: 'wids-1', ap_scan: 'enable' }],
    wtp_profiles: [{ name: 'prof-1', platform: '221E' }],
    wireless_vaps: [{ name: 'vap-1', ssid: 'Guest', status: 'disable' }],
    wireless_wtps: [{ wtp_id: 'AP1', admin: 'disable' }],
  })
  assert.equal(wifiSections.some((g) => g.label === 'Policies & NAT'), false)
  const wifiGroup = wifiSections.find((g) => g.label === 'WiFi & Switch')
  assert.ok(wifiGroup)
  assert.deepEqual(
    wifiGroup.subsections.map((s) => s.key),
    ['wireless_wtps', 'wireless_vaps', 'wtp_profiles', 'wids_profiles', 'managed_switches', 'switch_port_policies', 'nac_policies'],
  )
  assert.equal(defaultColumns([{ wtp_id: 'AP1', location: 'Lobby' }], 'wireless_wtps', 'fortigate').includes('location'), true)
  assert.equal(defaultColumns([{ name: 'vap-1', schedule: 'always' }], 'wireless_vaps', 'fortigate').includes('schedule'), true)
  assert.equal(defaultColumns([{ name: 'prof-1', platform: '221E' }], 'wtp_profiles', 'fortigate').includes('platform'), true)
  assert.equal(defaultColumns([{ name: 'wids-1', ap_scan: 'enable' }], 'wids_profiles', 'fortigate').includes('ap_scan'), true)
  assert.equal(defaultColumns([{ switch_id: 'SW1', firmware_provision_version: '7.4.2' }], 'managed_switches', 'fortigate').includes('firmware_provision_version'), true)
  assert.equal(defaultColumns([{ name: 'port-1', guest_vlan: 'guest' }], 'switch_port_policies', 'fortigate').includes('guest_vlan'), true)
  assert.equal(defaultColumns([{ name: 'nac-1', assign_vlan: '200' }], 'nac_policies', 'fortigate').includes('assign_vlan'), true)

  assert.equal(presentation.cellBadgeVariant('ap_scan', 'enable'), 'allow')
  assert.equal(presentation.cellBadgeVariant('admin', 'disable'), 'deny')
  assert.equal(presentation.cellBadgeVariant('mac_auth_bypass', 'disable'), 'muted')
  assert.equal(presentation.rowSemanticClass({ wtp_id: 'AP1', admin: 'disable' }, 'wireless_wtps'), 'row-danger')
  assert.deepEqual(
    presentation.sectionLegend('wireless_vaps', [{ name: 'vap-1', status: 'disable' }]),
    [
      { label: 'Enabled SSID', variant: 'default' },
      { label: 'Disabled SSID', variant: 'danger' },
    ],
  )
})

test('SD-WAN groups under Interfaces & Network after interface_topology rather than Additional sections', () => {
  const groups = reportSections({
    interfaces: [{ name: 'wan1' }],
    interface_topology: [{ name: 'wan1' }],
    sdwan: [{ vdom: 'root', status: 'enable', zones: [], members: [], health_checks: [], services: [] }],
    routes: [{ route_id: 1 }],
  })
  assert.equal(groups.some((g) => g.label === 'Additional sections'), false)
  const net = groups.find((g) => g.label === 'Interfaces & Network')
  assert.ok(net)
  assert.deepEqual(
    net.subsections.map((s) => s.key),
    ['interfaces', 'interface_topology', 'sdwan', 'routes'],
  )
  assert.equal(fieldLabel('sdwan'), 'SD-WAN')
})
