import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/report/reportPresentation.ts'
import { defaultColumns, detailGroups, fieldLabel, reportSections, rowColumns } from '../src/features/report/reportPresentation.ts'

test('overview counts string references as well as structured reference rows', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { SourceReport } = await server.ssrLoadModule('/src/features/report/SourceReport.tsx')
    for (const refs of [['first', 'second'], [{ reference: 'first' }, { reference: 'second' }], []]) {
      const html = renderToStaticMarkup(createElement(SourceReport, {
        data: { vendor: 'palo_alto', sections: { unresolved_references: refs } },
        excelProfile: 'full', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {},
      })).replace(/<!-- -->/g, '')
      assert.match(html, new RegExp(`Unresolved references</button></th><td>${refs.length}</td>`))
    }
  } finally { await server.close() }
})

test('PAN-OS rule columns and details distinguish source order, position, UUID and disabled state', () => {
  const policy = { name: 'disabled-rule', rule_order: 1, policy_id: 502, source_order: 502,
    rule_uuid: 'native-uuid', scope: 'vsys:vsys1', from_zones: ['trust'], to_zones: ['untrust'],
    source_addresses: ['192.0.2.0/24'], destination_addresses: ['198.51.100.0/24'], application: ['ssl'],
    services: ['application-default'], disabled: 'yes', action: 'allow', log_end: 'no',
    device_group: null, device_serial: null, profile_setting: { groups: ['profiles'] } }
  const before = structuredClone(policy)
  const columns = defaultColumns([policy], 'policies', 'palo_alto')
  for (const key of ['rule_order', 'source_addresses', 'destination_addresses', 'from_zones', 'to_zones', 'application', 'services', 'disabled']) assert.ok(columns.includes(key), key)
  for (const key of ['policy_id', 'device_group', 'device_serial']) assert.ok(!columns.includes(key), key)
  assert.ok(!rowColumns([policy], 'policies', 'palo_alto').includes('policy_id'))
  const fields = detailGroups(policy, 'policies', 'palo_alto').flatMap((group) => group.fields)
  assert.ok(!fields.some(([key]) => key === 'policy_id'))
  assert.equal(fields.find(([key]) => key === 'source_order')[1], 502)
  assert.equal(fields.find(([key]) => key === 'rule_uuid')[1], 'native-uuid')
  assert.equal(fields.find(([key]) => key === 'log_end')[1], 'no')
  assert.equal(fieldLabel('rule_order'), 'Rule position')
  assert.equal(fieldLabel('source_order'), 'Source inventory order')
  assert.equal(fieldLabel('rule_uuid'), 'Rule UUID')
  assert.deepEqual(policy, before)
  const nat = { ...policy, source_translation: { translated_address: '203.0.113.1' },
    destination_translation: { translated_address: '198.51.100.2' }, service: 'any' }
  const natColumns = defaultColumns([nat], 'nat', 'palo_alto')
  for (const key of ['source_addresses', 'destination_addresses', 'source_translation', 'destination_translation', 'service', 'disabled']) assert.ok(natColumns.includes(key), key)
})

test('PAN-OS parsed collections, proxy IDs and every source inventory record stay reachable', () => {
  const inventory = Array.from({ length: 205 }, (_, index) => ({ name: `record-${index}`, values: { setting: index } }))
  const groups = reportSections({ tags: [{}], zones: [{}], security_profile_groups: [{}], schedules: [{ name: 'office', recurring: { daily: ['08:00-17:00'] } }],
    default_security_rules: [{}], ike_crypto_profiles: [{}], ipsec_crypto_profiles: [{}], vpn_phase2: [{ name: 'proxy', tunnel: 'vpn', local: '192.0.2.0/24', remote: '198.51.100.0/24' }],
    source_inventory: inventory, extraction_coverage: [{ domain: 'application', status: 'SOURCE_ONLY' }] })
  const section = (key) => groups.find((group) => group.subsections.some((item) => item.key === key))
  assert.equal(section('tags').label, 'Objects')
  assert.equal(section('default_security_rules').label, 'Policies')
  assert.equal(section('ike_crypto_profiles').label, 'VPN')
  assert.equal(section('source_inventory').label, 'Extraction')
  const rows = section('source_inventory').subsections.find((item) => item.key === 'source_inventory').rows
  assert.equal(rows.length, 205)
  assert.equal(rows.at(-1).values.setting, 204)
  assert.ok(defaultColumns([{ name: 'office', recurring: { daily: ['08:00-17:00'] } }], 'schedules', 'palo_alto').includes('recurring'))
  assert.ok(defaultColumns([{ name: 'proxy', local: '192.0.2.0/24', remote: '198.51.100.0/24' }], 'vpn_phase2', 'palo_alto').includes('local'))
})

test('report preserves safe authentication metadata while hiding credential values at every nesting level', () => {
  const row = { name: 'gateway', password: 'PASSWORD_SENTINEL', private_key: 'PRIVATE_SENTINEL',
    password_label: 'Password prompt', save_user_credentials: '1', user_credential_or_client_cert_required: 'no',
    client_authentication: [{ auto_retrieve_passcode: 'no', 'password-label': 'Password prompt',
      'domain-credentials': '', 'save-user-credentials': '1', password: 'NESTED_SENTINEL' }],
    additional_settings: { 'password-label': { password: 'MALFORMED_SENTINEL' }, token: 'TOKEN_SENTINEL' } }
  const safe = presentation.safeValue(row)
  assert.equal(safe.password_label, 'Password prompt')
  assert.equal(safe.save_user_credentials, '1')
  assert.equal(safe.user_credential_or_client_cert_required, 'no')
  assert.equal(safe.client_authentication[0]['password-label'], 'Password prompt')
  assert.equal(safe.client_authentication[0]['domain-credentials'], '')
  assert.ok(!JSON.stringify(safe).includes('SENTINEL'))
  assert.ok(rowColumns([row], 'globalprotect_gateways', 'palo_alto').includes('password_label'))
  const fields = detailGroups(row, 'globalprotect_gateways', 'palo_alto').flatMap((group) => group.fields)
  assert.equal(fields.find(([key]) => key === 'password_label')[1], 'Password prompt')
  const groups = reportSections({ globalprotect_gateways: [row] })
  assert.equal(groups[0].rows[0].password_label, 'Password prompt')
  assert.ok(!JSON.stringify(groups).includes('SENTINEL'))
  const nested = presentation.safeValue({ client_authentication: [{ raw_extra: { 'password-label': 'Password prompt' },
    additional_settings: { 'password-label': 'Password prompt', 'user-credential-or-client-cert-required': 'no',
      password: 'NESTED_SENTINEL' } }] })
  assert.equal(nested.client_authentication[0].additional_settings['password-label'], 'Password prompt')
  assert.equal(nested.client_authentication[0].additional_settings['user-credential-or-client-cert-required'], 'no')
  assert.ok(!Object.hasOwn(nested.client_authentication[0], 'raw_extra'))
  assert.ok(!JSON.stringify(nested).includes('SENTINEL'))
})

test('PAN-OS report exposes coverage and full inventory instead of implying complete extraction', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { SourceReport } = await server.ssrLoadModule('/src/features/report/SourceReport.tsx')
    const html = renderToStaticMarkup(createElement(SourceReport, {
      data: { vendor: 'palo_alto', records_total: 205, records_returned: 200, records_truncated: true,
        summary: { source_only_count: 2, unsupported_count: 2, partial_count: 3 },
        sections: { extraction_coverage: [{ domain: 'application', status: 'SOURCE_ONLY' }],
          source_inventory: Array.from({ length: 205 }, (_, index) => ({ name: `record-${index}` })) } },
      excelProfile: 'full', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {},
    }))
    const text = html.replace(/<!-- -->/g, '')
    assert.match(text, /2 source-only records/)
    assert.match(text, /3 partial records/)
    assert.match(text, /all 205 source inventory records/)
    assert.match(text, /FULL Excel includes the sanitized source appendix/)
    assert.match(text, /<option[^>]*>Extraction<\/option>/)
    assert.match(text, /Unsupported \/ source-only/)
  } finally { await server.close() }
})

test('switching from scoped inventory to aggregate coverage does not filter away coverage rows', () => {
  const slots = []
  let cursor = 0
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) slots[index] = initial
      return [slots[index], (value) => { slots[index] = typeof value === 'function' ? value(slots[index]) : value }]
    },
    useMemo: (factory) => factory(), useRef: () => ({ current: null }), useEffect() {},
  }
  const compiled = ts.transpileModule(readFileSync(new URL('../src/features/report/SourceReport.tsx', import.meta.url), 'utf8'),
    { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const exports = {}
  const modules = { react: hooks, 'react/jsx-runtime': jsxRuntime, './reportPresentation': presentation,
    './ReportDetails': {}, './ExcelExportControls': {}, '../../components/common/tabKeyboard': {}, '../../components/common/ErrorBanner': {} }
  new Function('require', 'exports', compiled)((name) => modules[name], exports)
  function nodes(node) {
    if (Array.isArray(node)) return node.flatMap(nodes)
    return node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : []
  }
  const data = { vendor: 'palo_alto', sections: { extraction_coverage: [{ domain: 'application', status: 'SOURCE_ONLY' }],
    source_inventory: [{ name: 'a', scope: 'device:fw' }] } }
  const render = () => {
    cursor = 0
    return nodes(exports.SourceReport({ data, excelProfile: 'full', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {} }))
  }
  render().find((node) => node.props.role === 'tab' && node.props.children === 'Extraction').props.onClick()
  render().find((node) => node.props.id === 'subsection-tab-source_inventory').props.onClick()
  render().find((node) => node.props['aria-label'] === 'Filter report scope').props.onChange({ target: { value: 'device:fw' } })
  render().find((node) => node.props.id === 'subsection-tab-extraction_coverage').props.onClick()
  const tree = render()
  assert.ok(!tree.some((node) => node.props['aria-label'] === 'Filter report scope'))
  const table = tree.find((node) => typeof node.type === 'function' && node.type.name === 'SourceRowsTable')
  assert.equal(table.props.rows.length, 1)
  assert.equal(table.props.rows[0].domain, 'application')
})
