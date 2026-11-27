import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/report/reportPresentation.ts'

const SAMPLE_PM = {
  vendor: 'fortigate',
  vendor_label: 'FortiGate',
  hostname: 'FG-PM-TEST',
  subtitle: 'FortiGate-60F · FortiOS 7.4.9 · S/N FGT60F0001',
  summary: { pass: 1, warn: 1, fail: 1, info: 1, total: 4 },
  legend: [
    { label: 'Pass (green)', variant: 'success' },
    { label: 'Info (blue)', variant: 'info' },
    { label: 'Warn (amber)', variant: 'warn' },
    { label: 'Fail (red)', variant: 'danger' },
  ],
  rows: [
    { no: '1.1', category: 'Hardware Status', task: 'Hard Disk Space', status: 'Pass', finding: 'Yes (Onboard SSD)', guidance: 'Verify live disk < 80%.' },
    { no: '3.1', category: 'Product Life Cycle', task: 'Firewall Firmware Version', status: 'Fail', finding: 'FortiOS 6.4.14 (EOS)', guidance: 'Upgrade branch.' },
    { no: '6.5', category: 'Configuration', task: 'Firewall Date & Time', status: 'Warn', finding: 'Timezone mismatch', guidance: 'Set GMT+8.' },
    { no: '6.7', category: 'Configuration', task: 'High Availability', status: 'Info', finding: 'Standalone mode', guidance: 'Skip HA sync.' },
  ],
}

test('PmLookupPanel renders hero, status filters, legend, and checklist rows', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { PmLookupPanel } = await server.ssrLoadModule('/src/features/report/PmLookupPanel.tsx')
    const html = renderToStaticMarkup(createElement(PmLookupPanel, {
      vendor: 'fortigate',
      sourceEvidence: { vendor: 'fortigate', source_text: '' },
      initialData: SAMPLE_PM,
    }))
    assert.ok(html.includes('PM Lookup (Backup Config)'))
    assert.ok(html.includes('FG-PM-TEST'))
    assert.ok(html.includes('All (4)'))
    assert.ok(html.includes('Pass (1)'))
    assert.ok(html.includes('Warn (1)'))
    assert.ok(html.includes('Fail (1)'))
    assert.ok(html.includes('Info (1)'))
    assert.ok(html.includes('Export Excel'))
    assert.ok(html.includes('row-success'))
    assert.ok(html.includes('row-danger'))
    assert.ok(html.includes('row-warn'))
    assert.ok(html.includes('row-info'))
    assert.ok(html.includes('Yes (Onboard SSD)'))
  } finally {
    await server.close()
  }
})

test('PmLookupPanel filters rows by status chip and search text', () => {
  const slots = []
  let cursor = 0
  const hooks = {
    useState(initial) {
      const idx = cursor++
      if (!(idx in slots)) slots[idx] = typeof initial === 'function' ? initial() : initial
      return [slots[idx], (v) => { slots[idx] = typeof v === 'function' ? v(slots[idx]) : v }]
    },
    useMemo: (fn) => fn(),
    useEffect() {},
  }
  const source = readFileSync(new URL('../src/features/report/PmLookupPanel.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const modExports = {}
  const modules = {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    '../source/sourceApi': { fetchPmLookup: async () => SAMPLE_PM, downloadPmLookupExcel: async () => new Blob() },
    '../../utils/desktop': { saveBlobWithFallback: async () => ({ status: 'downloaded', filename: 'fortigate_pm_lookup.xlsx' }) },
    './reportPresentation': presentation,
    '../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../components/common/LoadingState': { LoadingState: 'LoadingState' },
  }
  new Function('require', 'exports', compiled)((name) => modules[name], modExports)
  const nodes = (node) => (Array.isArray(node) ? node.flatMap(nodes) : node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : [])
  const render = () => {
    cursor = 0
    return nodes(modExports.PmLookupPanel({
      vendor: 'fortigate',
      sourceEvidence: { vendor: 'fortigate', source_text: '' },
      initialData: SAMPLE_PM,
    }))
  }

  let tree = render()
  assert.equal(tree.filter((n) => n.type === 'tr').length, 5) // header + 4 rows

  const failBtn = tree.find((n) => n.type === 'button' && Array.isArray(n.props.children) && n.props.children[0] === 'Fail')
  failBtn.props.onClick()
  tree = render()
  assert.equal(tree.filter((n) => n.type === 'tr').length, 2) // header + 1 fail row
  assert.ok(tree.some((n) => n.type === 'td' && n.props.children === '3.1'))
})

test('reportPresentation parity: PA HA group.mode, device_setup advanced_routing, FG dedicated_to mgmt IP, and System & Logs grouping', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const {
      applianceHeroInfo,
      extendedSystemOverviewItems,
      haOverviewInfo,
      reportSections,
    } = await server.ssrLoadModule('/src/features/report/reportPresentation.ts')

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
  } finally {
    await server.close()
  }
})
