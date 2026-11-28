import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/report/reportPresentation.ts'
import {
  fieldLabel,
  isLifecycleCardData,
  reportSections,
} from '../src/features/report/reportPresentation.ts'
import {
  createHookHarness,
  createSharedVite,
  loadCjs,
  loadSourceReport,
  nodes,
} from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

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

const SAMPLE_SSL_TO_IPSEC = {
  has_ssl_vpn: true,
  vdom: 'root',
  vdoms: ['root', 'corp'],
  model: 'FGT60F',
  firmware: '7.4.9',
  servercert: 'Fortinet_Factory',
  is_factory_cert: true,
  require_client_cert: false,
  auth_mode: 'eap',
  auth_label: 'IKEv2 + EAP (PSK + User Group / LDAP / RADIUS)',
  wan_intf: 'wan1',
  listen_interfaces: ['wan1'],
  primary_pool: 'SSLVPN_POOL_1',
  ip_pools: ['SSLVPN_POOL_1'],
  portals_count: 1,
  ssl_policies_count: 1,
  referenced_groups: ['VPN_Staff'],
  warnings: ["SSL-VPN uses 'Fortinet_Factory' (self-signed)."],
  infos: ['IPSec uses UDP 500 & UDP 4500 (NAT-T) by default.'],
  ssl_policies: [
    {
      id: '10',
      name: 'SSL_To_LAN',
      status: 'Enable',
      srcintf: 'ssl.root',
      dstintf: 'internal',
      srcaddr: 'SSLVPN_POOL_1',
      dstaddr: 'CORP_LAN',
      service: 'ALL',
      action: 'ACCEPT',
      nat: 'Disable',
      schedule: 'always',
      groups: 'VPN_Staff',
      users: '-',
      profiles: 'av-profile: default',
    },
  ],
  gui_rows: [
    { parameter: 'Tunnel Name', recommended_value: 'RA-IPSec-IKEv2', notes: 'Custom Remote Access (Dial-up)' },
  ],
  cli_draft: 'config vpn ipsec phase1-interface\n    edit "RA-IPSec-IKEv2"\nend',
  forticlient_rows: [
    { setting: 'VPN Type', value: 'IPsec VPN (IKEv2)' },
  ],
  cutover_rows: [
    { step: '1', phase: 'Pre-Check', action: 'Install CA-signed server cert.' },
  ],
}

const SAMPLE_AUDIT = {
  vendor: 'fortigate',
  certificates: [
    { name: 'valid-cert', store: 'Local', common_name: 'valid.example.test', san: '', issuer: 'CA', not_before: '', expires: '2030-01-01', days_left: '1100', status: 'Valid' },
    { name: 'gw-cert', store: 'Local', common_name: 'vpn.example.test', san: '', issuer: 'CA', not_before: '', expires: '2026-12-12', days_left: '14', status: 'Expiring Soon' },
  ],
  certificate_summary: { total: 2, expired: 0, expiring_soon: 1, valid: 1, no_pem: 0 },
  exposure: [{ interface: 'wan1', ip: '1.1.1.2', protocols: ['HTTPS'], note: 'Unrestricted', restricted: false, severity: 'critical', targets: [{ ip: '1.1.1.2', port: 443, protocol: 'HTTPS' }] }],
  posture: { internet: 'Connected', internet_sub: '', disk: 'Yes', disk_sub: '' },
  hygiene: { unused_objects: [], hygiene_issues: [], counts: { unused: 0, disabled: 0, broad: 0, extra: 0 }, cleanup_cli: '' },
  quick_audit: {
    findings: [
      { severity: 'High', category: 'Overly Permissive ANY-ANY Allow Rules', count: 1, details: 'R10 WAN -> LAN' },
    ],
    high_count: 1,
    med_count: 0,
    info_count: 0,
  },
}

const SAMPLE_LIFECYCLE = {
  id: 'fg_lifecycle_card',
  vendor: 'fortigate',
  title: 'Lifecycle & Firmware',
  subtitle: 'Model & FortiOS branch support status · Fetching live data… (showing snapshot 2026-11-24)',
  source_label: 'Offline snapshot (2026-11-24)',
  snapshot_updated_at: '2026-11-24',
  needs_live_refresh: true,
  badge: { id: 'fg_lifecycle_badge', text: 'Lifecycle OK · Up to Date', variant: 'allow' },
  rows: [
    { label: 'Hardware Model', value: 'FortiGate-60F' },
    { label: 'Current Firmware', value: '7.4.13 (Branch 7.4)' },
  ],
  refresh_params: { vendor: 'fortigate', model: 'FG-60F', firmware: '7.4.13' },
}

const reportProps = (vendor) => ({
  data: { vendor, source_evidence: { vendor, source_text: '' }, summary: { objects: {}, validation: { severity_counts: {} } }, sections: { interfaces: [], policies: [], validation: [] } },
  excelProfile: 'fast',
  onExcelProfileChange: () => {},
  exporting: false,
  exportStatus: '',
  onExport: () => {},
})

test('PmLookupPanel renders hero, status filters, legend, and checklist rows', async () => {
  const { PmLookupPanel } = await vite.load('/src/features/report/PmLookupPanel.tsx')
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
})

test('PmLookupPanel filters rows by status chip and search text', () => {
  const { hooks, resetCursor } = createHookHarness()
  const modExports = loadCjs('../src/features/report/PmLookupPanel.tsx', {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    '../source/sourceApi': { fetchPmLookup: async () => SAMPLE_PM, downloadPmLookupExcel: async () => new Blob() },
    '../../utils/desktop': { saveBlobWithFallback: async () => ({ status: 'downloaded', filename: 'fortigate_pm_lookup.xlsx' }) },
    './reportPresentation': presentation,
    '../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../components/common/LoadingState': { LoadingState: 'LoadingState' },
  })
  const render = () => {
    resetCursor()
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

test('SslToIpsecPanel renders readiness alerts, policies table, draft CLI, and empty state', async () => {
  const { SslToIpsecPanel } = await vite.load('/src/features/report/SslToIpsecPanel.tsx')
  const html = renderToStaticMarkup(createElement(SslToIpsecPanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    initialData: SAMPLE_SSL_TO_IPSEC,
  }))
  assert.ok(html.includes('SSL-VPN → Dial-up IPSec (IKEv2) Assistant'))
  assert.ok(html.includes('1 Review Item(s)'))
  assert.ok(html.includes('Fortinet_Factory'))
  assert.ok(html.includes('SSL_To_LAN'))
  assert.ok(html.includes('row-success'))
  assert.ok(html.includes('Copy CLI'))
  assert.ok(html.includes('RA-IPSec-IKEv2'))
  assert.ok(html.includes('Select SSL-VPN VDOM'))

  const emptyHtml = renderToStaticMarkup(createElement(SslToIpsecPanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    initialData: { has_ssl_vpn: false, vdom: null, vdoms: [], model: 'FGT60F', firmware: '7.4.9' },
  }))
  assert.ok(emptyHtml.includes('No active SSL-VPN configuration detected'))
})

test('SourceReport exposes SSL-to-IPSec Assistant under VPN only for FortiGate', () => {
  const renderFor = (vendor, sections) => {
    const { hooks, resetCursor } = createHookHarness()
    const modExports = loadSourceReport(hooks)
    const render = () => {
      resetCursor()
      return nodes(modExports.SourceReport({
        data: {
          vendor,
          source_evidence: { vendor, source_text: 'cfg', source_name: 'fw.conf' },
          sections,
        },
        activeSection: 'VPN',
        exportStatus: '',
      }))
    }
    return { render }
  }

  const fg = renderFor('fortigate', { ssl_vpn_settings: [{ servercert: 'Fortinet_Factory' }] })
  let tree = fg.render()
  const assistantTab = tree.find((n) => n.props?.role === 'tab' && n.props?.children === 'SSL-to-IPSec Assistant')
  assert.ok(assistantTab)
  assert.ok(tree.some((n) => n.props?.children === 'Open SSL-to-IPSec Assistant →'))

  assistantTab.props.onClick()
  tree = fg.render()
  assert.ok(tree.some((n) => n.type === 'SslToIpsecPanel'))

  const pa = renderFor('palo_alto', { ike_gateways: [{ name: 'gw1' }] })
  const paTree = pa.render()
  assert.equal(paTree.find((n) => n.props?.role === 'tab' && n.props?.children === 'SSL-to-IPSec Assistant'), undefined)
})

test('Phase 3 panels render forms and results cleanly for FortiGate and Palo Alto', async () => {
  const { PolicyLookupPanel } = await vite.load('/src/features/report/PolicyLookupPanel.tsx')
  const { RouteLookupPanel } = await vite.load('/src/features/report/RouteLookupPanel.tsx')
  const { PacketTracePanel } = await vite.load('/src/features/report/PacketTracePanel.tsx')
  const { ConfigDiffPanel } = await vite.load('/src/features/report/ConfigDiffPanel.tsx')

  const fgSections = {
    interfaces: [{ name: 'internal', vdom: 'root' }, { name: 'wan1', vdom: 'root' }],
    zones: [{ name: 'Z_LAN' }],
    policies: [{ policy_id: 1, vdom: 'root' }],
  }
  const paSections = {
    interfaces: [{ name: 'ethernet1/1' }],
    zones: [{ name: 'trust' }, { name: 'untrust' }],
    virtual_routers: [{ name: 'default' }],
    security_rules: [{ name: 'Allow', vsys: 'vsys1' }],
  }

  const polHtml = renderToStaticMarkup(createElement(PolicyLookupPanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    sections: fgSections,
  }))
  assert.ok(polHtml.includes('Policy Match Simulator'))
  assert.ok(polHtml.includes('Evaluate Policy'))
  assert.ok(polHtml.includes('Z_LAN'))

  const routeHtml = renderToStaticMarkup(createElement(RouteLookupPanel, {
    vendor: 'palo_alto',
    sourceEvidence: { vendor: 'palo_alto', source_text: '' },
    sections: paSections,
  }))
  assert.ok(routeHtml.includes('Longest-Prefix-Match (LPM) Route Lookup'))
  assert.ok(routeHtml.includes('Lookup Route'))
  assert.ok(routeHtml.includes('default'))

  const traceHtml = renderToStaticMarkup(createElement(PacketTracePanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    sections: fgSections,
  }))
  assert.ok(traceHtml.includes('End-to-End Packet Flow Simulator'))
  assert.ok(traceHtml.includes('Trace Packet'))

  const diffHtml = renderToStaticMarkup(createElement(ConfigDiffPanel, {
    vendor: 'palo_alto',
    sourceEvidence: { vendor: 'palo_alto', source_text: '' },
    currentFilename: 'fw-baseline.xml',
  }))
  assert.ok(diffHtml.includes('Firewall-Aware Structural Config Diff'))
  assert.ok(diffHtml.includes('fw-baseline.xml'))
  assert.ok(diffHtml.includes('Compare Configs'))
})

test('SourceReport wires Overview sub-tabs, Policy Lookup tab, and Route Lookup tab for FG/PA', () => {
  const { hooks, resetCursor } = createHookHarness()
  const modExports = loadSourceReport(hooks)

  const fgData = {
    vendor: 'fortigate',
    source_evidence: { vendor: 'fortigate', source_text: 'config system global', source_name: 'edge.conf' },
    sections: {
      policies: [{ policy_id: 1, name: 'Allow' }],
      interfaces: [{ name: 'port1' }],
    },
  }
  let activeSection = 'Overview'
  const render = () => {
    resetCursor()
    return nodes(modExports.SourceReport({
      data: fgData,
      activeSection,
      onSectionChange(next) { activeSection = next },
      exportStatus: '',
    }))
  }

  let tree = render()
  const traceTab = tree.find((n) => n.props?.role === 'tab' && n.props?.children === 'Trace Packet')
  const diffTab = tree.find((n) => n.props?.role === 'tab' && n.props?.children === 'Config Diff')
  assert.ok(traceTab && diffTab)

  traceTab.props.onClick()
  tree = render()
  assert.ok(tree.some((n) => n.type === 'PacketTracePanel'))

  diffTab.props.onClick()
  tree = render()
  assert.ok(tree.some((n) => n.type === 'ConfigDiffPanel'))

  activeSection = 'Policies & NAT'
  tree = render()
  const polTab = tree.find((n) => n.props?.role === 'tab' && n.props?.children === 'Policy Lookup')
  assert.ok(polTab)
  polTab.props.onClick()
  tree = render()
  assert.ok(tree.some((n) => n.type === 'PolicyLookupPanel'))
  assert.ok(!tree.some((n) => n.props?.className === 'report-toolbar fw-table-toolbar'))

  activeSection = 'Interfaces & Network'
  tree = render()
  const routeTab = tree.find((n) => n.props?.role === 'tab' && n.props?.children === 'Route Lookup')
  assert.ok(routeTab)
  routeTab.props.onClick()
  tree = render()
  assert.ok(tree.some((n) => n.type === 'RouteLookupPanel'))
})

test('PublicExposureCard gates live exposure probe on liveDeviceAccess and SecurityAuditPanel renders unified audit sections', async () => {
  const { PublicExposureCard, SecurityAuditPanel } = await vite.load('/src/features/report/SecurityAuditPanel.tsx')
  const { SourceReport } = await vite.load('/src/features/report/SourceReport.tsx')

  const renderExposure = (liveDeviceAccess) => renderToStaticMarkup(createElement(PublicExposureCard, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    audit: SAMPLE_AUDIT,
    liveDeviceAccess,
  }))

  const publicExposureHtml = renderExposure(false)
  assert.ok(publicExposureHtml.includes('Public Management &amp; High-Risk VIP Exposure (1)'))
  assert.ok(!publicExposureHtml.includes('Verify Live Reachability'))
  assert.ok(publicExposureHtml.includes('local/desktop mode only'))
  assert.ok(renderExposure(true).includes('Verify Live Reachability'))

  const auditHtml = renderToStaticMarkup(createElement(SecurityAuditPanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    liveDeviceAccess: false,
    initialAudit: SAMPLE_AUDIT,
  }))

  assert.ok(!auditHtml.includes('Download Audit Report'))
  assert.ok(!auditHtml.includes('id="fg_lifecycle_card"'))
  assert.ok(!auditHtml.includes('Public Management &amp; High-Risk VIP Exposure'))
  assert.ok(!auditHtml.includes('Connectivity &amp; Storage Posture'))
  assert.ok(!auditHtml.includes('🩺'))
  assert.ok(!auditHtml.includes('📜'))
  assert.ok(!auditHtml.includes('🧹'))
  assert.ok(auditHtml.includes('audit-summary-strip'))
  assert.ok(auditHtml.includes('Quick Security &amp; Hygiene Audit (1)'))
  assert.ok(auditHtml.includes('Certificates (2)'))
  assert.ok(auditHtml.includes('Flagged (1)'))
  assert.ok(auditHtml.includes('vpn.example.test'))
  assert.ok(!auditHtml.includes('valid.example.test'), 'Flagged certificate view is active by default when flagged certs exist')
  assert.ok(auditHtml.includes('Rule Hygiene &amp; Unused Objects'))
  assert.ok(auditHtml.includes('audit-table-wrap'))
  assert.ok(auditHtml.includes('audit-table'))
  assert.ok(auditHtml.includes('Showing 1 of 2 certificates'))

  const populatedHygieneAudit = {
    ...SAMPLE_AUDIT,
    hygiene: {
      unused_objects: [
        { category: 'Address', name: 'old_host', scope: 'root', value: '10.0.0.5/32' },
        { category: 'Service', name: 'old_port', scope: 'root', value: 'tcp/8088' },
      ],
      hygiene_issues: [
        { severity: 'Medium', tone: 'warn', finding: 'Broad Any/All Rule', target: 'R42', details: 'Allows all services' },
      ],
      counts: { unused: 2, disabled: 1, broad: 1, extra: 0 },
      cleanup_cli: 'config firewall address\n  delete "old_host"\nend',
    },
  }
  const hygieneHtml = renderToStaticMarkup(createElement(SecurityAuditPanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
    liveDeviceAccess: false,
    initialAudit: populatedHygieneAudit,
  }))
  assert.ok(hygieneHtml.includes('audit-kpi-grid'))
  assert.ok(hygieneHtml.includes('Hygiene Issues (1)'))
  assert.ok(hygieneHtml.includes('Unused Objects (2)'))
  assert.ok(hygieneHtml.includes('Cleanup CLI'))
  assert.ok(hygieneHtml.includes('Showing 1 of 1 issues'))

  const fgHtml = renderToStaticMarkup(createElement(SourceReport, reportProps('fortigate')))
  const asaHtml = renderToStaticMarkup(createElement(SourceReport, reportProps('cisco_asa')))
  assert.ok(!fgHtml.includes('Security &amp; Health →'))
  assert.ok(!asaHtml.includes('Security &amp; Health →'))
  assert.ok(!asaHtml.includes('report-tab-Security%20Audit'))

  // Verify Overview mounts LifecycleCard & PublicExposureCard (without Validation card),
  // Security Audit mounts SecurityAuditPanel directly, and Diagnostics & Coverage mounts Config Warnings
  const { hooks, resetCursor } = createHookHarness()
  const modExports = loadSourceReport(hooks, {
    overrides: {
      '../source/sourceApi': { fetchSecurityAudit: async () => SAMPLE_AUDIT },
      './ExcelExportControls': { ExcelExportControls: 'ExcelExportControls' },
      './LifecycleCard': { LifecycleCard: 'LifecycleCard' },
    },
  })
  const baseProps = reportProps('fortigate')
  const fgData = {
    ...baseProps.data,
    summary: { ...baseProps.data.summary, lifecycle: SAMPLE_LIFECYCLE },
    sections: {
      ...baseProps.data.sections,
      validation: [{ severity: 'warning', domain: 'policy', object_name: '1', message: 'Disabled policy' }],
    },
  }
  let activeSection = 'Overview'
  const renderTree = () => {
    resetCursor()
    return nodes(modExports.SourceReport({
      ...baseProps,
      data: fgData,
      activeSection,
      onSectionChange(next) { activeSection = next },
    }))
  }
  let tree = renderTree()
  const lifecycleNode = tree.find((n) => n.type === 'LifecycleCard')
  assert.ok(lifecycleNode, 'Overview renders LifecycleCard')
  assert.equal(lifecycleNode.props.lifecycle, SAMPLE_LIFECYCLE)
  assert.ok(tree.some((n) => n.type === 'PublicExposureCard'), 'Overview renders PublicExposureCard')
  assert.equal(tree.some((n) => n.props?.children === 'Review findings →'), false, 'Overview must not render Validation card')

  activeSection = 'Security Audit'
  tree = renderTree()
  assert.equal(tree.some((n) => n.props?.role === 'tab' && String(n.props?.children ?? '').includes('Validation Findings')), false)
  const panelNode = tree.find((n) => n.type === 'SecurityAuditPanel')
  assert.ok(panelNode, 'SecurityAuditPanel is mounted directly on Security Audit')
  assert.equal(panelNode.props.lifecycle, undefined)

  activeSection = 'Diagnostics & Coverage'
  tree = renderTree()
  const warningsTab = tree.find((n) => n.props?.role === 'tab' && String(n.props?.children ?? '').includes('Config Warnings'))
  assert.ok(warningsTab, 'Diagnostics & Coverage includes Config Warnings tab')
})

test('LifecycleCard renders initial snapshot card and badge cleanly via SSR', async () => {
  const { LifecycleCard } = await vite.load('/src/features/report/LifecycleCard.tsx')
  assert.equal(isLifecycleCardData(SAMPLE_LIFECYCLE), true)
  assert.equal(isLifecycleCardData(null), false)

  const html = renderToStaticMarkup(createElement(LifecycleCard, { lifecycle: SAMPLE_LIFECYCLE }))
  assert.ok(html.includes('id="fg_lifecycle_card"'))
  assert.ok(html.includes('id="fg_lifecycle_badge"'))
  assert.ok(html.includes('fw-badge-allow'))
  assert.ok(html.includes('FortiGate-60F'))
  assert.ok(html.includes('Fetching live data…'))
})

test('LifecycleCard refreshes from /api/lifecycle when needs_live_refresh is true and keeps snapshot on failure', async () => {
  function runEffectCase({ fetchImpl, initialCard }) {
    const { hooks, slots, resetCursor, flushEffects } = createHookHarness()
    const modExports = loadCjs('../src/features/report/LifecycleCard.tsx', {
      react: hooks,
      'react/jsx-runtime': jsxRuntime,
      '../source/sourceApi': { fetchLifecycleStatus: fetchImpl },
    })
    const render = () => {
      resetCursor()
      return modExports.LifecycleCard({ lifecycle: initialCard })
    }
    render()
    const cleanups = flushEffects()
    return {
      render,
      cleanups,
      getCard: () => (slots[0]?.forLifecycle === initialCard ? slots[0].card : initialCard),
    }
  }

  // Case 1: Live refresh succeeds and updates card in place
  const liveCard = {
    ...SAMPLE_LIFECYCLE,
    needs_live_refresh: false,
    subtitle: 'Model & FortiOS branch support status · Source: Live (endoflife.date + Fortinet RSS)',
    badge: { id: 'fg_lifecycle_badge', text: 'Patch Available (7.4.99)', variant: 'warn' },
  }
  const calls = []
  const okCase = runEffectCase({
    initialCard: SAMPLE_LIFECYCLE,
    fetchImpl: async (params) => {
      calls.push(params)
      return liveCard
    },
  })
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0], SAMPLE_LIFECYCLE.refresh_params)
  assert.equal(okCase.getCard().badge.text, 'Patch Available (7.4.99)')
  assert.equal(okCase.getCard().needs_live_refresh, false)

  // Case 2: Live refresh fails -> keeps offline snapshot rows and updates subtitle cleanly
  const failCase = runEffectCase({
    initialCard: SAMPLE_LIFECYCLE,
    fetchImpl: async () => {
      throw new Error('offline')
    },
  })
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(failCase.getCard().badge.text, 'Lifecycle OK · Up to Date')
  assert.equal(failCase.getCard().needs_live_refresh, false)
  assert.ok(!failCase.getCard().subtitle.includes('Fetching live data'))
  assert.ok(failCase.getCard().subtitle.includes('Offline snapshot (2026-11-24)'))

  // Case 3: needs_live_refresh=false skips network fetch
  const skippedCalls = []
  runEffectCase({
    initialCard: { ...SAMPLE_LIFECYCLE, needs_live_refresh: false },
    fetchImpl: async (params) => {
      skippedCalls.push(params)
      return liveCard
    },
  })
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(skippedCalls.length, 0)
})

test('VPN inspector subsection and labels integrate cleanly in reportPresentation and VpnInspectorView', async () => {
  const { VpnInspectorView } = await vite.load('/src/features/report/VpnInspectorView.tsx')
  const { WhereUsedPanel } = await vite.load('/src/features/report/WhereUsedPanel.tsx')

  assert.equal(fieldLabel('vpn_inspector'), 'Site-to-Site Inspector')
  const sections = reportSections({
    vpn_inspector: [
      {
        health: 'warning',
        name: 'vpn-hq',
        vdom: 'root',
        remote_gateway: '198.51.100.1',
        ike_version: '2',
        tunnel_interface: 'vpn-hq',
        zones: ['VPN-ZONE'],
        phase2_count: 1,
        route_count: 1,
        policy_count: 1,
        finding_count: 1,
        phase1: { ike_version: '2', proposal: ['aes256-sha256'], dh_groups: [14] },
        phase2: [{ name: 'p2', local_selector: '10.10.1.0/24', remote_selector: '172.16.50.0/24' }],
        binding: { tunnel_interface: 'vpn-hq', zones: ['VPN-ZONE'], virtual_router: 'VDOM root' },
        routes: [{ route_id: 1, destination: '172.16.50.0/24', device: 'vpn-hq' }],
        policies: [{ policy_id: 10, name: 'Allow-VPN', action: 'accept', nat: 'enable', status: 'enable' }],
        findings: [{ severity: 'warning', code: 'ACCIDENTAL_NAT', message: 'NAT enabled on VPN policy' }],
      },
    ],
    vpn_tunnels: [{ name: 'vpn-hq' }],
  })
  const vpnGroup = sections.find((item) => item.label === 'VPN')
  assert.ok(vpnGroup)
  assert.equal(vpnGroup.subsections[0].key, 'vpn_inspector')

  const vpnHtml = renderToStaticMarkup(createElement(VpnInspectorView, {
    rows: vpnGroup.subsections[0].rows,
    vendor: 'fortigate',
  }))
  assert.ok(vpnHtml.includes('vpn-hq'))
  assert.ok(vpnHtml.includes('ACCIDENTAL_NAT'))
  assert.ok(vpnHtml.includes('Layer 4'))

  const searchHtml = renderToStaticMarkup(createElement(WhereUsedPanel, {
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
  }))
  assert.ok(searchHtml.includes('Global IP / Object'))
})
