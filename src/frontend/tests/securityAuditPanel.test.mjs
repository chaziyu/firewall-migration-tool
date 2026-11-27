import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

const SAMPLE_AUDIT = {
  vendor: 'fortigate',
  certificates: [{ name: 'gw-cert', store: 'Local', common_name: 'vpn.example.test', san: '', issuer: '', not_before: '', expires: '', days_left: '14', status: 'Expiring Soon' }],
  certificate_summary: { total: 1, expired: 0, expiring_soon: 1, valid: 0, no_pem: 0 },
  exposure: [{ interface: 'wan1', ip: '1.1.1.2', protocols: ['HTTPS'], note: 'Unrestricted', restricted: false, severity: 'critical', targets: [{ ip: '1.1.1.2', port: 443, protocol: 'HTTPS' }] }],
  posture: { internet: 'Connected', internet_sub: '', disk: 'Yes', disk_sub: '' },
  hygiene: { unused_objects: [], hygiene_issues: [], counts: { unused: 0, disabled: 0, broad: 0, extra: 0 }, cleanup_cli: '' },
  quick_audit: { findings: [], high_count: 0, med_count: 0, info_count: 0 },
}

const reportProps = (vendor) => ({
  data: { vendor, source_evidence: { vendor, source_text: '' }, summary: { objects: {}, validation: { severity_counts: {} } }, sections: { interfaces: [], policies: [], validation: [] } },
  excelProfile: 'fast',
  onExcelProfileChange: () => { },
  exporting: false,
  exportStatus: '',
  onExport: () => { },
})

const SAMPLE_LIFECYCLE = {
  id: 'fg_lifecycle_card',
  vendor: 'fortigate',
  title: 'Lifecycle & Firmware',
  subtitle: 'Model & FortiOS branch support status',
  source_label: 'Offline snapshot',
  needs_live_refresh: false,
  badge: { id: 'fg_lifecycle_badge', text: 'Lifecycle OK · Up to Date', variant: 'allow' },
  rows: [{ label: 'Hardware Model', value: 'FortiGate-60F' }],
}

test('SecurityAuditPanel gates live exposure probe on liveDeviceAccess and renders LifecycleCard, Certificate Alerts, and Quick Audit', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { SecurityAuditPanel } = await server.ssrLoadModule('/src/features/report/SecurityAuditPanel.tsx')
    const { SourceReport } = await server.ssrLoadModule('/src/features/report/SourceReport.tsx')

    const renderAudit = (liveDeviceAccess) => renderToStaticMarkup(createElement(SecurityAuditPanel, {
      vendor: 'fortigate',
      sourceEvidence: { vendor: 'fortigate', source_text: '' },
      liveDeviceAccess,
      initialAudit: SAMPLE_AUDIT,
      lifecycle: SAMPLE_LIFECYCLE,
    }))

    const publicHtml = renderAudit(false)
    assert.ok(publicHtml.includes('Download Audit Report'))
    assert.ok(publicHtml.includes('id="fg_lifecycle_card"'))
    assert.ok(publicHtml.includes('Certificate Expiry Alerts'))
    assert.ok(publicHtml.includes('Quick Security &amp; Hygiene Audit'))
    assert.ok(publicHtml.includes('High Risk'))
    assert.ok(publicHtml.includes('vpn.example.test'))
    assert.ok(!publicHtml.includes('Verify Live Reachability'))
    assert.ok(publicHtml.includes('local/desktop mode only'))
    assert.ok(renderAudit(true).includes('Verify Live Reachability'))

    const fgHtml = renderToStaticMarkup(createElement(SourceReport, reportProps('fortigate')))
    const asaHtml = renderToStaticMarkup(createElement(SourceReport, reportProps('cisco_asa')))
    assert.ok(!fgHtml.includes('Security &amp; Health →'))
    assert.ok(!asaHtml.includes('Security &amp; Health →'))
    assert.ok(!asaHtml.includes('report-tab-Security%20Audit'))

    // Verify Security & Health defaults to Security Audit for FortiGate and mounts LifecycleCard inside SecurityAuditPanel
    const { readFileSync } = await import('node:fs')
    const ts = (await import('typescript')).default
    const jsxRuntime = await import('react/jsx-runtime')
    const presentation = await import('../src/features/report/reportPresentation.ts')
    const slots = []
    let cursor = 0
    const hooks = {
      useState(initial) {
        const idx = cursor++
        if (!(idx in slots)) slots[idx] = typeof initial === 'function' ? initial() : initial
        return [slots[idx], (v) => { slots[idx] = typeof v === 'function' ? v(slots[idx]) : v }]
      },
      useMemo: (fn) => fn(),
      useRef: (v) => ({ current: v }),
      useEffect() {},
    }
    const source = readFileSync(new URL('../src/features/report/SourceReport.tsx', import.meta.url), 'utf8')
    const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
    const modExports = {}
    const modules = {
      react: hooks,
      'react/jsx-runtime': jsxRuntime,
      './reportPresentation': presentation,
      '../source/sourceApi': { fetchSecurityAudit: async () => SAMPLE_AUDIT },
      './ReportDetails': {},
      './ExcelExportControls': { ExcelExportControls: 'ExcelExportControls' },
      './LifecycleCard': { LifecycleCard: 'LifecycleCard' },
      './WhereUsedPanel': { WhereUsedPanel: 'WhereUsedPanel' },
      './VpnInspectorView': { VpnInspectorView: 'VpnInspectorView' },
      './SecurityAuditPanel': { SecurityAuditPanel: 'SecurityAuditPanel' },
      '../../components/common/tabKeyboard': {},
      '../../components/common/ErrorBanner': {},
    }
    new Function('require', 'exports', compiled)((name) => modules[name], modExports)
    const nodes = (node) => (Array.isArray(node) ? node.flatMap(nodes) : node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : [])
    const fgData = { ...reportProps('fortigate').data, summary: { ...reportProps('fortigate').data.summary, lifecycle: SAMPLE_LIFECYCLE } }
    const renderTree = () => {
      cursor = 0
      return nodes(modExports.SourceReport({ ...reportProps('fortigate'), data: fgData }))
    }
    let tree = renderTree()
    assert.equal(tree.some((n) => n.type === 'LifecycleCard'), false, 'Overview must not render LifecycleCard')
    tree.find((n) => n.props.role === 'tab' && n.props.children === 'Security & Health').props.onClick()
    tree = renderTree()
    const auditTab = tree.find((n) => n.props.role === 'tab' && n.props.children === 'Security Audit')
    assert.ok(auditTab && auditTab.props['aria-selected'] === true, 'Security & Health defaults to Security Audit tab')
    const panelNode = tree.find((n) => n.type === 'SecurityAuditPanel')
    assert.ok(panelNode, 'SecurityAuditPanel is mounted on Security & Health')
    assert.equal(panelNode.props.lifecycle, SAMPLE_LIFECYCLE)
  } finally {
    await server.close()
  }
})
