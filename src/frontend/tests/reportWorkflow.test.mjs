import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createHookHarness, createSharedVite, loadSourceReport, nodes } from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

test('topology rows render without load-more truncation, reset on filters, and keep full inspector values', () => {
  const { hooks, resetCursor, isPending, clearPending } = createHookHarness()
  const exports = loadSourceReport(hooks, { overrides: { './ReportDetails': { ReportDetails: 'ReportDetails' } } })
  const rows = Array.from({ length: 450 }, (_, index) => ({ name: `port-${index}`, vdom: index % 2 ? 'branch' : 'root', ip: Array.from({ length: 12 }, (_, i) => `192.0.${index % 256}.${i}/24`), enabled: false, metric: 0 }))
  const data = { vendor: 'fortigate', sections: { interface_topology: rows } }
  const beforeData = structuredClone(data)
  let activeSection = 'Overview'
  function render() {
    let tree
    let attempts = 0
    do {
      assert.ok(++attempts < 25, 'Report entered a render loop')
      clearPending()
      resetCursor()
      tree = exports.SourceReport({
        data,
        activeSection,
        onSectionChange(next) { activeSection = next },
        excelProfile: 'fast',
        onExcelProfileChange() {},
        exporting: false,
        exportStatus: '',
        onExport() {},
      })
    } while (isPending())
    return nodes(tree)
  }
  let tree = render()
  activeSection = 'Interfaces & Network'
  tree = render()
  const table = () => tree.find((node) => node.type?.name === 'SourceRowsTable')
  assert.equal(table().props.rows.length, 450)
  assert.equal(tree.some((node) => node.props.children === 'Load more rows'), false)
  const first = table().props.rows[0]
  table().props.onSelect(first)
  tree = render()
  const inspector = tree.find((node) => node.type === 'ReportDetails')
  assert.deepEqual(inspector.props.row.ip, rows[0].ip)
  assert.equal(inspector.props.row.enabled, false)
  assert.equal(inspector.props.row.metric, 0)
  inspector.props.next()
  tree = render()
  assert.equal(tree.find((node) => node.type === 'ReportDetails').props.row.name, 'port-1')
  tree.find((node) => node.props['aria-label'] === 'Filter report scope').props.onChange({ target: { value: 'branch' } })
  tree = render()
  assert.equal(table().props.rows.length, 225)
  assert.ok(table().props.rows.every((row) => row.vdom === 'branch'))
  tree.find((node) => node.props.type === 'search').props.onChange({ target: { value: 'port-449' } })
  tree = render()
  assert.equal(table().props.rows.length, 1)
  assert.equal(tree.some((node) => node.props.children === 'Load more rows'), false)
  assert.deepEqual(data, beforeData)
})

test('Excel controls explain vendor evidence and retain progress and disabled states', async () => {
  const { ExcelExportControls } = await vite.load('/src/features/report/ExcelExportControls.tsx')
  for (const [vendor, evidence] of [
    ['fortigate', 'FAST omits FortiGate Source Inventory and Extraction Coverage.'],
    ['palo_alto', 'FAST omits PAN-OS Source Inventory, Extraction Coverage, and PAN-OS Source Appendix'],
    ['cisco_asa', 'FAST omits Source Inventory and Extraction Coverage.'],
    ['juniper_srx', 'FAST omits Source Inventory and Extraction Coverage.'],
    ['cisco_ftd', 'FAST and FULL retain source evidence worksheets.'],
    ['checkpoint', 'FAST and FULL retain source evidence worksheets.'],
  ]) {
    const html = renderToStaticMarkup(createElement(ExcelExportControls, { vendor, profile: 'full', exporting: true, onProfileChange() {}, onExport() {} }))
    assert.ok(html.includes(evidence), vendor)
    assert.match(html, /<option value="full" selected="">FULL/)
    assert.match(html, /aria-describedby=/)
    assert.match(html, /<select[^>]*disabled=""/)
    assert.match(html, /<button[^>]*disabled=""[^>]*aria-busy="true"/)
    assert.ok(html.includes('Preparing workbook'))
    assert.ok(html.includes('does not imply complete extraction'))
    assert.match(html, /<details class="excel-profile-help"><summary>About Excel profiles<\/summary>/)
    assert.ok(!html.includes('<details class="excel-profile-help" open'), 'Profile explanation is collapsed by default')
  }
})

test('report table keeps a stable scroll viewport and row details', () => {
  const originalWindow = globalThis.window
  const originalObserver = globalThis.ResizeObserver
  const listeners = []
  let observerCreated = false
  let selected
  const table = { closest: () => ({}), getBoundingClientRect: () => ({ top: 320 }) }
  globalThis.window = { addEventListener: (name) => listeners.push(name), removeEventListener() {} }
  globalThis.ResizeObserver = class {
    constructor() { observerCreated = true }
    observe() {}
    disconnect() {}
  }
  try {
    const hooks = { useRef: () => ({ current: table }), useState: () => [undefined, () => {}], useEffect: (callback) => callback() }
    const exports = loadSourceReport(hooks, { extraExports: ['SourceRowsTable'] })
    const tree = exports.SourceRowsTable({ rows: [{ name: 'port1' }], columns: ['name'], onSelect(row) { selected = row } })
    const rendered = nodes(tree)
    const tableWrap = rendered.find((node) => node.props.className === 'report-table-wrap')
    assert.equal(tableWrap.props.role, 'region')
    assert.equal(tableWrap.props.tabIndex, 0)
    assert.equal(tableWrap.props.style, undefined)
    assert.deepEqual(listeners, [], 'Table height does not listen for page scroll or resize')
    assert.equal(observerCreated, false, 'Table height does not use ResizeObserver')
    const identity = rendered.find((node) => node.props.className === 'report-identity-content')
    const details = nodes(identity).find((node) => node.props['aria-label'] === 'Details for port1')
    details.props.onClick()
    assert.equal(selected.name, 'port1', 'Rows retain their Details action')

    const css = readFileSync(new URL('../src/App.css', import.meta.url), 'utf8')
    const tableRule = css.match(/\.source-report \.report-table-wrap\s*\{([^}]*)\}/)?.[1] ?? ''
    assert.match(tableRule, /height:\s*auto/)
    assert.match(tableRule, /max-height:\s*clamp\(320px,\s*75svh,\s*820px\)/)
    assert.match(tableRule, /overflow:\s*auto/)
    assert.match(css, /\.source-report \.report-table th\s*\{[^}]*position:\s*sticky/)
    assert.equal(Math.max(320, Math.min(900 * 0.75, 820)), 675, 'Desktop table height follows 75svh')
    assert.equal(Math.max(320, Math.min(390 * 0.75, 820)), 320, 'Mobile table height respects its minimum')
  } finally {
    globalThis.window = originalWindow
    globalThis.ResizeObserver = originalObserver
  }
})

test('large report tables virtualize on initial mount before viewport measurement', () => {
  const hooks = {
    useRef: (initial) => ({ current: initial }),
    useState: (initial) => [initial, () => {}],
    useEffect: () => {},
  }
  const exports = loadSourceReport(hooks, { extraExports: ['SourceRowsTable'] })
  const rows = Array.from({ length: 5209 }, (_, index) => ({ name: `addr-${index}`, vdom: 'root' }))
  const tree = exports.SourceRowsTable({ rows, columns: ['name', 'vdom'], selected: null, hasSource: true, topology: false, onSelect() {} })
  const renderedRows = nodes(tree).filter((node) => node.type === 'tr' && node.props.className !== 'report-virtual-spacer')
  assert.ok(renderedRows.length > 1 && renderedRows.length < 50, `Expected bounded initial window, got ${renderedRows.length} rows`)
})

test('FortiGate reports always expose WiFi & Switch and all seven core tabs even when empty', () => {
  const { hooks, resetCursor, isPending, clearPending } = createHookHarness()
  const exports = loadSourceReport(hooks, { overrides: { './ReportDetails': { ReportDetails: 'ReportDetails' } } })
  const data = { vendor: 'fortigate', sections: { wireless_wtps: [], wireless_vaps: [], wtp_profiles: [], wids_profiles: [], managed_switches: [], switch_port_policies: [], nac_policies: [] } }
  let activeSection = 'WiFi & Switch'
  let tree
  let attempts = 0
  do {
    assert.ok(++attempts < 25, 'Report entered a render loop')
    clearPending()
    resetCursor()
    tree = exports.SourceReport({
      data,
      activeSection,
      onSectionChange(next) { activeSection = next },
      excelProfile: 'fast',
      onExcelProfileChange() {},
      exporting: false,
      exportStatus: '',
      onExport() {},
    })
  } while (isPending())
  const rendered = nodes(tree)
  const tabs = rendered.filter((node) => node.props.role === 'tab' && String(node.props.id ?? '').startsWith('subsection-tab-'))
  assert.deepEqual(
    tabs.map((node) => node.props.id),
    [
      'subsection-tab-wireless_wtps',
      'subsection-tab-wireless_vaps',
      'subsection-tab-wtp_profiles',
      'subsection-tab-wids_profiles',
      'subsection-tab-managed_switches',
      'subsection-tab-switch_port_policies',
      'subsection-tab-nac_policies',
    ],
  )
  assert.ok(tabs.every((node) => String(node.props.children).includes('(0)')))
})

test('FortiGate Interfaces & Network always shows SD-WAN tab and renders FCR-style SD-WAN sections', async () => {
  const { hooks, resetCursor, isPending, clearPending } = createHookHarness()
  const exports = loadSourceReport(hooks, { overrides: { './ReportDetails': { ReportDetails: 'ReportDetails' } } })

  const emptyData = { vendor: 'fortigate', sections: { interfaces: [{ name: 'port1', vdom: 'root' }] } }
  let activeSection = 'Interfaces & Network'
  const renderTree = (data) => {
    let tree
    let attempts = 0
    do {
      assert.ok(++attempts < 25, 'Report entered a render loop')
      clearPending()
      resetCursor()
      tree = exports.SourceReport({
        data,
        activeSection,
        onSectionChange(next) { activeSection = next },
        excelProfile: 'fast',
        onExcelProfileChange() {},
        exporting: false,
        exportStatus: '',
        onExport() {},
      })
    } while (isPending())
    return nodes(tree)
  }

  const emptyRendered = renderTree(emptyData)
  const sdwanTabEmpty = emptyRendered.find((node) => node.props.id === 'subsection-tab-sdwan')
  assert.ok(sdwanTabEmpty, 'SD-WAN tab should always be visible for FortiGate Interfaces & Network')
  assert.equal(String(sdwanTabEmpty.props.children), 'SD-WAN (0)')

  const sdwanRows = [{
    vdom: 'root',
    status: 'enable',
    zones: [{ name: 'virtual-wan-link' }],
    members: [{ seq_num: 1, interface: 'wan1', zone: 'virtual-wan-link', gateway: '192.0.2.1', status: 'enable' }],
    health_checks: [{ name: 'PingCheck', server: '8.8.8.8', protocol: 'ping', members: [1], sla: [{ id: 1, latency_threshold: 300 }] }],
    services: [{ id: 1, name: 'VideoConferencing', src: ['192.168.4.0/23'], mode: 'priority', link_cost_factor: 'bibandwidth', health_check: ['PingCheck'], priority_members: [1], status: 'enable' }],
  }]
  const sdwanData = {
    vendor: 'fortigate',
    sections: {
      interfaces: [{ name: 'wan1', vdom: 'root' }],
      sdwan: sdwanRows,
    },
  }
  let tree = renderTree(sdwanData)
  const sdwanTab = tree.find((node) => node.props.id === 'subsection-tab-sdwan')
  assert.equal(String(sdwanTab.props.children), 'SD-WAN (1)')
  sdwanTab.props.onClick()
  tree = renderTree(sdwanData)
  const sdwanViewNode = tree.find((node) => node.type === 'SdwanView')
  assert.ok(sdwanViewNode, 'Selecting SD-WAN tab should mount SdwanView')
  assert.equal(sdwanViewNode.props.rows.length, 1)

  const { SdwanView } = await vite.load('/src/features/report/SdwanView.tsx')
  const html = renderToStaticMarkup(createElement(SdwanView, { rows: sdwanRows, scope: '' }))
  assert.ok(html.includes('SD-WAN Status'))
  assert.ok(html.includes('SD-WAN Zones / Members'))
  assert.ok(html.includes('SD-WAN Rules'))
  assert.ok(html.includes('Performance SLA'))
  assert.ok(html.includes('VideoConferencing'))
  assert.ok(html.includes('PingCheck'))
  const emptyHtml = renderToStaticMarkup(createElement(SdwanView, { rows: [], scope: '' }))
  assert.ok(emptyHtml.includes('No SD-WAN configuration found.'))
})
