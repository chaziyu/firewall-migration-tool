import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/report/reportPresentation.ts'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

function nodes(node) {
  if (Array.isArray(node)) return node.flatMap(nodes)
  return node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : []
}

test('topology rows load incrementally, reset on filters, and keep full inspector values', () => {
  const slots = []
  let cursor = 0
  let pending = false
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) slots[index] = initial
      return [slots[index], (value) => {
        const next = typeof value === 'function' ? value(slots[index]) : value
        if (!Object.is(next, slots[index])) { slots[index] = next; pending = true }
      }]
    },
    useMemo(factory, dependencies) {
      const index = cursor++
      const previous = slots[index]
      if (!previous || dependencies.some((value, i) => !Object.is(value, previous.dependencies[i]))) {
        slots[index] = { dependencies, value: factory() }
      }
      return slots[index].value
    },
    useRef(value) { return hooks.useMemo(() => ({ current: value }), []) },
    useEffect() {},
  }
  const source = readFileSync(new URL('../src/features/report/SourceReport.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const exports = {}
  const modules = { react: hooks, 'react/jsx-runtime': jsxRuntime, './reportPresentation': presentation,
    './ReportDetails': { ReportDetails: 'ReportDetails' }, './ExcelExportControls': {}, '../../components/common/tabKeyboard': {}, '../../components/common/ErrorBanner': {} }
  new Function('require', 'exports', compiled)((name) => { assert.ok(name in modules); return modules[name] }, exports)
  const rows = Array.from({ length: 450 }, (_, index) => ({ name: `port-${index}`, vdom: index % 2 ? 'branch' : 'root', ip: Array.from({ length: 12 }, (_, i) => `192.0.${index % 256}.${i}/24`), enabled: false, metric: 0 }))
  const data = { vendor: 'fortigate', sections: { interface_topology: rows } }
  const before = structuredClone(data)
  function render() {
    let tree
    let attempts = 0
    do {
      assert.ok(++attempts < 25, 'Report entered a render loop')
      pending = false
      cursor = 0
      tree = exports.SourceReport({ data, excelProfile: 'fast', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {} })
    } while (pending)
    return nodes(tree)
  }
  let tree = render()
  tree.find((node) => node.props.role === 'tab' && node.props.children === 'Interfaces').props.onClick()
  tree = render()
  const table = () => tree.find((node) => node.type?.name === 'SourceRowsTable')
  assert.equal(table().props.rows.length, 200)
  tree.find((node) => node.props.children === 'Load more rows').props.onClick()
  tree = render()
  assert.equal(table().props.rows.length, 400)
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
  assert.equal(table().props.rows.length, 200)
  assert.ok(table().props.rows.every((row) => row.vdom === 'branch'))
  tree.find((node) => node.props.type === 'search').props.onChange({ target: { value: 'port-449' } })
  tree = render()
  assert.equal(table().props.rows.length, 1)
  assert.equal(tree.some((node) => node.props.children === 'Load more rows'), false)
  assert.deepEqual(data, before)
})

test('Excel controls explain vendor evidence and retain progress and disabled states', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { ExcelExportControls } = await server.ssrLoadModule('/src/features/report/ExcelExportControls.tsx')
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
  } finally { await server.close() }
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
    const source = readFileSync(new URL('../src/features/report/SourceReport.tsx', import.meta.url), 'utf8')
    const compiled = ts.transpileModule(`${source}\nexport { SourceRowsTable }`, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
    const exports = {}
    const hooks = { useRef: () => ({ current: table }), useState: () => [undefined, () => {}], useEffect: (callback) => callback() }
    const modules = { react: hooks, 'react/jsx-runtime': jsxRuntime, './reportPresentation': presentation, './ReportDetails': {}, './ExcelExportControls': {}, '../../components/common/tabKeyboard': {}, '../../components/common/ErrorBanner': {} }
    new Function('require', 'exports', compiled)((name) => modules[name], exports)
    const tree = exports.SourceRowsTable({ rows: [{ name: 'port1' }], columns: ['name'], loadMoreRef: { current: null }, onSelect(row) { selected = row } })
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
    assert.match(tableRule, /height:\s*clamp\(320px,\s*75svh,\s*820px\)/)
    assert.match(tableRule, /overflow:\s*auto/)
    assert.match(tableRule, /scrollbar-gutter:\s*stable/)
    assert.match(css, /\.source-report \.report-table th\s*\{[^}]*position:\s*sticky/)
    assert.equal(Math.max(320, Math.min(900 * 0.75, 820)), 675, 'Desktop table height follows 75svh')
    assert.equal(Math.max(320, Math.min(390 * 0.75, 820)), 320, 'Mobile table height respects its minimum')
  } finally {
    globalThis.window = originalWindow
    globalThis.ResizeObserver = originalObserver
  }
})
