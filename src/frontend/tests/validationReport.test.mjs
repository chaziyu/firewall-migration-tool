import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import * as presentation from '../src/features/report/reportPresentation.ts'
import { createHookHarness, createSharedVite, loadSourceReport } from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

test('validation count labels distinguish zero, one and multiple findings', () => {
  const exports = loadSourceReport({}, { extraExports: ['ValidationSummary'] })
  for (const severity of ['error', 'warning']) {
    for (const count of [0, 1, 2]) {
      const rows = Array.from({ length: count }, () => ({ severity, message: 'review source' }))
      const html = renderToStaticMarkup(exports.ValidationSummary({ rows, activeGroup: '', onGroupChange() {} }))
      assert.ok(html.includes(`<strong>${count} ${count === 1 ? 'finding' : 'findings'}</strong>`))
      const errors = severity === 'error' ? count : 0
      const warnings = severity === 'warning' ? count : 0
      assert.ok(html.includes(`<span>${errors} ${errors === 1 ? 'error' : 'errors'}</span>`))
      assert.ok(html.includes(`<span>${warnings} ${warnings === 1 ? 'warning' : 'warnings'}</span>`))
    }
  }
})

test('native IPsec and static-route reference findings have source-object links', () => {
  const exports = loadSourceReport({}, { extraExports: ['ValidationTable'] })
  for (const object_type of ['ipsec-tunnel', 'static-route', 'route']) {
    const row = { domain: 'reference', object_type, object_name: 'owner', severity: 'warning' }
    let navigated
    const tree = exports.ValidationTable({ rows: [row], selected: null, onSelect() {}, onNavigate(value) { navigated = value }, grouped: false })
    const html = renderToStaticMarkup(tree)
    assert.ok(!html.includes('<th>Review</th>'), 'Review column is removed')
    assert.match(html, /View object/)
    const objectCell = tree.props.children.props.children[1].props.children[0].props.children[0]
    const viewButton = objectCell.props.children.props.children[1]
    viewButton.props.onClick({ stopPropagation() {} })
    assert.equal(navigated, row)
    assert.ok(html.includes('owner'))
  }
})

test('warning group selection settles and retains the matching findings', () => {
  const { hooks, resetCursor, isPending, clearPending } = createHookHarness()
  const exports = loadSourceReport(hooks, { extraExports: ['ValidationReport'] })
  const rows = Array.from({ length: 209 }, (_, i) => ({ severity: 'warning', domain: 'nat', message: i < 204 ? 'wan1' : 'any', object_name: String(i) }))
  function render() {
    let tree
    let attempts = 0
    do {
      assert.ok(++attempts < 25, 'Validation entered a render loop')
      clearPending()
      resetCursor()
      tree = exports.ValidationReport({ data: { sections: { validation: rows } }, reportScope: '', onReportScope() {}, active: true })
    } while (isPending())
    return tree
  }
  function table(tree) { return tree.props.children[4].props.children[0] }
  let tree = render()
  for (const group of presentation.findingGroups(rows)) {
    tree.props.children[2].props.onGroupChange(group.key)
    tree = render()
    assert.equal(table(tree).props.rows.length, group.count)
    assert.ok(table(tree).props.rows.every((row) => presentation.findingGroupKey(row) === group.key))
  }
  tree.props.children[2].props.onGroupChange('')
  assert.equal(table(render()).props.grouped, false)
})

test('overview displays public management exposure warning when interface allowaccess findings exist', async () => {
  const { SourceReport } = await vite.load('/src/features/report/SourceReport.tsx')
  const html = renderToStaticMarkup(createElement(SourceReport, {
    data: {
      vendor: 'fortigate',
      sections: {
        validation: [
          { severity: 'warning', domain: 'interface', field: 'allowaccess', object_name: 'wan1', message: "Public-facing interface 'wan1' exposes management access (https, ssh)." },
        ],
      },
    },
    excelProfile: 'fast', onExcelProfileChange() {}, exporting: false, exportStatus: '', onExport() {},
  })).replace(/<!-- -->/g, '')
  assert.ok(html.includes('Public management exposure (1)'))
  assert.ok(html.includes('wan1'))
})
