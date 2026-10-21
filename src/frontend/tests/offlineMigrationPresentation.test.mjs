import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as React from 'react'
import * as jsxRuntime from 'react/jsx-runtime'
import { renderToStaticMarkup } from 'react-dom/server'
import { offlineReviewRow, isReady } from '../src/features/migration/paloAltoToFortigate/reviewPresentation.ts'

function load(name, react = React) {
  const code = ts.transpileModule(readFileSync(new URL(`../src/features/migration/components/${name}.tsx`, import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
  }).outputText
  const modules = { react, 'react/jsx-runtime': jsxRuntime, '../../../components/common/Button': { Button: 'button' }, '../../../components/common/tabKeyboard': { tabKeyboard() {} } }
  const exports = {}
  new Function('require', 'exports', code)((name) => { assert.ok(name in modules, name); return modules[name] }, exports)
  return exports[name]
}

test('shared review refuses incomplete approval dependencies and retains exact scoped settings', () => {
  const Component = load('OfflineMigrationReview')
  const rows = [
    { key: 'object', family: 'address', sourceScope: 'vsys:a', sourceName: 'same-name', target: 'root / network', operation: 'REUSE', settings: { subnet: '10.0.0.0/24' }, dependencies: [], reasons: [], ready: true },
    { key: 'rule', family: 'policy', sourceScope: 'vsys:b', sourceName: 'same-name', target: 'root / rule', operation: 'CREATE', settings: { action: 'accept' }, dependencies: ['object'], reasons: [], ready: true },
  ]
  const props = { id: 'test', title: 'Target', rows, busy: false, tab: 'changes', selected: ['rule'], inputCount: 0, manualCount: 0, approveLabel: 'Confirm approval', onSelect() {}, onPreview() {}, onApprove() {}, onCancel() {}, onSetup() {}, onTabChange() {} }
  const incomplete = renderToStaticMarkup(React.createElement(Component, { ...props, approvalKeys: ['rule'] }))
  assert.match(incomplete, /Resolve blocked or missing prerequisites/)
  assert.match(incomplete, /<button disabled="">Confirm approval<\/button>/)
  const complete = renderToStaticMarkup(React.createElement(Component, { ...props, approvalKeys: ['object', 'rule'] }))
  assert.doesNotMatch(complete, /<button disabled="">Confirm approval<\/button>/)
  assert.match(complete, /Added prerequisite/)
  assert.match(complete, /10.0.0.0\/24/)
  assert.match(complete, /vsys:a/)
  assert.match(complete, /vsys:b/)
})

test('pair display adapter never makes unapproved or unknown dispositions selectable', () => {
  const row = { key: 'key', family: 'address', source_scope: 'vsys:a', source_name: 'name', target_vdom: 'root', target_name: 'target', settings: [], dependencies: [], blocking_reasons: [], render_disposition: 'CREATE' }
  assert.equal(offlineReviewRow(row).ready, true)
  assert.equal(offlineReviewRow(row).sourceScope, 'vsys:a')
  for (const render_disposition of ['BLOCK', 'NOT_APPROVED', 'UNKNOWN', '']) assert.equal(isReady({ ...row, render_disposition }), false)
})

test('shared review filters identical names by native source scope without clearing selection', () => {
  const slots = []; let cursor = 0
  const Component = load('OfflineMigrationReview', { useCallback: (fn) => fn, useState: (initial) => {
    const index = cursor++; slots[index] ??= initial
    return [slots[index], (value) => { slots[index] = value }]
  } })
  const rows = ['vsys:a', 'vsys:b'].map((scope) => ({ key: scope, family: 'address', sourceScope: scope, sourceName: 'same-name', target: scope, operation: 'CREATE', settings: {}, dependencies: [], reasons: [], ready: true }))
  const props = { id: 'test', title: 'Target', rows, busy: false, tab: 'changes', selected: ['vsys:a'], approvalKeys: null, inputCount: 0, manualCount: 0 }
  const nodes = (tree) => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []
  const render = () => { cursor = 0; return Component(props) }
  let tree = render()
  nodes(tree).find((node) => node.type === 'label' && node.props.children[0] === 'Source scope').props.children[1].props.onChange({ target: { value: 'vsys:b' } })
  tree = render()
  const rowSelectors = nodes(tree).filter((node) => node.type === 'input' && node.props['aria-label']?.startsWith('Select vsys:'))
  assert.deepEqual(rowSelectors.map((node) => node.props['aria-label']), ['Select vsys:b same-name'])
  assert.deepEqual(props.selected, ['vsys:a'])
})

test('shared offline export retains approved bytes, partial label and per-file download actions', () => {
  let slot = ''; const downloads = []
  const Component = load('OfflineMigrationExport', { useState: () => [slot, (value) => { slot = value }] })
  const files = [
    { key: 'requests', label: 'API requests', previewLabel: 'Reviewed requests', text: '{"request":"exact"}\n', sha256: 'request-hash', count: '2 API requests', downloadLabel: 'Download requests', downloadable: true },
    { key: 'manifest', label: 'Response bindings', previewLabel: 'Reviewed bindings', text: '{"bindings":[]}\n', sha256: 'binding-hash', count: '1 file', downloadLabel: 'Download bindings', downloadable: true },
  ]
  const props = { artifactId: 'approved-id', partial: true, noChanges: false, files, busy: false, verification: 'Offline only', onDownload: (key) => downloads.push(key), onBundle: () => downloads.push('bundle') }
  const nodes = (tree) => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []
  let tree = Component(props)
  assert.equal(nodes(tree).find((node) => node.type === 'textarea').props.value, files[0].text)
  nodes(tree).find((node) => node.props?.role === 'tab' && node.props.children === 'Response bindings').props.onClick()
  tree = Component(props)
  assert.equal(nodes(tree).find((node) => node.type === 'textarea').props.value, files[1].text)
  assert.ok(JSON.stringify(tree).includes('binding-hash'))
  assert.ok(JSON.stringify(tree).includes('Partial export'))
  nodes(tree).find((node) => node.type === 'button' && node.props.children === 'Download bindings').props.onClick()
  assert.deepEqual(downloads, ['manifest'])
})
