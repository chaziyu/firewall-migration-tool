import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'

function load(file, modules) {
  const exports = {}
  const js = ts.transpileModule(readFileSync(new URL(file, import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText
  new Function('require', 'exports', js)((name) => {
    if (name === 'react/jsx-runtime') return jsxRuntime
    assert.ok(name in modules, `Unexpected import ${name}`)
    return modules[name]
  }, exports)
  return exports
}
const api = load('../src/features/migration/paloAltoToFortigate/migrationApi.ts', { '../../../api/client': {} })
const rows = [
  { key: 'object', family: 'address', source_scope: 'vsys:one', source_name: 'net', target_name: 'net', target_vdom: 'root', settings: [['subnet', ['10.0.0.0', '255.255.255.0']]], dependencies: [], render_disposition: 'CREATE', blocking_reasons: [] },
  { key: 'policy', family: 'policy', source_scope: 'vsys:one', source_name: 'allow', target_name: '1', target_vdom: 'root', settings: [['action', ['accept']]], dependencies: ['object'], render_disposition: 'CREATE', blocking_reasons: [] },
  { key: 'manual', family: 'manual', source_scope: 'vsys:one', source_name: 'App-ID', target_name: '', target_vdom: 'root', settings: [], dependencies: [], render_disposition: 'BLOCK', blocking_reasons: ['Manual implementation'] },
]
const options = { source_scope: 'vsys:one', vdom: 'root', interfaces: {}, zones: {}, routers: {}, profile: {}, timezone: '', policy_settings: {} }
const review = { draft: { digest: 'draft', signature: 'signed', context: {}, configuration: rows, findings: [] }, requirements: { source_scopes: ['vsys:one'], decisions: [{ key: 'vdom', label: 'Target VDOM' }], findings: [] }, issues: [] }

function harness(saved, overrides = {}) {
  let state = saved
  const slots = []; let cursor = 0; let dirty = false; let effects = []
  const hooks = {
    useState(value) { const index = cursor++; if (!(index in slots)) slots[index] = typeof value === 'function' ? value() : value; return [slots[index], (next) => { slots[index] = typeof next === 'function' ? next(slots[index]) : next; dirty = true }] },
    useRef(value) { const index = cursor++; return slots[index] ??= { current: value } },
    useEffect(fn, deps) { const index = cursor++; if (!slots[index] || deps.some((d, i) => d !== slots[index][i])) { slots[index] = deps; effects.push(fn) } },
  }
  const Component = load('../src/features/migration/paloAltoToFortigate/MigrationWorkflow.tsx', {
    react: hooks, '../../../components/common/Button': { Button: 'Button' }, '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../source/FileUpload': { FileUpload: 'FileUpload' }, '../../source/sourceApi': {},
    '../../../storage/workspaceStore': { workspace: () => ({ fortigateMigration: state }), saveWorkspace: async (value) => { state = value.fortigateMigration } },
    '../migrationApi': { downloadFile() {} }, './migrationApi': { ...api, prepare: async () => review, ...overrides },
  }).FortiGateMigrationWorkflow
  const props = { source: { vendor: 'palo_alto', source_text: '<config />' }, sourceKey: 'source' }
  return {
    state: () => state,
    async render() { let tree; for (let i = 0; i < 15; i++) { cursor = 0; dirty = false; tree = Component(props); const callbacks = effects; effects = []; callbacks.forEach((fn) => fn()); await Promise.resolve(); await Promise.resolve(); if (!dirty) return tree } throw new Error('Did not settle') },
  }
}
function elements(tree) { if (!tree || typeof tree !== 'object') return []; if (Array.isArray(tree)) return tree.flatMap(elements); return [tree, ...elements(tree.props?.children)] }
function button(tree, label) { const node = elements(tree).find((n) => n.type === 'Button' && n.props.children === label); assert.ok(node, label); return node }
function initial(stage) { return { sourceKey: 'source', options: structuredClone(options), targetSource: null, review, approval: null, artifact: null, stage } }

test('reverse approval expands dependencies and refuses blocked or cyclic selections', () => {
  assert.deepEqual(api.approvalSelection(rows, ['policy']), ['object', 'policy'])
  assert.throws(() => api.approvalSelection(rows, ['manual']), /blocked/)
  assert.throws(() => api.approvalSelection([{ ...rows[0], dependencies: ['object'] }], ['object']), /cycle/)
})

test('failed review preserves target edits while revoking approval and artifact', async () => {
  const saved = { ...initial('place'), approval: { signature: 'old' }, artifact: { artifact_id: 'old' } }
  const h = harness(saved, { prepare: async (_source, opts) => { if (opts.vdom) throw new Error('Invalid target'); return review } })
  let tree = await h.render()
  const vdom = elements(tree).find((n) => n.type === 'label' && n.props.children?.[0] === 'Target VDOM')
  const input = elements(vdom).find((n) => n.type === 'input')
  input.props.onChange({ target: { value: 'edited' } })
  tree = await h.render()
  await button(tree, 'Prepare migration review').props.onClick()
  tree = await h.render()
  assert.equal(h.state().options.vdom, 'edited')
  assert.equal(h.state().approval, null)
  assert.equal(h.state().artifact, null)
  assert.ok(elements(tree).some((n) => n.type === 'ErrorBanner'))
})

test('approval stays explicit and failed generation can retry the same approval', async () => {
  let approvals = 0; let builds = 0
  const h = harness(initial('review'), {
    approve: async (_source, _opts, _target, _draft, selected) => { approvals++; assert.deepEqual(selected, ['object', 'policy']); return { approval: { signature: 'current' } } },
    build: async () => { builds++; if (builds === 1) throw new Error('Build failed'); return { artifact: { commands: ['config firewall address', 'end'], command_count: 2, report: { plan_status: 'PARTIAL', items: rows, deployment_eligibility: { eligible: false, reason: 'Export only' } } } } },
  })
  let tree = await h.render()
  button(tree, 'Review all ready changes').props.onClick()
  tree = await h.render()
  assert.equal(approvals, 0)
  assert.ok(elements(tree).some((n) => n.props?.['aria-label'] === 'FortiGate approval preview'))
  await button(tree, 'Approve these changes and generate commands').props.onClick()
  tree = await h.render()
  assert.equal(approvals, 1)
  assert.equal(h.state().approval.signature, 'current')
  assert.equal(h.state().artifact, null)
  await button(tree, 'Retry generation with current approval').props.onClick()
  tree = await h.render()
  assert.equal(builds, 2)
  assert.equal(approvals, 1)
  assert.ok(elements(tree).some((n) => n.props?.['aria-label'] === 'FortiGate command preview'))
})
