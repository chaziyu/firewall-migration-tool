import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'

const rows = [
  { key: 'object', family: 'address', source_name: 'clients', target_name: 'clients', settings: { management_operation: { path: '/web_api/add-network' } }, dependencies: [], blockers: [], render_disposition: 'CREATE' },
  { key: 'first', family: 'policy', source_name: 'deny', target_name: 'deny', settings: { position: { above: 'cleanup-uid' } }, dependencies: ['object'], blockers: [], render_disposition: 'CREATE' },
  { key: 'last', family: 'policy', source_name: 'allow', target_name: 'allow', settings: { uid: { $response_binding: 'first' } }, dependencies: ['first'], blockers: [], render_disposition: 'CREATE' },
]

function harness(overrides = {}, items = rows) {
  const options = { source_vdom: 'root', management_target: 'server', management_domain: 'domain', policy_package: 'package', access_layer: 'layer', install_on: ['gateway'], insertion_relation: 'above', insertion_anchor: 'cleanup-uid' }
  const review = { draft: { digest: 'draft' }, requirements: [], report: { plan_status: 'READY_FOR_REVIEW', items, findings: [] } }
  let saved = { pairId: 'fortigate_to_checkpoint', sourceKey: 'source', options, review, approval: null, artifact: null, preview: null }
  const slots = []; let cursor = 0; let dirty = false; let effects = []; let stage = 'review'
  const hooks = {
    useState(value) { const i = cursor++; if (!(i in slots)) slots[i] = typeof value === 'function' ? value() : value; return [slots[i], (next) => { slots[i] = typeof next === 'function' ? next(slots[i]) : next; dirty = true }] },
    useRef(value) { return slots[cursor++] ??= { current: value } },
    useMemo(fn) { cursor++; return fn() },
    useEffect(fn, deps) { const i = cursor++; if (!slots[i] || deps.some((d, j) => d !== slots[i][j])) { slots[i] = deps; effects.push(fn) } },
  }
  const modules = {
    react: hooks, 'react/jsx-runtime': jsxRuntime,
    '../components/MigrationCoverage': { MigrationCoverage: 'MigrationCoverage' },
    '../components/DestinationSnapshot': { DestinationSnapshot: 'DestinationSnapshot' },
    '../../../storage/workspaceStore': { workspace: () => ({ newPairMigration: saved }), saveWorkspace: async (value) => { saved = value.newPairMigration } },
    './migrationApi': { requirements: async () => ({ requirements: [] }), prepare: async () => review, ...overrides },
  }
  const output = ts.transpileModule(readFileSync(new URL('../src/features/migration/fortigateToCheckPoint/MigrationWorkflow.tsx', import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText
  const exports = {}
  new Function('require', 'exports', output)((name) => { assert.ok(name in modules, name); return modules[name] }, exports)
  const props = { source: { vendor: 'fortigate' }, sourceKey: 'source', onStageChange: (next) => { stage = next } }
  return {
    state: () => saved,
    async render() { let tree; for (let i = 0; i < 20; i++) { cursor = 0; dirty = false; tree = exports.CheckPointMigrationWorkflow({ ...props, stage }); const callbacks = effects; effects = []; callbacks.forEach((fn) => fn()); await new Promise((resolve) => setImmediate(resolve)); if (!dirty) return tree } throw new Error('Did not settle') },
  }
}
function elements(tree) { if (!tree || typeof tree !== 'object') return []; if (Array.isArray(tree)) return tree.flatMap(elements); return [tree, ...elements(tree.props?.children)] }
function button(tree, label) { const node = elements(tree).find((n) => n.type === 'button' && n.props.children === label); assert.ok(node, label); return node }
function selectLast(tree) { const inputs = elements(tree).filter((n) => n.type === 'input' && n.props.type === 'checkbox'); inputs.at(-1).props.onChange() }

test('preview expands prior rules and UID dependencies; retry uses the same signed approval', async () => {
  let approvals = 0; let builds = 0
  const approval = { selected_items: ['first', 'last', 'object'], signature: 'signed' }
  const name = 'checkpoint_management_operations.json'
  const file = { content: 'bytes', sha256: 'hash', byte_count: 5 }
  const artifact = { files: { [name]: file }, file_sha256: { [name]: 'hash' }, expires_at: 2000000000 }
  const h = harness({
    approve: async (_s, _o, _d, selected) => { approvals++; assert.deepEqual(selected, approval.selected_items); return { approval } },
    build: async (_s, _o, current) => { assert.equal(current, approval); builds++; if (builds === 1) throw new Error('Build failed'); return { artifact } },
    preview: async () => ({ files: { [name]: { text: 'bytes', sha256: 'hash', byte_count: 5 } } }),
  })
  let tree = await h.render()
  selectLast(tree); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  assert.equal(approvals, 0)
  const preview = elements(tree).find((n) => n.props?.['aria-label'] === 'Check Point approval preview')
  assert.ok(preview)
  const text = JSON.stringify(preview)
  for (const value of ['Required dependency', '/web_api/add-network', 'cleanup-uid', '$response_binding']) assert.ok(text.includes(value), value)
  button(tree, 'Approve these operations and generate files').props.onClick(); tree = await h.render()
  assert.equal(h.state().approval, approval)
  assert.equal(h.state().artifact, null)
  button(tree, 'Retry with current approval').props.onClick(); await h.render()
  assert.equal(builds, 2)
  assert.equal(approvals, 1)
  assert.equal(h.state().artifact, artifact)
  assert.equal(h.state().preview[name].text, file.content)
})

test('cancel and destination edits invalidate preview without creating approval', async () => {
  let approvals = 0
  const h = harness({ approve: async () => { approvals++ } })
  let tree = await h.render(); selectLast(tree); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  button(tree, 'Cancel approval preview').props.onClick(); tree = await h.render()
  assert.ok(!elements(tree).some((n) => n.props?.['aria-label'] === 'Check Point approval preview'))
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  elements(tree).find((n) => n.type === 'DestinationSnapshot').props.onChange({ source_text: 'changed' })
  tree = await h.render()
  assert.equal(h.state().review, null)
  assert.equal(h.state().approval, null)
  assert.equal(approvals, 0)
})

test('blocked dependencies prevent confirmation', async () => {
  const h = harness({}, rows.map((row) => row.key === 'object' ? { ...row, render_disposition: 'BLOCK' } : row))
  let tree = await h.render(); selectLast(tree); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  assert.ok(elements(tree).some((n) => n.props?.role === 'alert' && /blocked dependency/.test(n.props.children)))
  assert.ok(!elements(tree).some((n) => n.props?.children === 'Approve these operations and generate files'))
})
