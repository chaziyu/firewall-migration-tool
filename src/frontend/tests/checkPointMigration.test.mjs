import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import { renderToStaticMarkup } from 'react-dom/server'

const buttonExports = {}
const buttonOutput = ts.transpileModule(readFileSync(new URL('../src/components/common/Button.tsx', import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
new Function('require', 'exports', buttonOutput)((name) => { assert.equal(name, 'react/jsx-runtime'); return jsxRuntime }, buttonExports)

const rows = [
  { key: 'object', family: 'address', source_name: 'clients', target_name: 'clients', settings: { management_operation: { path: '/web_api/add-network' } }, dependencies: [], blockers: [], render_disposition: 'CREATE' },
  { key: 'first', family: 'policy', source_name: 'deny', target_name: 'deny', settings: { position: { above: 'cleanup-uid' } }, dependencies: ['object'], blockers: [], render_disposition: 'CREATE' },
  { key: 'last', family: 'policy', source_name: 'allow', target_name: 'allow', settings: { uid: { $response_binding: 'first' } }, dependencies: ['first'], blockers: [], render_disposition: 'CREATE' },
]
const destination = { source: { vendor: 'checkpoint', source_text: '{}' }, version: '1.8.1', mode: 'management', complete_families: ['objects', 'policies'] }

function harness(overrides = {}, items = rows, fresh = false, findings = []) {
  const options = { source_vdom: 'root', management_target: 'server', management_domain: 'domain', policy_package: 'package', access_layer: 'layer', install_on: ['gateway'], insertion_relation: 'above', insertion_anchor: 'cleanup-uid' }
  const review = { draft: { digest: 'draft' }, requirements: [], report: { plan_status: 'READY_FOR_REVIEW', items, findings } }
  let saved = fresh ? undefined : { pairId: 'fortigate_to_checkpoint', sourceKey: 'source', options, destination, requirements: [], review, approval: null, artifact: null, preview: null }
  const slots = []; let cursor = 0; let dirty = false; let effects = []; let stage = fresh ? 'place' : 'review'
  const hooks = {
    useState(value) { const i = cursor++; if (!(i in slots)) slots[i] = typeof value === 'function' ? value() : value; return [slots[i], (next) => { slots[i] = typeof next === 'function' ? next(slots[i]) : next; dirty = true }] },
    useRef(value) { return slots[cursor++] ??= { current: value } },
    useMemo(fn) { cursor++; return fn() },
    useEffect(fn, deps) { const i = cursor++; if (!slots[i] || deps.some((d, j) => d !== slots[i][j])) { slots[i] = deps; effects.push(fn) } },
  }
  const modules = {
    react: hooks, 'react/jsx-runtime': jsxRuntime,
    '../../../components/common/Button': buttonExports,
    '../components/MigrationCoverage': { MigrationCoverage: () => null },
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
function elements(tree) { if (!tree || typeof tree !== 'object') return []; if (Array.isArray(tree)) return tree.flatMap(elements); if (typeof tree.type === 'function') return elements(tree.type(tree.props)); return [tree, ...elements(tree.props?.children)] }
function button(tree, label) { const node = elements(tree).find((n) => n.type === 'button' && n.props.children === label); assert.ok(node, label); return node }
function selectLast(tree) { const inputs = elements(tree).filter((n) => n.type === 'input' && n.props.type === 'checkbox'); inputs.at(-1).props.onChange() }

test('preview expands prior rules and UID dependencies; retry uses the same signed approval', async () => {
  let approvals = 0; let builds = 0
  const approval = { selected_items: ['first', 'last', 'object'], signature: 'signed' }
  const name = 'checkpoint_management_operations.json'
  const file = { content: 'bytes', sha256: 'hash', byte_count: 5 }
  const artifact = { files: { [name]: file }, file_sha256: { [name]: 'hash' }, expires_at: 2000000000 }
  const h = harness({
    approve: async (_s, _o, _d, selected, target) => { approvals++; assert.equal(target, destination); assert.deepEqual(selected, approval.selected_items); return { approval } },
    build: async (_s, _o, current, target) => { assert.equal(target, destination); assert.equal(current, approval); builds++; if (builds === 1) throw new Error('Build failed'); return { artifact } },
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

test('cancel and option edits invalidate preview without creating approval', async () => {
  let approvals = 0
  const h = harness({ approve: async () => { approvals++ } })
  let tree = await h.render(); selectLast(tree); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  button(tree, 'Cancel approval preview').props.onClick(); tree = await h.render()
  assert.ok(!elements(tree).some((n) => n.props?.['aria-label'] === 'Check Point approval preview'))
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  button(tree, 'Edit target setup').props.onClick(); tree = await h.render()
  elements(tree).find((n) => n.type === 'input' && n.props.value === 'server').props.onChange({ target: { value: 'changed' } })
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

test('destination edits clear the expanded approval preview', async () => {
  const h = harness()
  let tree = await h.render(); selectLast(tree); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  assert.ok(elements(tree).some((n) => n.props?.['aria-label'] === 'Check Point approval preview'))
  button(tree, 'Edit target setup').props.onClick(); tree = await h.render()
  elements(tree).find((n) => n.type === 'DestinationSnapshot').props.onChange(null)
  tree = await h.render()
  assert.equal(h.state().destination, null)
  assert.equal(h.state().review, null)
  assert.equal(h.state().approval, null)
  assert.equal(h.state().artifact, null)
  assert.ok(!elements(tree).some((n) => n.props?.['aria-label'] === 'Check Point approval preview'))
})

test('new target proposes source scope and package without a snapshot or existing-policy fields', async () => {
  let prepared = 0
  const proposed = { target_mode: 'new', source_vdom: 'root', policy_package: 'Migrated root',
    management_api_version: '1.8.1', management_target: '', management_domain: '', gaia_target: '',
    access_layer: '', install_on: [], insertion_anchor: '', insertion_relation: '', target_cleanup_action: '' }
  const h = harness({
    requirements: async () => ({ requirements: [], source_vdoms: ['root'], options: proposed }),
    prepare: async (_s, options, target) => {
      prepared++; assert.equal(options.policy_package, 'Migrated root'); assert.equal(target, undefined)
      return { options: proposed, draft: {}, requirements: [], report: { items: rows, findings: [], plan_status: 'READY_FOR_REVIEW' } }
    },
  }, rows, true)
  let tree = await h.render()
  assert.equal(h.state().options.source_vdom, 'root')
  assert.equal(h.state().options.target_mode, 'new')
  assert.equal(h.state().approval, null)
  assert.ok(!elements(tree).some((n) => n.type === 'DestinationSnapshot'))
  assert.ok(!JSON.stringify(tree).includes('Existing Drop cleanup rule name or UID'))
  const prepare = button(tree, 'Prepare review')
  assert.equal(prepare.props.disabled, false)
  prepare.props.onClick(); tree = await h.render()
  assert.equal(prepared, 1)
  assert.ok(!elements(tree).some((n) => n.props?.children === 'Prepare review'))
  button(tree, 'Select all supported operations').props.onClick(); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  assert.ok(JSON.stringify(tree).includes('Create package:'))
  assert.equal(h.state().approval, null)
})

test('large findings are grouped and every affected item remains reachable', async () => {
  const repeated = Array.from({ length: 61 }, (_, i) => ({ code: 'GROUP_EXPANDED', message: 'Groups are expanded into rule lists.', source_vdom: i % 2 ? 'branch' : 'root', source_kind: 'address_group', source_name: `group-${i}`, blocking: false }))
  const distinct = Array.from({ length: 25 }, (_, i) => ({ code: `OTHER_${i}`, message: `Other finding ${i}`, blocking: true }))
  const findings = [...repeated, { ...repeated[0], blocking: true }, ...distinct]
  const h = harness({}, rows, false, findings)
  let tree = await h.render()
  const section = (tree) => elements(tree).find((n) => n.props?.['aria-label'] === 'Check Point findings')
  const groups = (tree) => elements(section(tree)).filter((n) => n.type === 'details' && n.props.className === 'checkpoint-plan-item')
  assert.equal(groups(tree).length, 25)
  const members = new Set()
  for (let page = 0; page < 3; page++) {
    const group = groups(tree)[0]
    const evidence = elements(group).filter((n) => n.type === 'pre').map((n) => JSON.parse(n.props.children))
    assert.ok(evidence.length <= 25)
    evidence.forEach((finding) => members.add(`${finding.source_vdom}/${finding.source_name}`))
    if (page < 2) { button(group, 'Next affected items').props.onClick(); tree = await h.render() }
  }
  assert.equal(members.size, 61)
  assert.ok(groups(tree).every((group) => !group.props.open))
  button(section(tree), 'Next finding groups').props.onClick(); tree = await h.render()
  assert.equal(groups(tree).length, 2)
  assert.ok(JSON.stringify(section(tree)).includes('Other finding 24'))
  assert.equal(h.state().review.report.findings, findings)
})

test('approval pages preserve all dependencies and exact settings in the signed selection', async () => {
  const items = Array.from({ length: 61 }, (_, i) => ({ ...rows[0], key: `item-${String(i).padStart(2, '0')}`, source_vdom: 'root', source_name: `object-${i}`, target_name: `target-${i}`, settings: { name: `target-${i}`, binding: { $response_binding: `response-${i}` } }, dependencies: i ? [`item-${String(i - 1).padStart(2, '0')}`] : [] }))
  let approved
  const h = harness({ approve: async (_s, _o, _d, selection) => { approved = selection; return { approval: { selected_items: selection, signature: 'signed' } } }, build: async () => { throw new Error('Offline build unavailable') } }, items)
  let tree = await h.render()
  button(tree, 'Next').props.onClick(); tree = await h.render()
  button(tree, 'Next').props.onClick(); tree = await h.render()
  selectLast(tree); tree = await h.render()
  button(tree, 'Review selected operations').props.onClick(); tree = await h.render()
  const preview = (tree) => elements(tree).find((n) => n.props?.['aria-label'] === 'Check Point approval preview')
  const inspected = new Set()
  for (let page = 0; page < 3; page++) {
    const details = elements(preview(tree)).filter((n) => n.type === 'details' && n.props.className === 'checkpoint-plan-item')
    assert.equal(details.length, page < 2 ? 25 : 11)
    assert.ok(details.every((node) => !node.props.open))
    for (const node of details) {
      const raw = elements(node).find((n) => n.type === 'pre')
      assert.equal(raw.props.className, 'set-command-preview')
      const evidence = JSON.parse(raw.props.children)
      inspected.add(evidence.settings.name)
      assert.deepEqual(evidence, { settings: items[Number(evidence.settings.name.slice(7))].settings, dependencies: items[Number(evidence.settings.name.slice(7))].dependencies })
    }
    if (page < 2) { button(preview(tree), 'Next approval details').props.onClick(); tree = await h.render() }
  }
  assert.equal(inspected.size, 61)
  button(tree, 'Approve these operations and generate files').props.onClick(); await h.render()
  assert.deepEqual(approved, items.map((item) => item.key))
  assert.equal(h.state().approval.signature, 'signed')
})

test('plan controls use shared buttons and keep blocker codes inside collapsed details', async () => {
  const h = harness({}, [{ ...rows[0], source_vdom: 'root', blockers: ['ADDRESS_REPRESENTATION_NOT_EXPLICIT_OR_SUPPORTED'], render_disposition: 'BLOCK' }])
  const tree = await h.render()
  const html = renderToStaticMarkup(tree)
  assert.ok(html.includes('class="secondary-button"'))
  assert.ok(html.includes('class="primary-button"'))
  assert.ok(html.includes('address representation not explicit or supported'))
  assert.ok(html.includes('<details><summary>Technical blocker codes</summary><pre class="set-command-preview">ADDRESS_REPRESENTATION_NOT_EXPLICIT_OR_SUPPORTED</pre></details>'))
  assert.equal(elements(tree).find((n) => n.type === 'input' && n.props.type === 'checkbox').props.disabled, true)
  assert.equal(button(tree, 'Review selected operations').props.disabled, true)
})
