import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/migration/paloAltoToFortigate/reviewPresentation.ts'

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
const review = { draft: { digest: 'draft', signature: 'signed', context: {}, configuration: rows, findings: [] }, requirements: { source_scopes: ['vsys:one'], decisions: [{ key: 'vdom', label: 'Target VDOM' }], findings: [] }, issues: [], resolved_options: options, proposals: [], effective_values: [] }

function harness(saved, overrides = {}, callbacks = {}) {
  let state = saved
  let slots = []; let cursor = 0; let dirty = false; let effects = []
  const instances = new Map()
  const hooks = {
    useState(value) { const container = slots; const index = cursor++; if (!(index in container)) container[index] = typeof value === 'function' ? value() : value; return [container[index], (next) => { container[index] = typeof next === 'function' ? next(container[index]) : next; dirty = true }] },
    useRef(value) { const index = cursor++; return slots[index] ??= { current: value } },
    useEffect(fn, deps) { const index = cursor++; if (!slots[index] || deps.some((d, i) => d !== slots[index][i])) { slots[index] = deps; effects.push(fn) } },
    useCallback(fn) { return slots[cursor++] ??= fn },
  }
  const sharedModules = { react: hooks, '../../../components/common/Button': { Button: 'Button' }, '../../../components/common/tabKeyboard': { tabKeyboard() {} } }
  const offlineReview = load('../src/features/migration/components/OfflineMigrationReview.tsx', sharedModules)
  const offlineExport = load('../src/features/migration/components/OfflineMigrationExport.tsx', sharedModules)
  const Component = load('../src/features/migration/paloAltoToFortigate/MigrationWorkflow.tsx', {
    react: hooks, '../../../components/common/Button': { Button: 'Button' }, '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../../components/common/tabKeyboard': { tabKeyboard() {} }, './reviewPresentation': presentation,
    '../components/OfflineMigrationReview': offlineReview, '../components/OfflineMigrationExport': offlineExport,
    '../../source/FileUpload': { FileUpload: 'FileUpload' }, '../../source/sourceApi': {},
    '../../../storage/workspaceStore': { workspace: () => ({ panosMigration: state }), saveWorkspace: async (value) => { state = value.panosMigration } },
    '../migrationApi': { downloadFile() {} }, './migrationApi': { ...api, prepare: async () => review, ...overrides },
  }).FortiGateMigrationWorkflow
  const props = { source: { vendor: 'palo_alto', source_text: '<config />' }, sourceKey: 'source', ...callbacks }
  function expand(tree) {
    if (Array.isArray(tree)) return tree.map(expand)
    if (!tree || typeof tree !== 'object') return tree
    if (typeof tree.type === 'function') {
      const parentSlots = slots; const parentCursor = cursor
      if (!instances.has(tree.type)) instances.set(tree.type, [])
      slots = instances.get(tree.type); cursor = 0
      const rendered = expand(tree.type(tree.props))
      slots = parentSlots; cursor = parentCursor
      return rendered
    }
    return { ...tree, props: { ...tree.props, children: expand(tree.props?.children) } }
  }
  return {
    state: () => state,
    async render() { let tree; for (let i = 0; i < 15; i++) { cursor = 0; dirty = false; tree = expand(Component(props)); const callbacks = effects; effects = []; callbacks.forEach((fn) => fn()); await Promise.resolve(); await Promise.resolve(); if (!dirty) return tree } throw new Error('Did not settle') },
  }
}
function elements(tree) { if (!tree || typeof tree !== 'object') return []; if (Array.isArray(tree)) return tree.flatMap(elements); return [tree, ...elements(tree.props?.children)] }
function button(tree, label) { const node = elements(tree).find((n) => n.type === 'Button' && n.props.children === label); assert.ok(node, label); return node }
function initial(stage) { return { pairId: 'palo_alto_to_fortigate', sourceKey: 'source', options: structuredClone(options), targetSource: null, review, approval: null, artifact: null, stage } }
function text(tree) { if (Array.isArray(tree)) return tree.map(text).join(''); return tree && typeof tree === 'object' ? text(tree.props?.children) : tree == null || typeof tree === 'boolean' ? '' : String(tree) }
function tab(tree, id) { return elements(tree).find((n) => n.props?.id === `fortigate-tab-${id}`) }

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
  await button(tree, 'Review migration').props.onClick()
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
  elements(tree).find((n) => n.props?.['aria-label'] === 'Select all ready changes').props.onChange({ target: { checked: true } })
  tree = await h.render()
  button(tree, 'Review selected changes').props.onClick()
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

test('a standalone source opens target setup before review without approving', async () => {
  let prepares = 0; let approvals = 0
  const saved = { ...initial('load'), review: null, options: { ...structuredClone(options), source_scope: '', vdom: '' } }
  const h = harness(saved, {
    prepare: async (_source, requested) => { prepares++; assert.equal(requested.vdom, ''); return review },
    approve: async () => { approvals++; throw new Error('Unexpected approval') },
  })
  const tree = await h.render()
  assert.equal(prepares, 1)
  assert.equal(h.state().stage, 'place')
  assert.equal(h.state().options.vdom, '')
  assert.ok(button(tree, 'Review migration'))
  const nav = elements(tree).find((n) => n.type === 'nav')
  assert.deepEqual(elements(nav).filter((n) => n.type === 'button').map((n) => n.props.children.at(-1)), ['Source', 'Target setup', 'Review migration', 'Download'])
  assert.equal(approvals, 0)
  assert.equal(h.state().artifact, null)
})

test('ambiguous source scopes stay on source selection', async () => {
  const result = { ...review, resolved_options: { ...options, source_scope: '' }, requirements: { ...review.requirements, source_scopes: ['vsys:one', 'vsys:two'] } }
  const h = harness({ ...initial('load'), review: null }, { prepare: async () => result })
  await h.render()
  assert.equal(h.state().stage, 'load')
  assert.equal(h.state().approval, null)
})

test('port inventory input retains a trailing comma while preparing allocations', async () => {
  const h = harness(initial('place'))
  let tree = await h.render()
  let input = elements(tree).find((n) => n.type === 'input' && n.props.placeholder === 'port1, port2')
  input.props.onChange({ target: { value: 'port1, ' } })
  tree = await h.render()
  input = elements(tree).find((n) => n.type === 'input' && n.props.placeholder === 'port1, port2')
  assert.equal(input.props.value, 'port1, ')
  assert.deepEqual(h.state().options.profile.ports, ['port1'])
  input.props.onChange({ target: { value: 'port1, port2' } })
  await h.render()
  assert.deepEqual(h.state().options.profile.ports, ['port1', 'port2'])
})

test('bulk choices require a preview and preserve individual exceptions', async () => {
  const decisions = [
    { key: 'policy:first:disabled', policy_key: 'first', field: 'disabled', label: 'First omitted disabled', choices: ['yes', 'no'] },
    { key: 'policy:second:disabled', policy_key: 'second', field: 'disabled', label: 'Second omitted disabled', choices: ['yes', 'no'] },
    { key: 'policy:exception:disabled', policy_key: 'exception', field: 'disabled', label: 'Existing exception', choices: ['yes', 'no'], value: 'yes' },
  ]
  const result = { ...review, requirements: { ...review.requirements, decisions } }
  const saved = initial('place')
  saved.options.policy_settings = { exception: { disabled: 'yes' } }
  const h = harness(saved, { prepare: async () => result })
  let tree = await h.render()
  const label = elements(tree).find((n) => n.type === 'label' && n.props.children?.[0] === 'Choose ')
  const select = elements(label).find((n) => n.type === 'select')
  assert.ok(select)
  select.props.onChange({ target: { value: 'no' } })
  tree = await h.render()
  assert.deepEqual(h.state().options.policy_settings, { exception: { disabled: 'yes' } })
  button(tree, 'Apply reviewed policy choice').props.onClick()
  await h.render()
  assert.deepEqual(h.state().options.policy_settings, { first: { disabled: 'no' }, second: { disabled: 'no' }, exception: { disabled: 'yes' } })
  assert.equal(h.state().approval, null)
})

test('out of order proposal responses cannot replace current edits', async () => {
  const pending = []
  const h = harness(initial('place'), { prepare: async (_source, requested) => {
    if (requested.vdom === 'root') return review
    return new Promise((resolve) => pending.push({ vdom: requested.vdom, resolve }))
  } })
  let tree = await h.render()
  const edit = (tree, value) => {
    const label = elements(tree).find((n) => n.type === 'label' && n.props.children?.[0] === 'Target VDOM')
    elements(label).find((n) => n.type === 'input').props.onChange({ target: { value } })
  }
  edit(tree, 'first')
  tree = await h.render()
  edit(tree, 'second')
  await h.render()
  assert.equal(pending.length, 2)
  pending[1].resolve({ ...review, resolved_options: { ...options, vdom: 'second' } })
  await h.render()
  pending[0].resolve({ ...review, resolved_options: { ...options, vdom: 'first' } })
  await h.render()
  assert.equal(h.state().options.vdom, 'second')
  assert.equal(h.state().review.resolved_options.vdom, 'second')
  assert.equal(h.state().approval, null)
})

test('zero-ready drafts show global blockers and input groups instead of an empty ready table', async () => {
  const finding = 'Source extraction or topology is incomplete'
  const result = { ...review, draft: { ...review.draft, findings: [finding], configuration: rows.map((row) => ({ ...row, render_disposition: 'BLOCK', blocking_reasons: [finding, 'Choose a target zone.'] })) },
    issues: rows.map((row) => ({ id: row.key, item_key: row.key, source_scope: row.source_scope, source_name: row.source_name, category: 'CHOICE', explanation: 'Choose a target zone.' })) }
  let sourceVisits = 0
  const h = harness(initial('review'), { prepare: async () => result }, { onReviewSource() { sourceVisits++ } })
  let tree = await h.render()
  assert.equal(tab(tree, 'decisions').props['aria-selected'], true)
  assert.match(text(tree), /No changes are ready to approve/)
  const shared = elements(tree).find((n) => n.props?.['aria-label'] === 'Shared migration blockers')
  assert.equal(text(shared).split(finding).length - 1, 1)
  elements(shared).find((n) => n.props?.children === 'Review source report').props.onClick()
  assert.equal(sourceVisits, 1)
  tab(tree, 'changes').props.onClick()
  tree = await h.render()
  assert.equal(elements(tree).find((n) => n.type === 'select' && n.props.value === 'all')?.props.value, 'all')
  assert.equal(elements(tree).filter((n) => n.type === 'tr').length, rows.length + 1)
  assert.equal(button(tree, 'Review selected changes').props.disabled, true)
  assert.ok(elements(tree).filter((n) => n.type === 'input' && n.props.type === 'checkbox').every((n) => n.props.disabled))
})

test('manual-only drafts and unfamiliar categories remain visible and searchable', async () => {
  const result = { ...review, draft: { ...review.draft, configuration: [rows[2]] }, issues: [{ id: 'future', item_key: 'manual', category: 'FUTURE_CATEGORY', source_scope: 'vsys:one', source_name: 'App-ID', explanation: 'Manual implementation' }] }
  const h = harness(initial('review'), { prepare: async () => result })
  let tree = await h.render()
  assert.equal(tab(tree, 'manual').props['aria-selected'], true)
  assert.match(text(tree), /Manual implementation/)
  const search = elements(tree).find((n) => n.type === 'label' && n.props.children?.[0] === 'Search issue groups')
  elements(search).find((n) => n.type === 'input').props.onChange({ target: { value: 'no-match' } })
  tree = await h.render()
  assert.match(text(tree), /No issue groups match this search/)
  assert.equal(h.state().approval, null)
})

test('technical evidence is collapsed and all 139 source values can be inspected', async () => {
  const effective_values = Array.from({ length: 139 }, (_, i) => ({ identity: ['vsys:one', 'policy', `policy-${i}`], field: 'log_end', value: 'yes', version: '11.0', reference: 'https://example.test/reference', origin: 'DOCUMENTED' }))
  const h = harness(initial('review'), { prepare: async () => ({ ...review, effective_values }) })
  let tree = await h.render()
  const evidence = elements(tree).find((n) => n.type === 'details' && elements(n).some((child) => child.type === 'summary' && child.props.children === 'Technical evidence'))
  assert.equal(evidence.props.open, undefined)
  for (let i = 0; i < 5; i++) { button(tree, 'Next source values').props.onClick(); tree = await h.render() }
  assert.match(text(tree), /policy-138/)
  assert.equal(button(tree, 'Next source values').props.disabled, true)
  const search = elements(tree).find((n) => n.type === 'label' && n.props.children?.[0] === 'Search effective source values')
  elements(search).find((n) => n.type === 'input').props.onChange({ target: { value: 'policy-138' } })
  tree = await h.render()
  assert.match(text(tree), /policy-138/)
  assert.doesNotMatch(text(tree), /policy-137/)
  assert.equal(h.state().approval, null)
})

test('selecting a policy previews added prerequisites without approving before confirmation', async () => {
  let approvals = 0
  const h = harness(initial('review'), { approve: async () => { approvals++; return {} } })
  let tree = await h.render()
  elements(tree).find((n) => n.props?.['aria-label'] === 'Select vsys:one allow').props.onChange({ target: { checked: true } })
  tree = await h.render()
  button(tree, 'Review selected changes').props.onClick()
  tree = await h.render()
  assert.match(text(tree), /1 prerequisites added to your selection/)
  assert.match(text(tree), /Added prerequisite.*net/)
  assert.match(text(tree), /10.0.0.0/)
  assert.equal(approvals, 0)
  assert.equal(h.state().approval, null)
  elements(tree).find((n) => n.props?.['aria-label'] === 'Select vsys:one allow').props.onChange({ target: { checked: false } })
  tree = await h.render()
  assert.ok(!elements(tree).some((n) => n.props?.['aria-label'] === 'FortiGate approval preview'))
  assert.equal(approvals, 0)
})

test('restored options survive step navigation and placement keeps parent interfaces first', async () => {
  const configuration = [
    { ...rows[0], key: 'parent', family: 'interface', source_name: 'ethernet1/1' },
    { ...rows[0], key: 'child', family: 'interface', source_name: 'ethernet1/1.201', dependencies: ['parent'] },
  ]
  const result = { ...review, draft: { ...review.draft, configuration }, requirements: { ...review.requirements, decisions: [
    { key: 'interfaces:ethernet1/1.201', label: 'VLAN child' }, { key: 'interfaces:ethernet1/1', label: 'Physical parent' },
  ] } }
  const saved = initial('place')
  saved.options.interfaces = { 'ethernet1/1': 'port5' }
  const h = harness(saved, { prepare: async () => result })
  let tree = await h.render()
  const fields = elements(tree).filter((n) => n.type === 'label' && ['VLAN child', 'Physical parent'].includes(n.props.children?.[0]))
  assert.deepEqual(fields.map((n) => n.props.children[0]), ['Physical parent', 'VLAN child'])
  const nav = elements(tree).find((n) => n.type === 'nav')
  elements(nav).find((n) => n.type === 'button' && n.props.children.at(-1) === 'Source').props.onClick()
  tree = await h.render()
  button(tree, 'Continue to target setup').props.onClick()
  await h.render()
  assert.equal(h.state().options.interfaces['ethernet1/1'], 'port5')
  assert.equal(h.state().stage, 'place')
})

test('assumed same-layout proposals prefill interface fields and remain editable without approval', async () => {
  const resolved = { ...options, interfaces: { 'ethernet1/1': 'port1', 'ethernet1/1.201': 'port1.201' }, profile: { ports: ['port1'] } }
  const result = { ...review, resolved_options: resolved, proposals: [
    { key: 'profile:ports', value: ['port1'], evidence_source: 'ASSUMED_LAYOUT', mode: 'SUGGESTED', review_state: 'PENDING', reason: 'Assumed layout' },
  ], requirements: { ...review.requirements, decisions: [
    { key: 'interfaces:ethernet1/1', label: 'Physical parent', value: 'port1', mode: 'SUGGESTED', evidence_source: 'ASSUMED_LAYOUT' },
    { key: 'interfaces:ethernet1/1.201', label: 'VLAN child', value: 'port1.201', mode: 'SUGGESTED', evidence_source: 'DERIVED' },
  ] } }
  const h = harness(initial('place'), { prepare: async () => result })
  let tree = await h.render()
  assert.match(text(tree), /Assumed same layout/)
  const fields = elements(tree).filter((n) => n.type === 'label' && ['Physical parent', 'VLAN child'].includes(n.props.children?.[0]))
  assert.deepEqual(fields.map((n) => elements(n).find((child) => child.type === 'input').props.value), ['port1', 'port1.201'])
  elements(fields[0]).find((n) => n.type === 'input').props.onChange({ target: { value: 'port5' } })
  tree = await h.render()
  assert.equal(h.state().options.interfaces['ethernet1/1'], 'port5')
  assert.equal(h.state().approval, null)
  assert.equal(h.state().artifact, null)
})

test('source topology corrections route to the source report without offering an ineffective target edit', async () => {
  const explanation = 'Source topology: virtual-router member is not imported into this VSYS'
  const result = { ...review, draft: { ...review.draft, configuration: [{ ...rows[0], render_disposition: 'BLOCK', blocking_reasons: [explanation] }] },
    issues: [{ id: 'source', item_key: 'object', category: 'SOURCE', source_scope: 'vsys:one', source_name: 'net', explanation }] }
  let visits = 0
  const h = harness(initial('review'), { prepare: async () => result }, { onReviewSource() { visits++ } })
  const tree = await h.render()
  assert.equal(tab(tree, 'decisions').props['aria-selected'], true)
  assert.match(text(tree), /Source correction required/)
  assert.ok(!elements(tree).some((n) => n.type === 'Button' && n.props.children === 'Resolve in target setup'))
  button(tree, 'Review source report').props.onClick()
  assert.equal(visits, 1)
  assert.equal(h.state().approval, null)
})
