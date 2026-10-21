import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'

function load(name, modules = {}) {
  const output = ts.transpileModule(readFileSync(new URL(`../src/${name}`, import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 },
  }).outputText
  const exports = {}
  new Function('require', 'exports', output)((name) => {
    if (name === 'react/jsx-runtime') return jsxRuntime
    assert.ok(name in modules, name)
    return modules[name]
  }, exports)
  return exports
}
const path = 'features/migration/fortigateToJuniperSrx/'
const selection = load(`${path}reviewSelection.ts`)
const buttons = load('components/common/Button.tsx')
const item = (key, overrides = {}) => ({ key, source_vdom: 'root', source_name: key, target_name: `target-${key}`, family: 'service', settings: { protocol: 'tcp', destination_port: '443' }, blockers: [], dependencies: [], guidance: [], render_disposition: 'CREATE', ...overrides })

function hooks() {
  const slots = []; let cursor = 0; let dirty = false; let effects = []
  return {
    api: {
      useState(value) { const i = cursor++; if (!(i in slots)) slots[i] = typeof value === 'function' ? value() : value; return [slots[i], (next) => { slots[i] = typeof next === 'function' ? next(slots[i]) : next; dirty = true }] },
      useRef(value) { return slots[cursor++] ??= { current: value } },
      useMemo(fn) { cursor++; return fn() },
      useCallback(fn) { cursor++; return fn },
      useEffect(fn, deps) { const i = cursor++; if (!slots[i] || deps.some((d, j) => d !== slots[i][j])) { slots[i] = deps; effects.push(fn) } },
    },
    async render(component, props) {
      for (let attempt = 0; attempt < 20; attempt++) {
        cursor = 0; dirty = false
        const tree = component(props)
        const callbacks = effects; effects = []; callbacks.forEach((fn) => fn())
        await new Promise((resolve) => setImmediate(resolve))
        if (!dirty) return tree
      }
      throw new Error('Did not settle')
    },
  }
}
function elements(tree) {
  if (!tree || typeof tree !== 'object') return []
  if (Array.isArray(tree)) return tree.flatMap(elements)
  if (typeof tree.type === 'function') return elements(tree.type(tree.props))
  return [tree, ...elements(tree.props?.children)]
}
function button(tree, text) {
  const found = elements(tree).find((node) => node.type === 'button' && JSON.stringify(node.props.children).includes(text))
  assert.ok(found, text)
  return found
}
function field(tree, label, type = 'input') {
  const parent = elements(tree).find((node) => node.type === 'label' && (node.props.children?.[0] === label || node.props.children === label))
  const result = elements(parent).find((node) => node.type === type)
  assert.ok(result, label)
  return result
}

test('SRX approval includes prerequisites, reused objects and transitive atomic groups in plan order', () => {
  const rows = [item('object', { render_disposition: 'REUSE' }), item('policy', { dependencies: ['object'], approval_group: 'nat' }), item('nat', { approval_group: 'nat', dependencies: ['pool'] }), item('pool', { approval_group: 'pool-group' }), item('routing', { approval_group: 'pool-group' })]
  assert.deepEqual(selection.expandSelection(rows, ['policy']), rows.map((row) => row.key))
  for (const changed of [
    rows.filter((row) => row.key !== 'object'),
    rows.map((row) => row.key === 'routing' ? { ...row, blockers: ['blocked'] } : row),
    rows.map((row) => row.key === 'object' ? { ...row, dependencies: ['policy'] } : row),
  ]) assert.throws(() => selection.expandSelection(changed, ['policy']), /blocked|cycle/)
})

test('SRX approval expands long dependency chains without overflowing the browser stack', () => {
  const rows = Array.from({ length: 12000 }, (_, i) => item(String(i), { dependencies: i ? [String(i - 1)] : [] }))
  assert.deepEqual(selection.expandSelection(rows, ['11999']), rows.map((row) => row.key))
})

test('SRX changes use bounded pages and preserve selections across search and status filters', async () => {
  const h = hooks()
  const { SrxDesignReview } = load(`${path}DesignReview.tsx`, { react: h.api, '../../../components/common/Button': buttons, './reviewSelection': selection })
  const rows = Array.from({ length: 61 }, (_, i) => item(`service-${i}`))
  rows.push(item('blocked', { family: 'policy', render_disposition: 'BLOCK', blockers: ['POLICY_NAT_UNSUPPORTED'] }))
  let preview
  const props = { items: rows, busy: false, selected: [], onSelect: (keys) => { props.selected = keys }, approvalKeys: null, onPreview: (keys) => { preview = keys }, onApprove() {}, onCancel() {}, onSetup() {} }
  let tree = await h.render(SrxDesignReview, props)
  const checkboxes = (tree) => elements(tree).filter((node) => node.type === 'input' && node.props.type === 'checkbox')
  assert.equal(checkboxes(tree).length, 25)
  checkboxes(tree)[0].props.onChange({ target: { checked: true } })
  button(tree, 'Next').props.onClick(); tree = await h.render(SrxDesignReview, props)
  assert.equal(checkboxes(tree).length, 25)
  assert.equal(props.selected.length, 1)
  assert.match(JSON.stringify(tree), /selected across all pages/)
  field(tree, 'Search').props.onChange({ target: { value: 'service-60' } }); tree = await h.render(SrxDesignReview, props)
  assert.equal(checkboxes(tree).length, 1)
  button(tree, 'Review matching changes').props.onClick()
  assert.deepEqual(preview, ['service-60'])
  assert.deepEqual(props.selected, ['service-0'])
  field(tree, 'Search').props.onChange({ target: { value: '' } })
  field(tree, 'Status', 'select').props.onChange({ target: { value: 'blocked' } }); tree = await h.render(SrxDesignReview, props)
  assert.equal(checkboxes(tree).length, 1)
  assert.equal(checkboxes(tree)[0].props.disabled, true)
})

test('SRX approval preview pages all exact settings before explicit confirmation', async () => {
  const h = hooks()
  const { SrxDesignReview } = load(`${path}DesignReview.tsx`, { react: h.api, '../../../components/common/Button': buttons, './reviewSelection': selection })
  const rows = Array.from({ length: 61 }, (_, i) => item(`service-${i}`, { settings: { protocol: 'udp', destination_port: String(i + 1) } }))
  let approved = 0
  const props = { items: rows, busy: false, selected: ['service-60'], onSelect() {}, approvalKeys: rows.map((row) => row.key), onPreview() {}, onApprove: () => approved++, onCancel() {}, onSetup() {} }
  let tree = await h.render(SrxDesignReview, props)
  const seen = []
  for (let page = 0; page < 3; page++) {
    const articles = elements(tree).filter((node) => node.type === 'article')
    assert.ok(articles.length <= 25)
    seen.push(...articles.map((node) => JSON.stringify(node)))
    if (page < 2) { button(tree, 'Next approval page').props.onClick(); tree = await h.render(SrxDesignReview, props) }
  }
  assert.equal(seen.length, 61)
  for (let i = 0; i < rows.length; i++) assert.ok(seen[i].includes(`target-service-${i}`))
  assert.equal(approved, 0)
  assert.equal(button(tree, 'Approve selection').props.disabled, false)
  button(tree, 'Approve selection').props.onClick()
  assert.equal(approved, 1)
  props.approvalKeys = ['missing']; tree = await h.render(SrxDesignReview, props)
  assert.equal(button(tree, 'Approve selection').props.disabled, true)
})

function workflowHarness(api = {}, stage = 'review', interfaceCount = 0) {
  const h = hooks()
  const options = { source_vdom: 'root', target_context: 'root', target_version: '25.2R1', target_mode: 'standalone', routing_table: 'inet.0', timezone: '', interfaces: {}, zones: {} }
  const requirements = Array.from({ length: interfaceCount }, (_, i) => ({ key: `interface-${i}`, source_vdom: 'root', source_kind: 'interface', source_name: `port${i}`, target_field: 'target_interface', choices: [] }))
  const review = { draft: { digest: 'draft' }, requirements, report: { items: [item('object')], findings: [], plan_status: 'READY_FOR_REVIEW' } }
  let saved = { pairId: 'fortigate_to_juniper_srx', sourceKey: 'source', options, requirements, review, approval: null, artifact: null, previewText: null }
  const modules = {
    react: h.api, '../../../components/common/Button': buttons,
    '../components/MigrationCoverage': { MigrationCoverage: 'Coverage' },
    '../components/DestinationSnapshot': { DestinationSnapshot: 'DestinationSnapshot' },
    '../../../components/common/LoadingState': { LoadingState: 'LoadingState' },
    '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../../storage/workspaceStore': { workspace: () => ({ panosMigration: saved }), saveWorkspace: async (value) => { saved = value.panosMigration } },
    '../migrationApi': { downloadFile() {} }, './migrationApi': { requirements: async () => ({ requirements }), prepare: async () => review, ...api },
    './reviewSelection': selection, './DesignReview': { SrxDesignReview: 'DesignReview' },
  }
  const { JuniperSRXMigrationWorkflow } = load(`${path}MigrationWorkflow.tsx`, modules)
  const props = { source: { vendor: 'fortigate', source_text: 'synthetic' }, sourceKey: 'source', stage, onStageChange: (stage) => { props.stage = stage } }
  return { state: () => saved, props, render: () => h.render(JuniperSRXMigrationWorkflow, props) }
}
const design = (tree) => elements(tree).find((node) => node.type === 'DesignReview')

test('SRX mapping editor paginates 83 interfaces and edits clear previous review and approval', async () => {
  const h = workflowHarness({}, 'place', 83)
  let tree = await h.render()
  const mappings = (tree) => elements(tree).filter((node) => node.type === 'input' && node.props['aria-label']?.startsWith('Target interface for'))
  assert.equal(mappings(tree).length, 10)
  button(tree, 'Next interfaces').props.onClick(); tree = await h.render()
  assert.equal(mappings(tree)[0].props['aria-label'], 'Target interface for root / port10')
  field(tree, 'Search interfaces').props.onChange({ target: { value: 'port82' } }); tree = await h.render()
  assert.equal(mappings(tree).length, 1)
  mappings(tree)[0].props.onChange({ target: { value: 'ge-0/0/0' } }); tree = await h.render()
  assert.equal(h.state().review, null)
  assert.equal(h.state().approval, null)
  assert.equal(h.state().options.interfaces.root.port82.target_interface, 'ge-0/0/0')
})

test('SRX signed approval survives build failure and retry does not approve again', async () => {
  let approvals = 0; let builds = 0
  const approval = { signature: 'signed', selected_items: ['object'] }
  const artifact = { command_sha256: 'hash', command_count: 1, report: { plan_status: 'READY_FOR_REVIEW' } }
  const h = workflowHarness({
    approve: async (_s, _o, _d, keys) => { approvals++; assert.deepEqual(keys, ['object']); return { approval } },
    build: async (_s, _o, signed) => { assert.equal(signed, approval); if (++builds === 1) throw new Error('Build failed'); return { artifact } },
    commandPreview: async () => ({ text: 'set synthetic\n', command_sha256: 'hash' }),
  })
  let tree = await h.render()
  design(tree).props.onPreview(['object']); tree = await h.render()
  assert.equal(approvals, 0)
  design(tree).props.onApprove(); tree = await h.render()
  assert.equal(h.state().approval, approval)
  button(tree, 'Retry with current approval').props.onClick(); await h.render()
  assert.equal(approvals, 1)
  assert.equal(builds, 2)
  assert.equal(h.state().previewText, 'set synthetic\n')
})

test('SRX failed validation clears the old review and mismatched previews surface an error', async () => {
  const h = workflowHarness({ prepare: async () => { throw new Error('Validation failed') } }, 'place')
  let tree = await h.render()
  button(tree, 'Validate changes').props.onClick(); tree = await h.render()
  assert.equal(h.state().review, null)
  assert.ok(elements(tree).some((node) => node.type === 'ErrorBanner' && node.props.message === 'Validation failed'))
  const mismatch = workflowHarness({
    approve: async () => ({ approval: { signature: 'signed' } }),
    build: async () => ({ artifact: { command_sha256: 'expected', command_count: 1, report: {} } }),
    commandPreview: async () => ({ text: 'wrong', command_sha256: 'wrong' }),
  })
  tree = await mismatch.render(); design(tree).props.onPreview(['object']); tree = await mismatch.render()
  design(tree).props.onApprove(); tree = await mismatch.render()
  assert.equal(mismatch.state().previewText, null)
  assert.ok(elements(tree).some((node) => node.type === 'ErrorBanner' && /integrity/.test(node.props.message)))
})

test('new-device proposals remain editable and revoke the old review without approval', async () => {
  const proposed = { source_vdom: 'root', target_context: 'root', target_version: '25.2R1', target_mode: 'standalone', routing_table: 'inet.0', timezone: '', interfaces: { root: { port0: { target_interface: 'ge-0/0/0', unit: 0 } } }, zones: {}, interface_zones: { root: { port0: 'lan-zone' } } }
  let approvals = 0
  const h = workflowHarness({ proposeNewTarget: async () => ({ options: proposed, approval_required: true, hardware_verified: false }), approve: async () => approvals++ }, 'place', 1)
  let tree = await h.render()
  button(tree, 'Propose new-device mappings').props.onClick(); tree = await h.render()
  assert.equal(h.state().options.interface_zones.root.port0, 'lan-zone')
  assert.equal(h.state().review, null)
  assert.equal(h.state().approval, null)
  assert.equal(approvals, 0)
  const port = elements(tree).find((node) => node.props?.['aria-label'] === 'Target interface for root / port0')
  assert.equal(port.props.value, 'ge-0/0/0')
  assert.equal(port.props.disabled, false)
  elements(tree).find((node) => node.type === 'DestinationSnapshot').props.onChange({ source: { vendor: 'juniper_srx' } })
  tree = await h.render()
  assert.equal(button(tree, 'Propose new-device mappings').props.disabled, true)
})
