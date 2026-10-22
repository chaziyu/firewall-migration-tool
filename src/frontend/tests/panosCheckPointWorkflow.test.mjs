import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { approvalSelection } from '../src/features/migration/paloAltoToCheckPoint/reviewSelection.ts'

const options = { source_scope: 'vsys:test', target_mode: 'new', management_target: '', management_domain: '',
  management_api_version: '1.8.1', policy_package: 'pan_test', gaia_target: '', access_layer: '', install_on: [], insertion_anchor: '', insertion_relation: '', target_cleanup_action: '' }
const review = { options, draft: {}, source_scopes: ['vsys:test'], requirements: [], report: { items: [], verification: 'Offline', findings: [] } }
const tick = () => new Promise((resolve) => setImmediate(resolve))
function harness(overrides = {}, savedOptions = options) {
  const slots = []; let cursor = 0; let effects = []; const cleanups = new Map(); const downloads = []
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) {
        const slot = { value: typeof initial === 'function' ? initial() : initial }
        slot.set = (value) => { slot.value = typeof value === 'function' ? value(slot.value) : value }
        slots[index] = slot
      }
      return [slots[index].value, slots[index].set]
    },
    useRef(initial) { const index = cursor++; return slots[index] ??= { current: initial } },
    useEffect(fn, deps) {
      const index = cursor++
      if (!slots[index] || deps.some((value, i) => !Object.is(value, slots[index][i]))) {
        slots[index] = deps; effects.push(() => { cleanups.get(index)?.(); cleanups.set(index, fn()) })
      }
    },
  }
  function load(path, modules) {
    const code = ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
    const exports = {}
    new Function('require', 'exports', code)((name) => {
      if (name === 'react') return hooks
      if (name === 'react/jsx-runtime') return { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) }
      assert.ok(name in modules, name); return modules[name]
    }, exports)
    return exports
  }
  const activity = load('../src/features/migration/hooks/useMigrationReviewActivity.ts', { '../../../api/client': { RequestError: class extends Error {} } })
  const saved = { pairId: 'palo_alto_to_checkpoint', sourceKey: 'source', options: savedOptions, review, stage: 'export', approval: {},
    artifact: { artifact_id: 'id', files: { 'checkpoint_management_operations.json': { content: 'exact\n', sha256: 'hash', byte_count: 6 } }, report: { items: [], verification: 'Offline', management_operation_count: 1 } } }
  const Component = load('../src/features/migration/paloAltoToCheckPoint/MigrationWorkflow.tsx', {
    '../../../components/common/Button': { Button: 'Button' }, '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../../storage/workspaceStore': { workspace: () => ({ panosMigration: saved }), saveWorkspace: async () => {} },
    '../components/OfflineMigrationReview': { OfflineMigrationReview: 'Review' }, '../components/OfflineMigrationExport': { OfflineMigrationExport: 'Export' },
    '../components/DestinationSnapshot': { DestinationSnapshot: 'Snapshot' }, '../hooks/useMigrationReviewActivity': activity,
    '../migrationApi': { downloadFile: (...args) => downloads.push(args) }, './migrationApi': { prepare: async (_source, options) => ({ ...review, options }), download: async () => new Blob(['exact\n']), ...overrides },
    './reviewSelection': { approvalSelection },
  }).PaloAltoToCheckPointWorkflow
  const props = { source: { vendor: 'palo_alto', source_text: '<config />' }, sourceKey: 'source', stage: 'export' }
  const nodes = (tree) => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []
  return { downloads, props, async render() {
    let tree
    for (let i = 0; i < 4; i++) { cursor = 0; tree = Component(props); const pending = effects; effects = []; pending.forEach((fn) => fn()); await tick() }
    return nodes(tree)
  }, close() { for (const cleanup of cleanups.values()) cleanup?.() } }
}

test('PAN Check Point shared export presents each exact file and saves the current API bytes', async () => {
  const h = harness()
  try {
    const nodes = await h.render()
    const exported = nodes.find((node) => node.type === 'Export')
    assert.equal(exported.props.files[0].text, 'exact\n')
    exported.props.onDownload('management-operations')
    await tick()
    assert.equal(h.downloads[0][1], 'checkpoint_management_operations.json')
    assert.equal(await h.downloads[0][0].text(), 'exact\n')
  } finally { h.close() }
})

test('PAN Check Point snapshot metadata edits revoke artifacts and suppress a late download', async () => {
  let resolve
  const h = harness({ download: () => new Promise((done) => { resolve = done }) }, { ...options, target_mode: 'existing' })
  try {
    let nodes = await h.render()
    nodes.find((node) => node.type === 'Export').props.onBundle()
    h.props.stage = 'place'; nodes = await h.render()
    nodes.find((node) => node.type === 'Snapshot').props.onChange({ source: {}, metadata: { complete_families: [] } })
    resolve(new Blob(['old']))
    await tick()
    assert.equal(h.downloads.length, 0)
    h.props.stage = 'export'; nodes = await h.render()
    assert.equal(nodes.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('PAN Check Point source stage and comma-separated target edits preserve guided control behavior', async () => {
  const h = harness()
  try {
    h.props.stage = 'load'
    let nodes = await h.render()
    assert.equal(nodes.some((node) => node.type === 'select'), false)
    assert.ok(nodes.some((node) => node.type === 'Button' && node.props.children === 'Continue to target setup'))
    h.props.stage = 'place'; nodes = await h.render()
    const label = nodes.find((node) => node.type === 'label' && node.props.children?.[0] === 'Install-on gateways or clusters (comma separated)')
    label.props.children[1].props.onChange({ target: { value: 'gateway-one, ' } })
    nodes = await h.render()
    assert.ok(nodes.some((node) => node.type === 'input' && node.props.value === 'gateway-one, '))
    h.props.stage = 'export'; nodes = await h.render()
    assert.equal(nodes.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('PAN Check Point source/pair unmount suppresses a late bundle', async () => {
  let resolve
  const h = harness({ download: () => new Promise((done) => { resolve = done }) })
  const nodes = await h.render()
  nodes.find((node) => node.type === 'Export').props.onBundle()
  h.close(); resolve(new Blob(['old pair']))
  await tick()
  assert.equal(h.downloads.length, 0)
})

test('PAN Check Point approval expands the complete predecessor/UID chain and rejects blocked work', () => {
  const rows = Array.from({ length: 10000 }, (_, index) => ({ key: String(index), dependencies: index ? [String(index - 1)] : [], blockers: [], render_disposition: 'CREATE' }))
  assert.equal(approvalSelection(rows, ['9999']).length, 10000)
  rows[1].render_disposition = 'BLOCK'
  assert.throws(() => approvalSelection(rows, ['9999']), /blocked/)
})
