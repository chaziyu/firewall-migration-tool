import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { approvalSelection } from '../src/features/migration/paloAltoToCiscoAsa/reviewSelection.ts'

const options = { source_scope: 'vsys:test', target_context: 'single', target_version: '9.20', target_mode: 'routed', interfaces: {}, new_target_confirmed: false, routing_complete: false, permit_inter_interface: false, permit_intra_interface: false, ace_limit: 256 }
const review = { draft: {}, report: { items: [], verification: 'Offline', findings: [] }, requirements: { source_scopes: ['vsys:test'], decisions: [] } }
const tick = () => new Promise((resolve) => setImmediate(resolve))
function harness(overrides = {}) {
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
  const saved = { pairId: 'palo_alto_to_cisco_asa', sourceKey: 'source', options, review, stage: 'export', approval: {}, artifact: { artifact_id: 'id', command_count: 1, command_text: 'exact\n', command_sha256: 'hash', report: { verification: 'Offline' } } }
  const Component = load('../src/features/migration/paloAltoToCiscoAsa/MigrationWorkflow.tsx', {
    '../../../components/common/Button': { Button: 'Button' }, '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../../storage/workspaceStore': { workspace: () => ({ panosMigration: saved }), saveWorkspace: async () => {} },
    '../components/OfflineMigrationReview': { OfflineMigrationReview: 'Review' }, '../components/OfflineMigrationExport': { OfflineMigrationExport: 'Export' },
    '../components/DestinationSnapshot': { DestinationSnapshot: 'Snapshot' }, '../hooks/useMigrationReviewActivity': activity,
    '../migrationApi': { downloadFile: (...args) => downloads.push(args) }, './migrationApi': { prepare: async () => review, download: async () => new Blob(['exact\n']), ...overrides },
    './reviewSelection': { approvalSelection },
  }).PaloAltoToCiscoAsaWorkflow
  const props = { source: { vendor: 'palo_alto', source_text: '<config />' }, sourceKey: 'source', stage: 'export' }
  const nodes = (tree) => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []
  return { downloads, props, async render() {
    let tree
    for (let i = 0; i < 4; i++) { cursor = 0; tree = Component(props); const pending = effects; effects = []; pending.forEach((fn) => fn()); await tick() }
    return nodes(tree)
  }, close() { for (const cleanup of cleanups.values()) cleanup?.() } }
}

test('ASA current downloads reach the shared file saver with exact API bytes', async () => {
  const h = harness()
  try {
    const nodes = await h.render()
    nodes.find((node) => node.type === 'Export').props.onDownload('cli')
    await tick()
    assert.equal(h.downloads.length, 1)
    assert.equal(h.downloads[0][1], 'asa_config.cfg')
    assert.equal(await h.downloads[0][0].text(), 'exact\n')
  } finally { h.close() }
})

test('ASA target edits revoke artifacts and suppress a late download', async () => {
  let resolve
  const h = harness({ download: () => new Promise((done) => { resolve = done }) })
  try {
    let nodes = await h.render()
    nodes.find((node) => node.type === 'Export').props.onDownload('cli')
    h.props.stage = 'place'; nodes = await h.render()
    nodes.find((node) => node.type === 'Snapshot').props.onChange({ source: { source_text: 'hostname target' }, metadata: {} })
    resolve(new Blob(['stale']))
    await tick()
    assert.equal(h.downloads.length, 0)
    h.props.stage = 'export'; nodes = await h.render()
    assert.equal(nodes.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('ASA source stage keeps target controls in the target setup stage', async () => {
  const h = harness()
  try {
    h.props.stage = 'load'
    let nodes = await h.render()
    assert.equal(nodes.some((node) => node.type === 'Snapshot'), false)
    assert.equal(nodes.some((node) => node.type === 'fieldset'), false)
    assert.ok(nodes.some((node) => node.type === 'Button' && node.props.children === 'Continue to target setup'))
    h.props.stage = 'place'
    nodes = await h.render()
    assert.ok(nodes.some((node) => node.type === 'Snapshot'))
  } finally { h.close() }
})

test('ASA pair or source unmount suppresses an in-flight download', async () => {
  let resolve
  const h = harness({ download: () => new Promise((done) => { resolve = done }) })
  const nodes = await h.render()
  nodes.find((node) => node.type === 'Export').props.onBundle()
  h.close()
  resolve(new Blob(['old pair artifact']))
  await tick()
  assert.equal(h.downloads.length, 0)
})
