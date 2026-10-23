import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { approvalSelection } from '../src/features/migration/paloAltoToCiscoFtd/reviewSelection.ts'

const options = {
  source_scope: 'vsys:test',
  target_mode: 'new',
  manager_target: 'fmc.example.com',
  domain_id: 'e276abec-e0f2-11e3-8169-6d9ed49b625f',
  domain_name: 'Global',
  fmc_api_version: '7.7.0',
  policy_name: 'PAN_ACP_test',
  target_device_id: '',
  target_device_name: '',
}

const review = {
  options,
  draft: {},
  source_scopes: ['vsys:test'],
  requirements: [],
  report: { items: [], verification: 'Offline', findings: [] },
}

const tick = () => new Promise((resolve) => setImmediate(resolve))

function harness(overrides = {}, savedOptions = options, restoreWorkspace = true) {
  const slots = []
  let cursor = 0
  let effects = []
  const cleanups = new Map()
  const downloads = []

  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) {
        const slot = { value: typeof initial === 'function' ? initial() : initial }
        slot.set = (value) => {
          slot.value = typeof value === 'function' ? value(slot.value) : value
        }
        slots[index] = slot
      }
      return [slots[index].value, slots[index].set]
    },
    useRef(initial) {
      const index = cursor++
      return (slots[index] ??= { current: initial })
    },
    useEffect(fn, deps) {
      const index = cursor++
      if (!slots[index] || deps.some((value, i) => !Object.is(value, slots[index][i]))) {
        slots[index] = deps
        effects.push(() => {
          cleanups.get(index)?.()
          cleanups.set(index, fn())
        })
      }
    },
  }

  function load(path, modules) {
    const code = ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
    }).outputText
    const exports = {}
    new Function('require', 'exports', code)((name) => {
      if (name === 'react') return hooks
      if (name === 'react/jsx-runtime') return { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) }
      assert.ok(name in modules, name)
      return modules[name]
    }, exports)
    return exports
  }

  const activity = load('../src/features/migration/hooks/useMigrationReviewActivity.ts', {
    '../../../api/client': { RequestError: class extends Error {} },
  })
  const saved = {
    pairId: 'palo_alto_to_cisco_ftd',
    sourceKey: 'source',
    options: savedOptions,
    review,
    stage: 'export',
    approval: {},
    artifact: {
      artifact_id: 'id',
      files: {
        'cisco_fmc_operations.json': { content: 'exact\n', sha256: 'hash', byte_count: 6 },
        'cisco_fmc_curl.sh': { content: '#!/bin/bash\n', sha256: 'hash2', byte_count: 12 },
        'cisco_fmc_bindings.json': { content: '{}\n', sha256: 'hash3', byte_count: 3 },
        'ftd_application_instructions.txt': { content: 'Instructions\n', sha256: 'hash4', byte_count: 13 },
      },
      report: { items: [], verification: 'Offline', fmc_operation_count: 1 },
    },
  }

  const Component = load('../src/features/migration/paloAltoToCiscoFtd/MigrationWorkflow.tsx', {
    '../../../components/common/Button': { Button: 'Button' },
    '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../../storage/workspaceStore': { workspace: () => restoreWorkspace ? ({ panosMigration: saved }) : {}, saveWorkspace: async () => {} },
    '../components/OfflineMigrationReview': { OfflineMigrationReview: 'Review' },
    '../components/OfflineMigrationExport': { OfflineMigrationExport: 'Export' },
    '../components/DestinationSnapshot': { DestinationSnapshot: 'Snapshot' },
    '../hooks/useMigrationReviewActivity': activity,
    '../migrationApi': { downloadFile: (...args) => downloads.push(args) },
    './migrationApi': {
      prepare: async (_source, opt) => ({ ...review, options: opt }),
      download: async () => new Blob(['exact\n']),
      ...overrides,
    },
    './reviewSelection': { approvalSelection },
  }).PaloAltoToCiscoFtdWorkflow

  const props = { source: { vendor: 'palo_alto', source_text: '<config />' }, sourceKey: 'source', stage: 'export' }
  const nodes = (tree) =>
    Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []

  return {
    downloads,
    props,
    async render() {
      let tree
      for (let i = 0; i < 4; i++) {
        cursor = 0
        tree = Component(props)
        const pending = effects
        effects = []
        pending.forEach((fn) => fn())
        await tick()
      }
      return nodes(tree)
    },
    close() {
      for (const cleanup of cleanups.values()) cleanup?.()
    },
  }
}

test('PAN Cisco FTD export presents file list and downloads exact bytes', async () => {
  const h = harness()
  try {
    const nodes = await h.render()
    const exported = nodes.find((node) => node.type === 'Export')
    assert.ok(exported)
    exported.props.onDownload('fmc-operations')
    await tick()
    assert.equal(h.downloads[0][1], 'cisco_fmc_operations.json')
    assert.equal(await h.downloads[0][0].text(), 'exact\n')
  } finally {
    h.close()
  }
})

test('PAN Cisco FTD fresh setup requires explicit FMC identity', async () => {
  const h = harness({}, options, false)
  try {
    h.props.stage = 'place'
    const nodes = await h.render()
    const inputs = nodes.filter((node) => node.type === 'input')
    assert.deepEqual(inputs.map((node) => node.props.value), ['', '', '', '', '7.7.0'])
  } finally {
    h.close()
  }
})

test('PAN Cisco FTD target snapshot change clears reviewed draft', async () => {
  const h = harness({}, { ...options, target_mode: 'existing' })
  try {
    h.props.stage = 'place'
    let nodes = await h.render()
    const snapshot = nodes.find((node) => node.type === 'Snapshot')
    assert.ok(snapshot)
    snapshot.props.onChange({ source: {}, metadata: { complete_families: [] } })
    await tick()
    h.props.stage = 'export'
    nodes = await h.render()
    assert.equal(nodes.some((node) => node.type === 'Export'), false)
  } finally {
    h.close()
  }
})

test('PAN Cisco FTD approvalSelection computes dependency closure', () => {
  const rows = [
    { key: 'zone-1', family: 'zone', dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'net-1', family: 'address', dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'acp-1', family: 'acp', dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'rule-1', family: 'policy', dependencies: ['zone-1', 'net-1', 'acp-1'], blockers: [], render_disposition: 'CREATE' },
  ]
  const selected = approvalSelection(rows, ['rule-1'])
  assert.deepEqual(selected.sort(), ['acp-1', 'net-1', 'rule-1', 'zone-1'])
})
