import test from 'node:test'
import assert from 'node:assert/strict'
import * as jsxRuntime from 'react/jsx-runtime'
import { approvalSelection as asaApprovalSelection } from '../src/features/migration/paloAltoToCiscoAsa/reviewSelection.ts'
import { approvalSelection as cpApprovalSelection } from '../src/features/migration/paloAltoToCheckPoint/reviewSelection.ts'
import { approvalSelection as ftdApprovalSelection } from '../src/features/migration/paloAltoToCiscoFtd/reviewSelection.ts'
import { loadCjs, nodes } from './testHelpers.mjs'

const tick = () => new Promise((resolve) => setImmediate(resolve))

const PAIR_CONFIG = {
  asa: {
    folder: 'paloAltoToCiscoAsa',
    pairId: 'palo_alto_to_cisco_asa',
    exportName: 'PaloAltoToCiscoAsaWorkflow',
    approvalSelection: asaApprovalSelection,
    options: {
      source_scope: 'vsys:test', target_context: 'single', target_version: '9.20', target_mode: 'routed',
      interfaces: {}, new_target_confirmed: false, routing_complete: false, permit_inter_interface: false,
      permit_intra_interface: false, ace_limit: 256,
    },
    artifact: {
      artifact_id: 'id', command_count: 1, command_text: 'exact\n', command_sha256: 'hash',
      report: { items: [], verification: 'Offline' },
    },
    prepareReturnsOptions: false,
  },
  checkpoint: {
    folder: 'paloAltoToCheckPoint',
    pairId: 'palo_alto_to_checkpoint',
    exportName: 'PaloAltoToCheckPointWorkflow',
    approvalSelection: cpApprovalSelection,
    options: {
      source_scope: 'vsys:test', target_mode: 'new', management_target: '', management_domain: '',
      management_api_version: '1.8.1', policy_package: 'pan_test', gaia_target: '', access_layer: '',
      install_on: [], insertion_anchor: '', insertion_relation: '', target_cleanup_action: '',
    },
    artifact: {
      artifact_id: 'id',
      files: { 'checkpoint_management_operations.json': { content: 'exact\n', sha256: 'hash', byte_count: 6 } },
      report: { items: [], verification: 'Offline', management_operation_count: 1 },
    },
    prepareReturnsOptions: true,
  },
  ftd: {
    folder: 'paloAltoToCiscoFtd',
    pairId: 'palo_alto_to_cisco_ftd',
    exportName: 'PaloAltoToCiscoFtdWorkflow',
    approvalSelection: ftdApprovalSelection,
    options: {
      source_scope: 'vsys:test', target_mode: 'new', manager_target: 'fmc.example.com',
      domain_id: 'e276abec-e0f2-11e3-8169-6d9ed49b625f', domain_name: 'Global',
      fmc_api_version: '7.7.0', policy_name: 'PAN_ACP_test', target_device_id: '', target_device_name: '',
    },
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
    prepareReturnsOptions: true,
  },
}

function createHarness(pairKey, overrides = {}, savedOptions, restoreWorkspace = true) {
  const cfg = PAIR_CONFIG[pairKey]
  const effectiveOptions = savedOptions ?? cfg.options
  const review = {
    options: cfg.options,
    draft: {},
    source_scopes: ['vsys:test'],
    requirements: pairKey === 'asa' ? { source_scopes: ['vsys:test'], decisions: [] } : [],
    report: { items: [], verification: 'Offline', findings: [] },
  }

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
        slot.set = (value) => { slot.value = typeof value === 'function' ? value(slot.value) : value }
        slots[index] = slot
      }
      return [slots[index].value, slots[index].set]
    },
    useRef(initial) { const index = cursor++; return (slots[index] ??= { current: initial }) },
    useEffect(fn, deps) {
      const index = cursor++
      if (!slots[index] || deps.some((value, i) => !Object.is(value, slots[index][i]))) {
        slots[index] = deps
        effects.push(() => { cleanups.get(index)?.(); cleanups.set(index, fn()) })
      }
    },
  }

  const activity = loadCjs('../src/features/migration/hooks/useMigrationReviewActivity.ts', {
    react: hooks,
    '../../../api/client': { RequestError: class extends Error {} },
  })
  const saved = {
    pairId: cfg.pairId,
    sourceKey: 'source',
    options: effectiveOptions,
    review,
    stage: 'export',
    approval: {},
    artifact: cfg.artifact,
  }
  const Component = loadCjs(`../src/features/migration/${cfg.folder}/MigrationWorkflow.tsx`, {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    '../../../components/common/Button': { Button: 'Button' },
    '../../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../../storage/workspaceStore': {
      workspace: () => (restoreWorkspace ? { panosMigration: saved } : {}),
      saveWorkspace: async () => {},
    },
    '../components/OfflineMigrationReview': { OfflineMigrationReview: 'Review' },
    '../components/OfflineMigrationExport': { OfflineMigrationExport: 'Export' },
    '../components/DestinationSnapshot': { DestinationSnapshot: 'Snapshot' },
    '../hooks/useMigrationReviewActivity': activity,
    '../migrationApi': { downloadFile: (...args) => downloads.push(args) },
    './migrationApi': {
      prepare: async (_source, opt) => (cfg.prepareReturnsOptions ? { ...review, options: opt } : review),
      download: async () => new Blob(['exact\n']),
      ...overrides,
    },
    './reviewSelection': { approvalSelection: cfg.approvalSelection },
  })[cfg.exportName]

  const props = { source: { vendor: 'palo_alto', source_text: '<config />' }, sourceKey: 'source', stage: 'export' }
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

// --- PAN-OS -> Cisco ASA ---
test('ASA preview expands the complete traffic unit and dependencies in plan order', () => {
  const rows = [
    { key: 'object', dependencies: [], blockers: [] },
    { key: 'interface', approval_group: 'traffic', dependencies: [], blockers: [] },
    { key: 'policy', approval_group: 'traffic', dependencies: ['object', 'interface'], blockers: [] },
    { key: 'default', approval_group: 'traffic', dependencies: ['policy'], blockers: [] },
    { key: 'binding', approval_group: 'traffic', dependencies: ['default'], blockers: [] },
  ]
  assert.deepEqual(asaApprovalSelection(rows, ['policy']), rows.map((row) => row.key))
  assert.deepEqual(asaApprovalSelection(rows, ['object']), ['object'])
  assert.throws(() => asaApprovalSelection(rows.map((row) => (row.key === 'binding' ? { ...row, blockers: ['conflict'] } : row)), ['policy']))
  assert.throws(() => asaApprovalSelection(rows, ['missing']))
})

test('ASA current downloads reach the shared file saver with exact API bytes', async () => {
  const h = createHarness('asa')
  try {
    const rendered = await h.render()
    rendered.find((node) => node.type === 'Export').props.onDownload('cli')
    await tick()
    assert.equal(h.downloads.length, 1)
    assert.equal(h.downloads[0][1], 'asa_config.cfg')
    assert.equal(await h.downloads[0][0].text(), 'exact\n')
  } finally { h.close() }
})

test('ASA target edits revoke artifacts and suppress a late download', async () => {
  let resolve
  const h = createHarness('asa', { download: () => new Promise((done) => { resolve = done }) })
  try {
    let rendered = await h.render()
    rendered.find((node) => node.type === 'Export').props.onDownload('cli')
    h.props.stage = 'place'; rendered = await h.render()
    rendered.find((node) => node.type === 'Snapshot').props.onChange({ source: { source_text: 'hostname target' }, metadata: {} })
    resolve(new Blob(['stale']))
    await tick()
    assert.equal(h.downloads.length, 0)
    h.props.stage = 'export'; rendered = await h.render()
    assert.equal(rendered.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('ASA source stage keeps target controls in the target setup stage', async () => {
  const h = createHarness('asa')
  try {
    h.props.stage = 'load'
    let rendered = await h.render()
    assert.equal(rendered.some((node) => node.type === 'Snapshot'), false)
    assert.equal(rendered.some((node) => node.type === 'fieldset'), false)
    assert.ok(rendered.some((node) => node.type === 'Button' && node.props.children === 'Continue to target setup'))
    h.props.stage = 'place'
    rendered = await h.render()
    assert.ok(rendered.some((node) => node.type === 'Snapshot'))
  } finally { h.close() }
})

test('ASA pair or source unmount suppresses an in-flight download', async () => {
  let resolve
  const h = createHarness('asa', { download: () => new Promise((done) => { resolve = done }) })
  const rendered = await h.render()
  rendered.find((node) => node.type === 'Export').props.onBundle()
  h.close()
  resolve(new Blob(['old pair artifact']))
  await tick()
  assert.equal(h.downloads.length, 0)
})

// --- PAN-OS -> Check Point ---
test('PAN Check Point shared export presents each exact file and saves the current API bytes', async () => {
  const h = createHarness('checkpoint')
  try {
    const rendered = await h.render()
    const exported = rendered.find((node) => node.type === 'Export')
    assert.equal(exported.props.files[0].text, 'exact\n')
    exported.props.onDownload('management-operations')
    await tick()
    assert.equal(h.downloads[0][1], 'checkpoint_management_operations.json')
    assert.equal(await h.downloads[0][0].text(), 'exact\n')
  } finally { h.close() }
})

test('PAN Check Point snapshot metadata edits revoke artifacts and suppress a late download', async () => {
  let resolve
  const h = createHarness('checkpoint', { download: () => new Promise((done) => { resolve = done }) }, { ...PAIR_CONFIG.checkpoint.options, target_mode: 'existing' })
  try {
    let rendered = await h.render()
    rendered.find((node) => node.type === 'Export').props.onBundle()
    h.props.stage = 'place'; rendered = await h.render()
    rendered.find((node) => node.type === 'Snapshot').props.onChange({ source: {}, metadata: { complete_families: [] } })
    resolve(new Blob(['old']))
    await tick()
    assert.equal(h.downloads.length, 0)
    h.props.stage = 'export'; rendered = await h.render()
    assert.equal(rendered.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('PAN Check Point source stage and comma-separated target edits preserve guided control behavior', async () => {
  const h = createHarness('checkpoint')
  try {
    h.props.stage = 'load'
    let rendered = await h.render()
    assert.equal(rendered.some((node) => node.type === 'select'), false)
    assert.ok(rendered.some((node) => node.type === 'Button' && node.props.children === 'Continue to target setup'))
    h.props.stage = 'place'; rendered = await h.render()
    const label = rendered.find((node) => node.type === 'label' && node.props.children?.[0] === 'Install-on gateways or clusters (comma separated)')
    label.props.children[1].props.onChange({ target: { value: 'gateway-one, ' } })
    rendered = await h.render()
    assert.ok(rendered.some((node) => node.type === 'input' && node.props.value === 'gateway-one, '))
    h.props.stage = 'export'; rendered = await h.render()
    assert.equal(rendered.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('PAN Check Point source/pair unmount suppresses a late bundle', async () => {
  let resolve
  const h = createHarness('checkpoint', { download: () => new Promise((done) => { resolve = done }) })
  const rendered = await h.render()
  rendered.find((node) => node.type === 'Export').props.onBundle()
  h.close(); resolve(new Blob(['old pair']))
  await tick()
  assert.equal(h.downloads.length, 0)
})

test('PAN Check Point approval expands the complete predecessor/UID chain and rejects blocked work', () => {
  const rows = Array.from({ length: 10000 }, (_, index) => ({ key: String(index), dependencies: index ? [String(index - 1)] : [], blockers: [], render_disposition: 'CREATE' }))
  assert.equal(cpApprovalSelection(rows, ['9999']).length, 10000)
  rows[1].render_disposition = 'BLOCK'
  assert.throws(() => cpApprovalSelection(rows, ['9999']), /blocked/)
})

// --- PAN-OS -> Cisco FTD ---
test('PAN Cisco FTD export presents file list and downloads exact bytes', async () => {
  const h = createHarness('ftd')
  try {
    const rendered = await h.render()
    const exported = rendered.find((node) => node.type === 'Export')
    assert.ok(exported)
    exported.props.onDownload('fmc-operations')
    await tick()
    assert.equal(h.downloads[0][1], 'cisco_fmc_operations.json')
    assert.equal(await h.downloads[0][0].text(), 'exact\n')
  } finally { h.close() }
})

test('PAN Cisco FTD fresh setup requires explicit FMC identity', async () => {
  const h = createHarness('ftd', {}, PAIR_CONFIG.ftd.options, false)
  try {
    h.props.stage = 'place'
    const rendered = await h.render()
    const inputs = rendered.filter((node) => node.type === 'input')
    assert.deepEqual(inputs.map((node) => node.props.value), ['', '', '', '', '7.7.0'])
  } finally { h.close() }
})

test('PAN Cisco FTD target snapshot change clears reviewed draft', async () => {
  const h = createHarness('ftd', {}, { ...PAIR_CONFIG.ftd.options, target_mode: 'existing' })
  try {
    h.props.stage = 'place'
    let rendered = await h.render()
    const snapshot = rendered.find((node) => node.type === 'Snapshot')
    assert.ok(snapshot)
    snapshot.props.onChange({ source: {}, metadata: { complete_families: [] } })
    await tick()
    h.props.stage = 'export'
    rendered = await h.render()
    assert.equal(rendered.some((node) => node.type === 'Export'), false)
  } finally { h.close() }
})

test('PAN Cisco FTD approvalSelection computes dependency closure', () => {
  const rows = [
    { key: 'zone-1', family: 'zone', dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'net-1', family: 'address', dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'acp-1', family: 'acp', dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'rule-1', family: 'policy', dependencies: ['zone-1', 'net-1', 'acp-1'], blockers: [], render_disposition: 'CREATE' },
  ]
  const selected = ftdApprovalSelection(rows, ['rule-1'])
  assert.deepEqual(selected.sort(), ['acp-1', 'net-1', 'rule-1', 'zone-1'])
})
