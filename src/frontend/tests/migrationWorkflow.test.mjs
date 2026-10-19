import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as drafts from '../src/features/migration/reviewDrafts.ts'
import * as presentation from '../src/features/migration/reviewPresentation.ts'
import { tabKeyboard } from '../src/components/common/tabKeyboard.ts'

globalThis.requestAnimationFrame ??= () => 0

test('VIP destination-zone choices retain scoped values and remain editable after rebuilding', async () => {
  const harness = component('../src/features/migration/components/MigrationConversionSettings.tsx', 'MigrationConversionSettings', {})
  let settings = { vip_external_zones: { blue: { web: 'blue-outside' } } }
  const props = { draft: { context: {}, findings: [{ code: 'VIP_EXTERNAL_ZONE_REQUIRED', source_vdom: 'root', identity: 'web', message: 'Choose zone' }] },
    section: 'policy', busy: false, onChange: (value) => { settings = value } }
  let tree = await harness.render({ ...props, settings })
  elements(tree).find((node) => node.props['aria-label'] === 'Original-packet destination zone for root/web').props.onChange({ target: { value: 'outside' } })
  assert.deepEqual(settings.vip_external_zones, { blue: { web: 'blue-outside' }, root: { web: 'outside' } })
  tree = await harness.render({ ...props, draft: { context: { conversion_settings: settings }, findings: [] }, settings, busy: true })
  const input = elements(tree).find((node) => node.props['aria-label'] === 'Original-packet destination zone for root/web')
  assert.equal(input.props.value, 'outside')
  assert.equal(input.props.disabled, true)
})

test('public navigation hides device access while local navigation exposes it', async () => {
  const harness = component('../src/components/layout/Sidebar.tsx', 'Sidebar', {})
  const props = { view: 'report', onViewChange: () => {} }
  const publicTree = await harness.render({ ...props, liveDeviceAccess: false })
  assert.equal(elements(publicTree).filter((node) => node.type === 'button').length, 2)
  assert.ok(!JSON.stringify(publicTree).includes('Live collection'))
  assert.ok(!JSON.stringify(publicTree).includes('Live migration'))
  const localTree = await harness.render({ ...props, liveDeviceAccess: true })
  assert.equal(elements(localTree).filter((node) => node.type === 'button').length, 4)
})

test('device controls stay unavailable when server capabilities cannot be loaded', async () => {
  const originalWindow = globalThis.window
  const originalDocument = globalThis.document
  globalThis.window = { setInterval: () => 1, clearInterval: () => {} }
  globalThis.document = { documentElement: { dataset: {} } }
  try {
    for (const allowed of [false, true, 'failed']) {
      const harness = component('../src/App.tsx', 'default', {
        './App.css': {},
        './storage/workspaceStore': { clearWorkspace: async () => {}, workspaceExpired: () => false },
        './components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
        './components/layout/AppLayout': { AppLayout: 'AppLayout' },
        './features/source/SourceConfiguration': { SourceConfiguration: 'SourceConfiguration' },
        './api/client': { apiFetch: async (path) => {
          assert.equal(path, '/api/capabilities')
          if (allowed === 'failed') throw new Error('offline')
          return { ok: true, json: async () => ({ live_device_access: allowed }) }
        } },
      })
      const tree = await harness.render({})
      const expected = allowed === true
      assert.equal(tree.props.liveDeviceAccess, expected)
      assert.equal(elements(tree).find((node) => node.type === 'SourceConfiguration').props.liveDeviceAccess, expected)
    }
  } finally {
    globalThis.window = originalWindow
    globalThis.document = originalDocument
  }
})

// Exercise component handlers and effects with the same hook harness used by validationReport tests.
function component(file, name, modules, { strictEffectReplay = false } = {}) {
  const slots = []
  let cursor = 0
  let pending = false
  let effects = []
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) slots[index] = typeof initial === 'function' ? initial() : initial
      return [slots[index], (value) => {
        const next = typeof value === 'function' ? value(slots[index]) : value
        if (!Object.is(next, slots[index])) { slots[index] = next; pending = true }
      }]
    },
    useMemo(factory, dependencies) {
      const index = cursor++
      const old = slots[index]
      if (!old || dependencies.some((value, i) => !Object.is(value, old.dependencies[i]))) {
        slots[index] = { dependencies, value: factory() }
      }
      return slots[index].value
    },
    useRef(value) { return hooks.useMemo(() => ({ current: value }), []) },
    useCallback(callback, dependencies) { return hooks.useMemo(() => callback, dependencies) },
    useEffect(callback, dependencies) {
      const cleanup = hooks.useRef()
      hooks.useMemo(() => { effects.push(() => {
        cleanup.current?.()
        cleanup.current = callback()
        return () => { cleanup.current?.(); cleanup.current = undefined }
      }) }, dependencies)
    },
  }
  const compiled = ts.transpileModule(readFileSync(new URL(file, import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText
  const exports = {}
  const requireModule = (key) => {
    if (key.endsWith('/components/MigrationCoverage')) return { MigrationCoverage: 'MigrationCoverage' }
    if (key.endsWith('/components/DestinationSnapshot')) return { DestinationSnapshot: 'DestinationSnapshot' }
    if (key === 'react') return hooks
    if (key === 'react/jsx-runtime') return jsxRuntime
    if (key in modules) return modules[key]
    if (key.endsWith('/components/common/Button')) return { Button: 'Button' }
    if (key.endsWith('/components/common/ErrorBanner')) return { ErrorBanner: 'ErrorBanner' }
    if (key.endsWith('/components/common/LoadingState')) return { LoadingState: 'LoadingState' }
    if (key.endsWith('/components/common/tabKeyboard')) return { tabKeyboard: () => {} }
    if (key === './components/MigrationTargetSetup') return { MigrationTargetSetup: 'TargetSetup' }
    if (key === './components/MigrationSetUpload') return { MigrationSetUpload: 'SetUpload' }
    if (key === './components/MigrationConversionSettings') return { MigrationConversionSettings: 'ConversionSettings' }
    if (key === './components/MigrationIssueWorkspace') return { MigrationIssueWorkspace: 'IssueWorkspace' }
    if (key === '../migration/fortigateToJuniperSrx/MigrationWorkflow') return { JuniperSRXMigrationWorkflow: 'JuniperSRX' }
    if (key === '../migration/fortigateToCiscoAsa/MigrationWorkflow') return { CiscoAsaMigrationWorkflow: 'CiscoAsa' }
    if (key.endsWith('/MigrationMappingSummary')) return { MigrationMappingSummary: 'MappingSummary' }
    if (key === './hooks/useMigrationReviewActivity') {
      const hook = ts.transpileModule(readFileSync(new URL('../src/features/migration/hooks/useMigrationReviewActivity.ts', import.meta.url), 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.CommonJS },
      }).outputText
      const hookExports = {}
      new Function('require', 'exports', hook)((dependency) =>
        requireModule(dependency === '../../../api/client' ? '../../api/client' : dependency), hookExports)
      return hookExports
    }
    assert.ok(key in modules, `Unexpected import: ${key}`)
    return modules[key]
  }
  new Function('require', 'exports', compiled)(requireModule, exports)
  return {
    async render(props) {
      if (name === 'MigrationReview') props = { stage: 'place', onStageChange: () => {}, ...props }
      let tree
      for (let attempt = 0; attempt < 20; attempt++) {
        pending = false
        cursor = 0
        tree = exports[name](props)
        const currentEffects = effects
        effects = []
        currentEffects.forEach((effect) => {
          const cleanup = effect()
          if (strictEffectReplay && attempt === 0 && typeof cleanup === 'function') { cleanup(); effect() }
        })
        await new Promise((resolve) => setImmediate(resolve))
        if (!pending) return tree
      }
      assert.fail('Component did not settle')
    },
  }
}

test('destination uploads discard replaced responses and retain only sanitized evidence', async () => {
  const requests = []
  let value = null
  let uploading = false
  const onChange = (next) => { value = next }
  const onPendingChange = (next) => { uploading = next }
  const harness = component('../src/features/migration/components/DestinationSnapshot.tsx', 'DestinationSnapshot', {
    '../../source/FileUpload': { FileUpload: 'FileUpload' },
    '../../source/sourceApi': { previewSource: () => new Promise((resolve) => requests.push(resolve)) },
  })
  const props = () => ({ vendor: 'cisco_asa', families: ['objects'], value, disabled: false,
    onChange, onPendingChange })
  let tree = await harness.render(props())
  elements(tree).find((node) => node.type === 'FileUpload').props.onChange(new File(['raw first'], 'first.cfg'))
  tree = await harness.render(props())
  elements(tree).find((node) => node.type === 'FileUpload').props.onChange(new File(['raw second'], 'second.cfg'))
  requests[1]({ source_evidence: { vendor: 'cisco_asa', source_text: 'sanitized second', source_name: 'second.cfg' } })
  tree = await harness.render(props())
  requests[0]({ source_evidence: { vendor: 'cisco_asa', source_text: 'sanitized first' } })
  tree = await harness.render(props())
  assert.equal(value.source.source_text, 'sanitized second')
  assert.equal(uploading, false)
  const checkbox = elements(tree).find((node) => node.type === 'input' && node.props.type === 'checkbox')
  checkbox.props.onChange({ target: { checked: true } })
  assert.deepEqual(value.metadata.complete_families, ['objects'])
  tree = await harness.render(props())
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Remove destination evidence').props.onClick()
  assert.equal(value, null)
})

for (const [folder, name, pairId] of [
  ['fortigateToCiscoAsa', 'CiscoAsaMigrationWorkflow', 'fortigate_to_cisco_asa'],
  ['fortigateToJuniperSrx', 'JuniperSRXMigrationWorkflow', 'fortigate_to_juniper_srx'],
  ['fortigateToCheckPoint', 'CheckPointMigrationWorkflow', 'fortigate_to_checkpoint'],
]) test(`${pairId}: destination edits invalidate approval and discard stale preparation`, async () => {
  const source = { vendor: 'fortigate', source_text: 'source' }
  const destination = { source: { vendor: 'target', source_text: 'one' }, metadata: { context: 'scope', version: 'version', mode: 'mode', complete_families: [] } }
  const options = { source_vdom: 'root', interfaces: {}, zones: {}, install_on: [] }
  const report = { items: [], findings: [] }
  let saved = { pairId, sourceKey: 'source', options, destination, requirements: [], review: { report }, approval: { signature: 'old' }, artifact: { artifact_id: 'old' }, previewText: 'old', preview: {} }
  let finish
  const calls = []
  const harness = component(`../src/features/migration/${folder}/MigrationWorkflow.tsx`, name, {
    '../../../storage/workspaceStore': { workspace: () => ({ newPairMigration: saved }), saveWorkspace: async (update) => { saved = update.newPairMigration } },
    '../migrationApi': { downloadFile: () => {} },
    './migrationApi': { requirements: async () => ({ requirements: [], report }), prepare: (...args) => {
      calls.push(args)
      return new Promise((resolve) => { finish = resolve })
    } },
  })
  const props = { source, sourceKey: 'source', stage: 'place', onStageChange: () => {} }
  let tree = await harness.render(props)
  const snapshot = elements(tree).find((node) => node.type === 'DestinationSnapshot')
  const next = { ...destination, metadata: { ...destination.metadata, complete_families: ['objects'] } }
  snapshot.props.onChange(next)
  tree = await harness.render(props)
  assert.equal(saved.approval, null)
  assert.equal(saved.artifact, null)
  elements(tree).find((node) => (node.type === 'Button' || node.type === 'button') && /^Prepare/.test(node.props.children)).props.onClick()
  tree = await harness.render(props)
  assert.deepEqual(calls[0].at(-1), next)
  elements(tree).find((node) => node.type === 'DestinationSnapshot').props.onChange(null)
  finish({ draft: { digest: 'stale' }, requirements: [], report })
  tree = await harness.render(props)
  assert.equal(saved.review, null)
  assert.equal(saved.destination, null)
})

test('initial migration preparation starts once when StrictMode replays effects', async () => {
  const requests = []
  const modes = []
  const result = { decisions: { decisions: [] }, decision_document: { decisions: [] }, target_devices: [], target_device: null,
    decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'draft', context: { overrides: {} }, decisions: [], configuration: [] } }
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': { ...workspace, saveWorkspace: async () => {} },
    '../../api/client': { RequestError: api.RequestError, postJson: async (path, payload) => { requests.push(path); modes.push(payload.workflow_mode); return result } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design', MigrationDesignSummary: 'DesignSummary' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  }, { strictEffectReplay: true })
  await harness.render({ preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate' })
  assert.deepEqual(requests, ['/api/migration/design/prepare'])
  assert.deepEqual(modes, ['OFFLINE_EXPORT'])
})

test('offline setup removes duplicate tools and moves exceptions to review; destination tools remain available', async () => {
  const result = { decisions: { decisions: [] }, decision_document: { decisions: [] }, target_devices: [], target_device: null,
    decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'draft', context: { overrides: {} }, decisions: [], configuration: [], readiness: { coverage: { supported: 0, manual: 2841 }, deployment: { missing_prerequisites: ['baseline_sha256'] } } } }
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': { ...workspace, saveWorkspace: async () => {} },
    '../../api/client': { RequestError: api.RequestError, postJson: async () => result },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'load' }
  let tree = await harness.render(props)
  const evidence = (tree) => elements(tree).find((node) => node.type === 'details' && node.props.className === 'migration-target-evidence')
  const tools = (tree) => elements(tree).find((node) => node.type === 'details' && elements(node.props.children).some((child) => child.type === 'summary' && child.props.children === 'Advanced tools and mapping files'))
  assert.equal(evidence(tree).props.open, false)
  assert.equal(evidence(tree).props.hidden, true)
  assert.equal(tools(tree), undefined)
  assert.equal(elements(tree).find((node) => node.type === 'Interfaces'), undefined)
  assert.equal(elements(tree).find((node) => node.type === 'Decisions'), undefined)
  tree = await harness.render({ ...props, stage: 'place' })
  assert.equal(elements(tree).find((node) => node.props.id === 'migration-panel-manual')?.props.hidden, true)
  assert.equal(tools(tree), undefined)
  tree = await harness.render({ ...props, stage: 'review' })
  const tablist = elements(tree).find((node) => node.props.role === 'tablist' && node.props['aria-label'] === 'Review migration')
  assert.ok(tablist)
  assert.deepEqual(elements(tablist).filter((node) => node.props.role === 'tab').map((node) => [node.props.children].flat().filter((value) => typeof value === 'string').join('')), ['Changes ', 'Needs your input ', 'Work outside this tool '])
  assert.equal(elements(tree).find((node) => node.props.id === 'migration-exceptions'), undefined)
  const options = elements(tree).find((node) => node.props.className === 'conversion-options')
  assert.ok(options)
  assert.ok(!options.props.open)
  const changedTabs = []
  tree = await harness.render({ ...props, stage: 'review', onReviewTabChange: (tab) => changedTabs.push(tab) })
  const initialContext = elements(tree).find((node) => node.type === 'IssueWorkspace' && node.props.tab === 'decisions').props.contextKey
  elements(tree).find((node) => node.type === 'Design').props.onSelectIssue('issue-1')
  assert.deepEqual(changedTabs, ['decisions'])
  tree = await harness.render(props)
  const inputWorkspace = elements(tree).find((node) => node.type === 'IssueWorkspace' && node.props.tab === 'decisions')
  assert.equal(inputWorkspace.props.selectedId, 'issue-1')
  assert.notEqual(inputWorkspace.props.contextKey, initialContext, 'Linked inputs reset old task filters')
  elements(tree).find((node) => node.type === 'Design').props.onResolveInputs()
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.type === 'IssueWorkspace' && node.props.tab === 'decisions').props.selectedId, '')
  assert.ok(!JSON.stringify(tree).includes('Candidate prerequisites missing'))
  assert.ok(!elements(tree).map((node) => [node.props.children].flat().filter((value) => typeof value === 'string').join(' ')).join(' ').includes('baseline_sha256'))
  assert.ok(!JSON.stringify(tree).includes('migration-review-intro'))
  await elements(tree).find((node) => node.type === 'select' && node.props['aria-label'] === 'Migration intent').props.onChange({ target: { value: 'destination' } })
  tree = await harness.render(props)
  assert.equal(evidence(tree).props.open, true)
  assert.equal(evidence(tree).props.hidden, false)
  tree = await harness.render({ ...props, stage: 'place' })
  assert.equal(tools(tree).props.hidden, false)
  assert.ok(elements(tree).some((node) => node.type === 'Interfaces'))
  assert.ok(elements(tree).some((node) => node.type === 'Decisions'))
})

test('source panel collapses after successful analysis and preserves manual expansion until the source changes', async () => {
  let completePreview
  let rejectPreview
  let completeSnapshot
  const modules = {
    '../../storage/workspaceStore': { restoreWorkspace: async () => ({}), saveWorkspace: async () => {} },
    '../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' }, '../../components/common/LoadingState': { LoadingState: 'LoadingState' },
    './FileUpload': { FileUpload: 'FileUpload' }, '../report/SourceReport': { SourceReport: 'SourceReport' },
    '../report/ExcelExportControls': { ExcelExportControls: 'ExcelExportControls' },
    './sourceApi': {
      loadMigrationPairs: async () => [{ pair_id: 'fortigate_to_palo_alto', source_vendor: 'fortigate', target_vendor: 'palo_alto', display_name: 'FortiGate → PAN-OS', export_available: true }],
      loadSourceVendors: async () => [{ vendor_id: 'fortigate', display_name: 'FortiGate', file_extensions: ['.conf'] }],
      previewSource: () => new Promise((resolve, reject) => { completePreview = resolve; rejectPreview = reject }),
      importCollectionSnapshot: () => new Promise((resolve) => { completeSnapshot = resolve }),
    },
    './SourceOverview': { SourceOverview: 'SourceOverview' }, './VendorSelect': { VendorSelect: 'VendorSelect' }, './LiveCollection': { LiveCollection: 'LiveCollection' },
    '../migration/MigrationWorkflow': { MigrationWorkflow: 'MigrationWorkflow' }, '../migration/MigrationReview': { MigrationReview: 'MigrationReview' },
    '../migration/paloAltoToFortigate/MigrationWorkflow': { FortiGateMigrationWorkflow: 'FortiGateMigrationWorkflow' },
    '../migration/MigrationPairWorkflow': { MigrationPairWorkflow: 'MigrationPairWorkflow' },
    '../migration/pairApi': { loadMigrationPairs: async () => [
      { pair_id: 'fortigate_to_palo_alto', source_vendor: 'fortigate', target_vendor: 'palo_alto', display_name: 'FortiGate → PAN-OS', export_available: true },
      { pair_id: 'fortigate_to_juniper_srx', source_vendor: 'fortigate', target_vendor: 'juniper_srx', display_name: 'FortiGate → Juniper SRX', export_available: true },
    ] },
    '../report/reportPresentation': { asRecord: (value) => value ?? {} },
  }
  const harness = component('../src/features/source/SourceConfiguration.tsx', 'SourceConfiguration', modules)
  const props = { view: 'report', onViewChange: () => {}, liveDeviceAccess: false }
  const controls = (tree) => elements(tree).find((node) => node.props.id === 'source-configuration-controls')
  const upload = (tree) => elements(tree).find((node) => node.type === 'FileUpload')
  const toggle = (tree) => elements(tree).find((node) => node.props['aria-controls'] === 'source-configuration-controls')
  let tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, false)
  upload(tree).props.onChange({ name: 'first.conf', size: 2048 })
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, false, 'Loading never hides the source controls')
  completePreview({ source_digest: 'first', source_evidence: { source_name: 'first.conf' } })
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, true)
  assert.equal(toggle(tree).props.children, 'Change source')
  assert.ok(JSON.stringify(tree).includes('first.conf'))
  toggle(tree).props.onClick()
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, false)
  assert.equal(upload(tree).props.file.name, 'first.conf', 'Expanding preserves the current source')
  elements(tree).find((node) => node.type === 'SourceReport').props.onExcelProfileChange('full')
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, false, 'Report updates preserve manual expansion')
  upload(tree).props.onChange({ name: 'bad.conf', size: 10 })
  tree = await harness.render(props)
  rejectPreview(new Error('Invalid configuration'))
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, false)
  assert.equal(elements(tree).find((node) => node.type === 'SourceReport'), undefined)
  assert.ok(JSON.stringify(tree).includes('Invalid configuration'))
  upload(tree).props.onChange({ name: 'second.conf', size: 50 })
  tree = await harness.render(props)
  completePreview({ source_digest: 'second', source_evidence: { source_name: 'second.conf' } })
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, true)
  toggle(tree).props.onClick()
  tree = await harness.render(props)
  elements(tree).find((node) => node.props.role === 'tab' && String(node.props.children).includes('Upload Snapshot')).props.onClick()
  tree = await harness.render(props)
  upload(tree).props.onChange({ name: 'snapshot.json' })
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, false)
  completeSnapshot({ vendor_id: 'fortigate', snapshot: { source_name: 'snapshot.json' }, preview: { source_digest: 'snapshot' } })
  tree = await harness.render(props)
  assert.equal(controls(tree).props.hidden, true)
  toggle(tree).props.onClick()
  tree = await harness.render(props)
  assert.equal(upload(tree).props.title, 'Drop your collection snapshot here', 'Imported sources remain replaceable')
  modules['../../storage/workspaceStore'].restoreWorkspace = async () => ({ preview: {
    vendor: 'palo_alto', source_digest: 'restored', source_evidence: { source_name: 'restored.xml' },
  } })
  const restored = component('../src/features/source/SourceConfiguration.tsx', 'SourceConfiguration', modules)
  tree = await restored.render(props)
  assert.equal(controls(tree).props.hidden, true)
  assert.ok(JSON.stringify(tree).includes('restored.xml'))
  assert.equal(elements(tree).find((node) => node.type === 'SourceReport').props.excelProfile, 'full')
})

test('a new source analysis opens target setup and keeps source settings reachable', async () => {
  const harness = component('../src/features/source/SourceConfiguration.tsx', 'SourceConfiguration', {
    '../../storage/workspaceStore': { restoreWorkspace: async () => ({}), saveWorkspace: async () => {} },
    '../../components/common/Button': { Button: 'Button' }, '../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../components/common/LoadingState': { LoadingState: 'LoadingState' }, './FileUpload': { FileUpload: 'FileUpload' },
    '../report/SourceReport': { SourceReport: 'SourceReport' },
    '../report/ExcelExportControls': { ExcelExportControls: 'ExcelExportControls' },
    './sourceApi': { loadMigrationPairs: async () => [{ pair_id: 'fortigate_to_palo_alto', source_vendor: 'fortigate', target_vendor: 'palo_alto', display_name: 'FortiGate → PAN-OS', export_available: true }], loadSourceVendors: async () => [{ vendor_id: 'fortigate', display_name: 'FortiGate', file_extensions: ['.conf'] }], previewSource: async () => ({ source_digest: 'source', source_evidence: {} }), downloadSourceWorkbook: async () => {}, importCollectionSnapshot: async () => {} },
    './SourceOverview': { SourceOverview: 'SourceOverview' }, './VendorSelect': { VendorSelect: 'VendorSelect' }, './LiveCollection': { LiveCollection: 'LiveCollection' },
    '../migration/MigrationWorkflow': { MigrationWorkflow: 'MigrationWorkflow' }, '../migration/MigrationReview': { MigrationReview: 'MigrationReview' },
    '../migration/paloAltoToFortigate/MigrationWorkflow': { FortiGateMigrationWorkflow: 'FortiGateMigrationWorkflow' },
    '../migration/MigrationPairWorkflow': { MigrationPairWorkflow: 'MigrationPairWorkflow' },
    '../migration/pairApi': { loadMigrationPairs: async () => [
      { pair_id: 'fortigate_to_palo_alto', source_vendor: 'fortigate', target_vendor: 'palo_alto', display_name: 'FortiGate → PAN-OS', export_available: true },
      { pair_id: 'fortigate_to_juniper_srx', source_vendor: 'fortigate', target_vendor: 'juniper_srx', display_name: 'FortiGate → Juniper SRX', export_available: true },
    ] },
    '../report/reportPresentation': { asRecord: (value) => value ?? {} },
  })
  let tree = await harness.render({ view: 'migration', onViewChange: () => {} })
  const liveTree = await harness.render({ view: 'live', liveDeviceAccess: true, onViewChange: () => {} })
  assert.deepEqual(elements(liveTree).find((node) => node.type === 'MigrationWorkflow').props.preview, {})
  assert.equal(elements(liveTree).find((node) => node.props.id === 'source-configuration').props.hidden, true)
  tree = await harness.render({ view: 'migration', onViewChange: () => {} })
  assert.ok(!JSON.stringify(tree).includes('Download project'))
  assert.ok(!JSON.stringify(tree).includes('Resume project'))
  const upload = elements(tree).find((node) => node.type === 'FileUpload')
  upload.props.onChange(new Blob(['config']))
  tree = await harness.render({ view: 'migration', onViewChange: () => {} })
  assert.ok(!JSON.stringify(tree).includes('Migration project files'))
  assert.equal(elements(tree).find((node) => node.type === 'MigrationReview').props.stage, 'place')
  let migration = elements(tree).find((node) => node.type === 'MigrationReview')
  assert.equal(migration.props.reviewTab, 'changes')
  migration.props.onReviewTabChange('manual')
  tree = await harness.render({ view: 'migration', onViewChange: () => {} })
  migration = elements(tree).find((node) => node.type === 'MigrationReview')
  assert.equal(migration.props.reviewTab, 'manual')
  migration.props.onContextChange({ source_text: '<config />' }, 'PA1')
  tree = await harness.render({ view: 'migration', onViewChange: () => {} })
  assert.equal(elements(tree).find((node) => node.type === 'MigrationReview').props.reviewTab, 'changes')
  const labels = ['Source', 'Target setup', 'Review migration', 'Download']
  const stages = ['load', 'place', 'review', 'export']
  const nav = elements(tree).find((node) => node.props['aria-label'] === 'Migration workspace')
  assert.equal(elements(nav.props.children).filter((node) => node.type === 'button').length, 4)
  for (const index of [1, 2, 3, 0]) {
    const button = elements(tree).find((node) => node.type === 'button' && node.props.children?.[2] === labels[index])
    button.props.onClick()
    tree = await harness.render({ view: 'migration', onViewChange: () => {} })
    assert.equal(elements(tree).find((node) => node.type === 'MigrationReview').props.stage, stages[index])
  }
  const target = elements(tree).find((node) => node.type === 'select' && node.props.value === 'fortigate_to_palo_alto')
  target.props.onChange({ target: { value: 'fortigate_to_juniper_srx' } })
  tree = await harness.render({ view: 'migration', onViewChange: () => {} })
  assert.equal(elements(tree).find((node) => node.type === 'MigrationPairWorkflow').props.pairId, 'fortigate_to_juniper_srx')
})

function elements(tree) {
  if (Array.isArray(tree)) return tree.flatMap(elements)
  if (!tree || typeof tree !== 'object') return []
  return [tree, ...elements(tree.props?.children)]
}

test('controlled settings preserve hardware across VPN editing and keep version metadata', async () => {
  const harness = component('../src/features/migration/components/MigrationConversionSettings.tsx', 'MigrationConversionSettings', {})
  let settings = { panos_version: '11.1' }
  const props = { draft: { context: {}, findings: [
    { code: 'VPN_PARAMETERS_REQUIRED', message: 'Missing lifetime', source_vdom: 'root', source_kind: 'ipsec_phase2', fields: ['lifetime_seconds'], member_keys: ['root/ipsec_phase2/a', 'root/ipsec_phase2/b'] },
  ] }, busy: false, onChange: (value) => { settings = value } }
  let tree = await harness.render({ ...props, settings, section: 'hardware' })
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'PAN-OS command version'), undefined)
  elements(tree).find((node) => node.props['aria-label'] === 'Target hardware').props.onChange({ target: { value: 'PA-820' } })
  tree = await harness.render({ ...props, settings, section: 'vpn' })
  elements(tree).find((node) => node.type === 'input' && node.props.type === 'number').props.onChange({ target: { value: '86400' } })
  assert.deepEqual(settings, { panos_version: '11.1', target_model: 'PA-820', vpn_parameters: {
    'root/ipsec_phase2/a': { lifetime_seconds: 86400 }, 'root/ipsec_phase2/b': { lifetime_seconds: 86400 },
  } })
})

test('bulk management and identity proposals remain controlled and preserve identity overrides', async () => {
  const harness = component('../src/features/migration/components/MigrationConversionSettings.tsx', 'MigrationConversionSettings', {})
  let settings = { identity_mappings: { root: { 'group/staff': 'DOMAIN/staff' } } }
  const props = { draft: { context: {}, findings: [
    { code: 'MANAGEMENT_PROFILE_GROUP', identity: 'root/ping,ssh', source_vdom: 'root', message: 'ping, ssh', member_keys: ['root/port1'] },
    { code: 'IDENTITY_MAPPING_REQUIRED', identity: 'group/staff', proposed_value: 'staff', source_vdom: 'root', message: 'group staff', member_keys: ['1'] },
    { code: 'IDENTITY_MAPPING_REQUIRED', identity: 'group/finance', proposed_value: 'finance', source_vdom: 'root', message: 'group finance', member_keys: ['2'] },
  ] }, busy: false, onChange: (value) => { settings = value } }
  let tree = await harness.render({ ...props, settings, section: 'management' })
  assert.deepEqual(elements(tree).filter((node) => node.type === 'summary').map((node) => node.props.children),
    ['Use existing profile', 'Create profile'])
  const settingsGroup = elements(tree).find((node) => node.type.name === 'SettingsGroup')
  assert.equal(settingsGroup.props.title, 'Interface access')
  assert.equal(settingsGroup.props.inline, false)
  assert.ok(elements(tree).filter((node) => node.type === 'details').every((node) => !node.props.open))
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Apply to groups').props.disabled, true)
  elements(tree).find((node) => node.props['aria-label'] === 'Allowed IP ranges for all groups').props.onChange({ target: { value: '192.0.2.0/24' } })
  tree = await harness.render({ ...props, settings, section: 'management' })
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Apply to groups').props.onClick()
  tree = await harness.render({ ...props, settings, section: 'policy' })
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Propose source identity names').props.onClick()
  assert.deepEqual(settings.generated_management_profiles, { 'root/ping,ssh': { permitted_ips: ['192.0.2.0/24'] } })
  assert.deepEqual(settings.identity_mappings, { root: { 'group/staff': 'DOMAIN/staff', 'group/finance': 'finance' } })
  assert.equal(settings.identity_prerequisites, undefined)
  tree = await harness.render({ ...props, draft: { ...props.draft, destination_verified: true }, settings, section: 'management' })
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Apply to groups').props.disabled, true)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Allowed IP ranges for root/ping,ssh').props.disabled, true)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Management profile for root/ping,ssh').props.disabled, false)
})

test('one reviewed management profile applies only to its scoped protocol group', async () => {
  const harness = component('../src/features/migration/components/MigrationConversionSettings.tsx', 'MigrationConversionSettings', {})
  let settings = { management_profiles: { 'root/a': 'old-a', 'root/b': 'old-b', 'blue/a': 'keep' } }
  const props = { draft: { context: {}, findings: [{ code: 'MANAGEMENT_PROFILE_GROUP', identity: 'root/ping,ssh', source_vdom: 'root',
      message: 'ping, ssh', member_keys: ['root/a', 'root/b'] }] }, busy: false, onChange: (value) => { settings = value } }
  const tree = await harness.render({ ...props, settings, section: 'management' })
  const field = elements(tree).find((node) => node.props['aria-label'] === 'Management profile for root/ping,ssh')
  assert.equal(field.props.value, '')
  assert.ok(field.props.placeholder.startsWith('Mixed assignments'))
  field.props.onChange({ target: { value: 'reviewed-profile' } })
  assert.deepEqual(settings.management_profiles, { 'root/a': 'reviewed-profile', 'root/b': 'reviewed-profile', 'blue/a': 'keep' })
})

test('decision workspace settings edit only the selected finding scope', async () => {
  const harness = component('../src/features/migration/components/MigrationConversionSettings.tsx', 'MigrationConversionSettings', {})
  let settings = { existing_vpns: ['branch/site'] }
  const action = { kind: 'EDIT_SETTINGS', section: 'vpn', finding_code: 'VPN_PREREQUISITE', source_vdom: 'root', identity: 'root/site', member_keys: [] }
  const props = { draft: { context: {}, findings: [
    { code: 'VPN_PREREQUISITE', source_vdom: 'root', identity: 'root/site', message: 'Root VPN' },
    { code: 'VPN_PREREQUISITE', source_vdom: 'branch', identity: 'branch/site', message: 'Branch VPN' },
  ] }, section: 'vpn', busy: false, settings, selectedFinding: action, onChange: (value) => { settings = value } }
  const tree = await harness.render(props)
  const checks = elements(tree).filter((node) => node.type === 'input' && node.props.type === 'checkbox')
  assert.equal(checks.length, 1)
  assert.equal(checks[0].props.checked, false)
  checks[0].props.onChange({ target: { checked: true } })
  assert.deepEqual(settings.existing_vpns, ['branch/site', 'root/site'])
})

const workspace = { workspace: () => ({ referenceRole: 'TEMPLATE', targetSource: null,
  targetDevice: '', deterministicDraft: null, artifact: null }), saveWorkspace: async () => {} }
const destinationWorkspace = { ...workspace, workspace: () => ({ ...workspace.workspace(), workflowMode: 'destination' }) }
const api = { RequestError: class extends Error {} }

function reviewHarness(postJson, store = workspace) {
  return component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': store, '../../api/client': { ...api, postJson },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
}

for (const mode of ['offline', 'destination']) test(`${mode}: rejected settings can be corrected without losing mappings or granting approval`, async () => {
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null }
  const initial = { decisions: { decisions: [decision] }, decision_document: { decisions: [decision] }, target_devices: mode === 'destination' ? ['serial'] : [], target_device: mode === 'destination' ? 'serial' : '',
    decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'initial', context: { overrides: {}, conversion_settings: {} },
      decisions: [{ ...decision, decision_key: 'port', status: 'READY', proposed_value: 'ethernet1/1', dependencies: [] }], configuration: [] } }
  const calls = [], documents = [], approvals = []
  const harness = reviewHarness(async (path, payload) => {
    calls.push({ path, payload })
    if (calls.length === 1) return initial
    if (payload.conversion_settings.generated_management_profiles['root/ping'].permitted_ips[0] === 'invalid') throw new Error('Invalid management network')
    return { ...initial, draft: { ...initial.draft, digest: 'corrected', context: { overrides: payload.draft_overrides, conversion_settings: payload.conversion_settings },
      decisions: [{ ...initial.draft.decisions[0], proposed_value: payload.draft_overrides.port }] } }
  }, { ...workspace, workspace: () => ({ ...workspace.workspace(), workflowMode: mode }) })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'place', onDecisionDocument: (value) => documents.push(value), onApproved: () => approvals.push(true) }
  let tree = await harness.render(props)
  const setup = () => elements(tree).find((node) => node.type === 'TargetSetup')
  const editor = () => elements(tree).find((node) => node.type === 'ConversionSettings')
  const settings = { target_model: 'PA-820', generated_management_profiles: { 'root/ping': { permitted_ips: ['invalid'] } } }
  if (mode === 'offline') setup().props.onChange('port', 'ethernet1/2')
  else elements(tree).find((node) => node.type === 'Queues').props.setDrafts({ port: 'ethernet1/2' })
  tree = await harness.render(props)
  editor().props.onChange(settings)
  tree = await harness.render(props)
  if (mode === 'offline') await setup().props.onApply()
  else await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Validate changes').props.onClick()
  tree = await harness.render(props)
  assert.equal(editor().props.busy, false)
  assert.equal(mode === 'offline' ? setup().props.busy : elements(tree).find((node) => node.type === 'Queues').props.busy, false)
  assert.equal(elements(tree).find((node) => node.type === 'Design').props.busy, true)
  assert.equal(calls.length, 2)
  editor().props.onChange({ ...settings, generated_management_profiles: { 'root/ping': { permitted_ips: ['192.0.2.0/24'] } } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'button' && node.props.children === 'Retry intended draft update').props.onClick()
  await new Promise((resolve) => setImmediate(resolve))
  tree = await harness.render(props)
  assert.deepEqual(calls[2].payload.draft_overrides, { port: 'ethernet1/2' })
  assert.deepEqual(calls[2].payload.conversion_settings, { ...settings, generated_management_profiles: { 'root/ping': { permitted_ips: ['192.0.2.0/24'] } } })
  assert.equal(calls[2].payload.target_device, mode === 'destination' ? 'serial' : '')
  assert.equal(elements(tree).find((node) => node.type === 'Design').props.busy, false)
  assert.ok(documents.every((document) => !document?.design_approval))
  assert.equal(approvals.length, 0)
})

test('a failed device-context change keeps editing and approval disabled', async () => {
  let calls = 0
  const harness = reviewHarness(async () => {
    if (calls++) throw new Error('Target could not be verified')
    return { decisions: { decisions: [] }, decision_document: { decisions: [] }, target_devices: ['serial', 'other'], target_device: 'serial',
      decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'initial', context: { overrides: {} }, decisions: [], configuration: [] } }
  }, destinationWorkspace)
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'load' }
  let tree = await harness.render(props)
  const device = elements(tree).find((node) => node.type === 'select' && Array.isArray(node.props.children) && JSON.stringify(node.props.children).includes('other'))
  device.props.onChange({ target: { value: 'other' } })
  await new Promise((resolve) => setImmediate(resolve))
  tree = await harness.render(props)
  assert.ok(elements(tree).filter((node) => node.type === 'ConversionSettings').every((node) => node.props.busy))
  assert.equal(elements(tree).find((node) => node.type === 'Design').props.busy, true)
  assert.ok(JSON.stringify(tree).includes('stale and read-only'))
})

test('destination bulk review stays in target setup and preserves staged values across steps', async () => {
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null }
  const group = { decision_keys: ['port'], source_vdom: 'root', source_kind: 'interface', source_name: 'port1', queue: 'NEEDS_INPUT', decisions: [decision], candidates: {}, source_evidence: {}, affected_count: 0, dependent_decision_count: 0 }
  const harness = reviewHarness(async () => ({ decisions: { decisions: [decision] }, decision_document: { decisions: [decision] }, target_devices: [], target_device: '',
    decision_candidates: {}, review_groups: [group], rule_suggestions: [], draft: { digest: 'initial', context: { overrides: {} }, decisions: [{ ...decision, decision_key: 'port', status: 'NEEDS_INPUT', dependencies: [] }], configuration: [] } }), destinationWorkspace)
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'place' }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Queues').props.setDrafts({ port: 'ethernet1/9' })
  tree = await harness.render(props)
  await elements(tree).find((node) => node.type === 'Queues').props.updateGroup(group)
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Bulk proposal review').props.hidden, false)
  assert.equal(elements(tree).filter((node) => node.type === 'MappingSummary').length, 1)
  assert.ok(!JSON.stringify(tree).includes('Design review stages'))
  assert.ok(!Object.keys(elements(tree).find((node) => node.type === 'MappingSummary').props.counts).some((key) => key.includes('configuration')))
  for (const stage of ['load', 'review', 'place']) {
    tree = await harness.render({ ...props, stage })
    assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Bulk proposal review').props.hidden, stage !== 'place')
    assert.equal(elements(tree).find((node) => node.type === 'Queues').props.drafts.port, 'ethernet1/9')
  }
})

test('the shared mapping dashboard has no configuration counts and separates exclusions', async () => {
  const harness = component('../src/features/migration/components/MigrationMappingSummary.tsx', 'MigrationMappingSummary', {})
  const tree = await harness.render({ counts: { needsInput: 1, conflicts: 2, blocked: 3, ready: 4, approved: 5, unsupported: 6, excluded: 7 }, pending: true })
  assert.ok(JSON.stringify(tree).includes('unsupported fields'))
  assert.ok(JSON.stringify(tree).includes('explicitly excluded fields'))
  assert.ok(!JSON.stringify(tree).includes('configuration items'))
  assert.ok(elements(tree).some((node) => node.props.role === 'status'))
})

test('review tabs route actionable task groups before manual work', () => {
  const makeIssue = (id, action) => ({ id, action })
  const issues = [makeIssue('mapping', { kind: 'EDIT_MAPPING', decision_key: 'key' }),
    makeIssue('setting', { kind: 'EDIT_SETTINGS', section: 'vpn' }),
    makeIssue('source', { kind: 'REVIEW_SOURCE' }), makeIssue('manual', null)]
  assert.deepEqual(presentation.migrationIssueCounts(issues), { decisions: 3, manual: 1 })
  assert.deepEqual(presentation.migrationIssueTasks(issues, 'manual').map((issue) => issue.id), ['manual'])
  assert.deepEqual(presentation.migrationIssueTasks(issues, 'decisions').map((issue) => issue.id), ['mapping', 'setting', 'source'])
})

test('review tabs use the shared arrow and Home/End keyboard behavior', () => {
  const originalDocument = globalThis.document
  const events = []
  const buttons = Array.from({ length: 3 }, (_, index) => ({ focus: () => events.push(['focus', index]), click: () => events.push(['click', index]) }))
  try {
    globalThis.document = { activeElement: buttons[0] }
    const event = (key) => ({ key, currentTarget: { querySelectorAll: () => buttons }, preventDefault: () => events.push(['prevent']) })
    tabKeyboard(event('ArrowRight'))
    assert.deepEqual(events, [['prevent'], ['focus', 1], ['click', 1]])
    events.length = 0
    globalThis.document.activeElement = buttons[2]
    tabKeyboard(event('Home'))
    assert.deepEqual(events, [['prevent'], ['focus', 0], ['click', 0]])
  } finally { globalThis.document = originalDocument }
})

test('compact mapping status hides zero counts and keeps evidence behind details', async () => {
  const harness = component('../src/features/migration/components/MigrationMappingSummary.tsx', 'MigrationMappingSummary', {})
  const counts = { needsInput: 1, conflicts: 0, blocked: 2, ready: 4, approved: 0, unsupported: 3, excluded: 1 }
  let tree = await harness.render({ counts, compact: true, sourceIssues: 2, pending: true, children: 'Source evidence' })
  const labels = elements(tree).filter((node) => node.type === 'span').map((node) => [node.props.children].flat().join(''))
  assert.deepEqual(labels, ['2 source issues · affected items blocked', 'Input needed: 1', 'Blocked: 2', 'Changes not validated'])
  assert.equal(elements(tree).filter((node) => node.type === 'h3').length, 0)
  const details = elements(tree).find((node) => node.type === 'details')
  assert.ok(!details.props.open)
  assert.ok(JSON.stringify(details).includes('Source evidence'))
  assert.ok(JSON.stringify(details).includes('Proposals require final approval'))
  tree = await harness.render({ counts: { ...counts, needsInput: 0, blocked: 0, conflicts: 1 }, compact: true })
  assert.deepEqual(elements(tree).filter((node) => node.type === 'span').map((node) => [node.props.children].flat().join('')), ['Conflicts: 1'])
  tree = await harness.render({ counts: { ...counts, needsInput: 0, blocked: 0 }, compact: true })
  assert.equal(elements(tree).filter((node) => node.type === 'span').length, 0)
})

test('mapping summary separates conflicts, unsupported fields and explicit exclusions', () => {
  const rows = [
    { decision_key: 'input', status: 'NEEDS_INPUT', dependencies: [] },
    { decision_key: 'conflict', status: 'CONFLICT', dependencies: [] },
    { decision_key: 'child', status: 'NEEDS_INPUT', dependencies: ['input'] },
    { decision_key: 'ready', status: 'READY', dependencies: [] },
    { decision_key: 'approved', status: 'READY', dependencies: [] },
    { decision_key: 'unsupported', status: 'UNSUPPORTED', dependencies: [] },
    { decision_key: 'excluded', status: 'UNSUPPORTED', source_kind: 'interface', source_vdom: 'root', source_name: 'port1', dependencies: [] },
  ]
  assert.deepEqual(presentation.mappingSummary(rows, new Map(rows.map((row) => [row.decision_key, row])), new Set(['approved']), ['root/port1']),
    { needsInput: 1, conflicts: 1, blocked: 1, ready: 1, approved: 1, unsupported: 1, excluded: 1 })
})

test('compact placement retains conflicts and pending edits without repeating ready labels', async () => {
  const row = { decision_key: 'vsys', source_vdom: 'root', source_kind: 'vdom', source_name: 'root', target_field: 'vsys',
    proposed_value: 'vsys1', status: 'CONFLICT', dependencies: [], blocking_reasons: [] }
  const harness = component('../src/features/migration/components/MigrationTargetSetup.tsx', 'MigrationTargetSetup', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const props = { draft: { decisions: [row], configuration: [] }, review: { decisions: { decisions: [] } }, drafts: {}, approvedItems: [], busy: false }
  let tree = await harness.render(props)
  assert.ok(elements(tree).some((node) => node.type === 'small' && node.props.children === 'Conflict'))
  tree = await harness.render({ ...props, drafts: { vsys: 'vsys2' } })
  assert.ok(elements(tree).some((node) => node.type === 'small' && node.props.children === 'Pending validation'))
  assert.ok(elements(tree).some((node) => node.type === 'Button' && node.props.children === 'Validate changes'))
  tree = await harness.render({ ...props, draft: { ...props.draft, decisions: [{ ...row, status: 'READY' }] } })
  assert.equal(elements(tree).filter((node) => node.type === 'small').length, 0)
})

test('empty specialist sections disappear while applied choices stay editable', async () => {
  const harness = component('../src/features/migration/components/MigrationConversionSettings.tsx', 'MigrationConversionSettings', {})
  const settings = { existing_vpns: ['root/site'], vpn_parameters: { 'root/ipsec_phase2/site': { lifetime_seconds: 3600 } },
    identity_mappings: { root: { 'group/staff': 'DOMAIN/staff' } }, security_profiles: { 'root/inspection': 'protected' },
    management_profiles: { 'root/port1': 'admin' } }
  for (const section of ['management', 'vpn', 'policy']) {
    const empty = await harness.render({ draft: { context: {}, findings: [] }, settings: {}, section, busy: false, onChange: () => {} })
    assert.equal(elements(empty).filter((node) => node.type === 'details').length, 0)
    const tree = await harness.render({ draft: { context: { conversion_settings: settings }, findings: [] }, settings, section, busy: false, onChange: () => {} })
    assert.ok(elements(tree).some((node) => node.props.id === `settings-${section}`))
    if (section === 'management') {
      assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Management profile for interface:root/port1').props.value, 'admin')
      assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Allowed IP ranges for all groups'), undefined)
    }
    if (section === 'vpn') assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'lifetime seconds').props.value, 3600)
    if (section === 'policy') assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Target identity for root/group/staff').props.value, 'DOMAIN/staff')
  }
})

test('settings and mapping edits validate together, survive failure and undo without restoring approval', async () => {
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null }
  const result = { decisions: { decisions: [decision] }, decision_document: { decisions: [decision], design_approval: { configuration: {}, decisions: { port: { review_state: 'CONFIRMED', approved_operation: 'CREATE' } } } }, target_devices: [], target_device: null,
    decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'draft', context: { overrides: {}, conversion_settings: { panos_version: '11.1' } },
      decisions: [{ ...decision, decision_key: 'port', status: 'READY', proposed_value: 'ethernet1/1', dependencies: [] }], configuration: [] } }
  const calls = [], documents = [], stages = []
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': workspace,
    '../../api/client': { ...api, postJson: async (path, payload) => { calls.push({ path, payload }); if (calls.length > 1) throw new Error('validation failed'); return result } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'place', onDecisionDocument: (value) => documents.push(value), onStageChange: (value) => stages.push(value) }
  let tree = await harness.render(props)
  const setup = () => elements(tree).find((node) => node.type === 'TargetSetup')
  setup().props.onChange('port', 'ethernet1/2')
  tree = await harness.render(props)
  setup().props.onSettingsChange({ ...setup().props.settings, target_model: 'PA-820' })
  tree = await harness.render({ ...props, stage: 'review' })
  assert.ok(elements(tree).find((node) => node.type === 'Design').props.busy)
  tree = await harness.render(props)
  await setup().props.onApply()
  tree = await harness.render(props)
  assert.deepEqual(calls[1].payload.draft_overrides, { port: 'ethernet1/2' })
  assert.deepEqual(calls[1].payload.conversion_settings, { panos_version: '11.1', target_model: 'PA-820' })
  assert.equal(setup().props.drafts.port, 'ethernet1/2')
  assert.equal(setup().props.settings.target_model, 'PA-820')
  setup().props.onUndo()
  tree = await harness.render(props)
  assert.equal(setup().props.drafts.port, 'ethernet1/1')
  assert.deepEqual(setup().props.settings, { panos_version: '11.1' })
  assert.deepEqual(setup().props.approvedItems, [])
  assert.equal(setup().props.approvalRevoked, true)
  assert.equal(documents.at(-1), null)
  await elements(tree).find((node) => node.type === 'Design').props.onApprove(['port'])
  assert.equal(calls.length, 2)
  await elements(tree).find((node) => node.type === 'button' && node.props.children === 'Retry intended draft update').props.onClick()
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(calls[2].payload.conversion_settings, { panos_version: '11.1' })
  assert.deepEqual(calls[2].payload.draft_overrides, {})
  setup().props.onViewIssues()
  tree = await harness.render({ ...props, stage: stages.at(-1) })
  assert.equal(stages.at(-1), 'review')
  assert.equal(elements(tree).find((node) => node.props.id === 'migration-exceptions'), undefined)
})

test('excluded interfaces can be re-included while missing source interfaces have no scope toggle', async () => {
  const rows = ['port1', 'missing', 'ssl.root'].map((name) => ({ decision_key: name, source_vdom: 'root', source_kind: 'interface', source_name: name,
    target_field: 'target_interface', status: 'UNSUPPORTED', dependencies: [], blocking_reasons: [] }))
  const changes = []
  const harness = component('../src/features/migration/components/MigrationTargetSetup.tsx', 'MigrationTargetSetup', { '../reviewDrafts': drafts, '../reviewPresentation': presentation })
  const tree = await harness.render({ draft: { context: { conversion_settings: { excluded_interfaces: ['root/port1'] } }, decisions: rows, configuration: [], source_issues: [{ code: 'SOURCE_INTERFACE_MISSING', source_vdom: 'root', source_name: 'missing', affected_keys: [], message: 'Missing source' }] },
    review: { decisions: { decisions: rows.map((row) => ({ ...row, key: row.decision_key })) } }, drafts: {}, approvedItems: [], busy: false,
    settings: { excluded_interfaces: ['root/port1'] }, onSettingsChange: (value) => changes.push(value) })
  const toggle = elements(tree).find((node) => node.props['aria-label'] === 'Include root/port1 in conversion')
  assert.equal(toggle.props.checked, false)
  assert.equal(toggle.props.disabled, false)
  toggle.props.onChange({ target: { checked: true } })
  assert.deepEqual(changes, [{ excluded_interfaces: [] }])
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Include root/missing in conversion'), undefined)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Include root/ssl.root in conversion'), undefined)
  assert.ok(!elements(tree).some((node) => node.props.role === 'alert'))
})

test('offline target setup applies scoped edits once and keeps approval separate', async () => {
  const decisions = ['root', 'blue'].map((vdom) => ({ key: `${vdom}-port`, source_vdom: vdom, source_kind: 'interface', source_name: 'port1',
    target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null }))
  const result = { decisions: { decisions }, decision_document: { decisions }, target_devices: [], target_device: null,
    decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'draft', context: { overrides: {} },
      decisions: decisions.map((row) => ({ ...row, decision_key: row.key, status: 'NEEDS_INPUT', proposed_value: null, dependencies: [] })), configuration: [] } }
  const calls = []
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': workspace,
    '../../api/client': { ...api, postJson: async (path, payload) => { calls.push({ path, payload }); return result } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'place' }
  let tree = await harness.render(props)
  const setup = () => elements(tree).find((node) => node.type === 'TargetSetup')
  setup().props.onChange('root-port', 'ethernet1/1')
  tree = await harness.render(props)
  setup().props.onChange('blue-port', ' ')
  tree = await harness.render(props)
  await setup().props.onApply()
  tree = await harness.render(props)
  assert.deepEqual(calls.map((call) => call.path), ['/api/migration/design/prepare', '/api/migration/design/prepare'])
  assert.deepEqual(calls[1].payload.draft_overrides, { 'root-port': 'ethernet1/1' })
  assert.equal(calls[1].payload.workflow_mode, 'OFFLINE_EXPORT')
  assert.ok(!setup().props.review.decision_document.design_approval)
  const advanced = elements(tree).find((node) => node.type === 'details' && node.props.children?.[0]?.props.children === 'Advanced mapping editors')
  assert.equal(advanced, undefined)
})

test('target setup uses direct fields, draft states, pagination and scoped navigation', async () => {
  const fields = Array.from({ length: 30 }, (_, index) => ({ decision_key: `port-${index}`, source_vdom: 'root', source_kind: 'interface',
    source_name: `port${String(index).padStart(2, '0')}`, target_field: 'target_interface', proposed_value: index ? `ethernet1/${index + 1}` : null,
    status: index ? 'READY' : 'NEEDS_INPUT', dependencies: [], blocking_reasons: [],
    evidence: index ? ['Automatic offline port allocation proposal; target port availability, hardware and cabling are unverified. Engineer approval is required.'] : [] }))
  const ownership = { decision_key: 'vsys', source_vdom: 'root', source_kind: 'vdom', source_name: 'root', target_field: 'vsys',
    proposed_value: 'vsys1', status: 'READY', dependencies: [], blocking_reasons: [] }
  const harness = component('../src/features/migration/components/MigrationTargetSetup.tsx', 'MigrationTargetSetup', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const edits = []
  const props = { draft: { decisions: [ownership, ...fields], configuration: [] },
    review: { decisions: { decisions: fields.map((row) => ({ ...row, key: row.decision_key, review_state: 'PENDING' })) }, decision_context: {} },
    drafts: {}, approvedItems: [], busy: false, onChange: (...args) => edits.push(args), onApply: () => {}, onReview: () => {} }
  let tree = await harness.render(props)
  assert.equal(elements(tree).filter((node) => node.type === 'select').length, 0)
  assert.equal(elements(tree).filter((node) => node.type === 'tr').length, 11)
  assert.deepEqual(elements(tree).filter((node) => node.type === 'th').map((node) => node.props.children), ['Include', 'Source', 'Target interface', 'Zone', 'Status'])
  assert.ok(elements(tree).some((node) => node.type === 'p' && node.props.children === 'Ports unverified. Check hardware and cabling.'))
  assert.ok(elements(tree).some((node) => node.type === 'summary' && node.props.children === 'Proposal evidence'))
  assert.ok(!elements(tree).some((node) => node.type === 'small' && node.props.children === 'Ready for review'))
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Continue').props.disabled, false)
  assert.ok(elements(tree).some((node) => node.type === 'td' && node.props.children?.[0] === 'Ready'))
  assert.ok(elements(tree).some((node) => node.type === 'td' && node.props.children?.[0] === 'Needs decision'))
  const input = elements(tree).find((node) => node.props['aria-label'] === 'Target interface for root / port00')
  input.props.onChange({ target: { value: 'ethernet1/1' } })
  assert.deepEqual(edits, [['port-0', 'ethernet1/1']])
  tree = await harness.render({ ...props, drafts: { 'port-0': 'ethernet1/1' } })
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Validate changes').props.disabled, false)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Continue'), undefined)
  const editedProps = { ...props, drafts: { 'port-0': 'ethernet1/1' } }
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next interfaces').props.onClick()
  tree = await harness.render(editedProps)
  assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Target interface for root / port10'))
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Previous interfaces').props.onClick()
  tree = await harness.render(editedProps)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Target interface for root / port00').props.value, 'ethernet1/1')
  const search = elements(tree).find((node) => node.type === 'input' && !node.props['aria-label'])
  search.props.onChange({ target: { value: 'port29' } })
  tree = await harness.render(editedProps)
  assert.equal(elements(tree).filter((node) => node.type === 'tr').length, 2)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next interfaces'), undefined)
  const originalDocument = globalThis.document
  globalThis.document = { getElementById: () => null }
  try {
    tree = await harness.render({ ...props, focusRequest: { key: 'port-29', request: 1 } })
    assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Target interface for root / port29'))
    assert.equal(elements(tree).filter((node) => node.type === 'tr').length, 11)
    assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next interfaces').props.disabled, true)
  } finally { globalThis.document = originalDocument }
})

test('unsupported VPN and missing source rows explain the gap without editable mapping fields', async () => {
  const interfaces = ['dev.pnet', 'ssl.root', 'l2t.root', 'naf.root', 'Euronet-P1'].flatMap((name) =>
    ['target_interface', 'target_zone'].map((field) => ({ decision_key: `${name}-${field}`, source_vdom: 'root', source_kind: 'interface',
      source_name: name, target_field: field, proposed_value: field === 'target_zone' ? `root-${name}` : null,
      status: name === 'Euronet-P1' ? 'NEEDS_INPUT' : 'UNSUPPORTED', dependencies: [],
      blocking_reasons: ['Special or remote-access tunnel requires a separate target VPN design'] })))
  const sameNameOtherScope = { ...interfaces.at(-2), decision_key: 'blue-euronet', source_vdom: 'blue', status: 'READY', proposed_value: 'tunnel.9' }
  const fields = [...interfaces, sameNameOtherScope]
  const harness = component('../src/features/migration/components/MigrationTargetSetup.tsx', 'MigrationTargetSetup', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const sourceIssue = { code: 'SOURCE_INTERFACE_MISSING', source_vdom: 'root', source_name: 'Euronet-P1',
    message: 'Euronet-P1 is referenced but has no explicit source interface.', affected_keys: ['dependent'] }
  const tree = await harness.render({ draft: { decisions: fields, configuration: [], source_issues: [sourceIssue] },
    review: { decisions: { decisions: fields.map((row) => ({ ...row, key: row.decision_key })) } },
    drafts: {}, approvedItems: [], busy: false, onChange: () => assert.fail('Unavailable mappings cannot be edited') })
  assert.equal(elements(tree).filter((node) => node.type === 'input' && /for root/.test(node.props['aria-label'])).length, 0)
  assert.equal(elements(tree).filter((node) => node.type === 'strong' && node.props.children === 'Not converted automatically').length, 4)
  assert.equal(elements(tree).filter((node) => node.type === 'strong' && node.props.children === 'Source interface missing').length, 1)
  assert.equal(elements(tree).filter((node) => node.type === 'td' && node.props.children === 'Not generated').length, 5)
  assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Needs attention'))
  const summary = elements(tree).find((node) => node.type === 'MappingSummary')
  assert.equal(summary.props.compact, true)
  assert.equal(summary.props.sourceIssues, 1)
  assert.ok(JSON.stringify(summary.props.children).includes(sourceIssue.message))
  assert.ok(elements(tree).find((node) => node.type === 'MappingSummary').props.counts.unsupported > 0)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Target interface for blue / Euronet-P1').props.value, 'tunnel.9')
})

test('shared zones are edited once within interfaces while explicit member overrides stay editable', async () => {
  const shared = { decision_key: 'shared', source_vdom: 'root', source_kind: 'zone', source_name: 'VPN', target_field: 'target_zone',
    proposed_value: 'VPN', status: 'READY', dependencies: [], blocking_reasons: [] }
  const fields = [shared, ...['a', 'b', 'c'].flatMap((name) => ['target_interface', 'target_zone'].map((field) => ({
    ...shared, decision_key: `${name}-${field}`, source_kind: 'interface', source_name: name, target_field: field,
    proposed_value: field === 'target_interface' ? `tunnel.${name === 'a' ? 1 : 2}` : name === 'a' ? 'VPN' : 'custom-zone',
    dependencies: field === 'target_zone' ? ['shared'] : [],
  })))]
  const harness = component('../src/features/migration/components/MigrationTargetSetup.tsx', 'MigrationTargetSetup', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const changes = []
  const props = { draft: { decisions: fields, configuration: [], context: { overrides: { 'b-target_zone': 'custom-zone' } } },
    review: { decisions: { decisions: fields.map((row) => ({ ...row, key: row.decision_key })) }, decision_context: { shared: { source_members: ['a', 'b', 'c'] } } },
    drafts: { 'a-target_zone': 'VPN' }, approvedItems: [], busy: false, onChange: (...args) => changes.push(args) }
  let tree = await harness.render(props)
  assert.ok(!JSON.stringify(tree).includes('Source zone proposals'))
  assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Shared source zones'))
  assert.ok(JSON.stringify(tree).includes('a, b'))
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Zone for root / a'), undefined)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Zone for root / b').props.value, 'custom-zone')
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Zone for root / c').props.value, 'custom-zone')
  elements(tree).find((node) => node.props['aria-label'] === 'Source zone for root / VPN').props.onChange({ target: { value: 'new-zone' } })
  assert.deepEqual(changes, [['shared', 'new-zone']])
  tree = await harness.render({ ...props, drafts: { shared: 'new-zone' } })
  assert.equal(elements(tree).find((node) => node.props.id === 'setup-a-target_zone').props.children[0], 'new-zone')
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Zone for root / b').props.value, 'custom-zone')
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Continue'), undefined)
  tree = await harness.render({ ...props, drafts: { 'a-target_zone': 'staged-zone' } })
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Zone for root / a').props.value, 'staged-zone')
})

test('needs-attention navigation opens the page with the actionable mapping', async () => {
  const fields = Array.from({ length: 30 }, (_, index) => ({ decision_key: `port-${index}`, source_vdom: 'root', source_kind: 'interface',
    source_name: `port${String(index).padStart(2, '0')}`, target_field: 'target_interface', status: 'NEEDS_INPUT', dependencies: [], blocking_reasons: [] }))
  const harness = component('../src/features/migration/components/MigrationTargetSetup.tsx', 'MigrationTargetSetup', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const props = { draft: { decisions: fields, configuration: [], issues: [{ id: 'choice', category: 'CHOICE', source_vdom: 'root',
    source_name: 'port29', explanation: 'Choose its target port.', action: { kind: 'EDIT_MAPPING', decision_key: 'port-29' } }] },
    review: { decisions: { decisions: fields.map((row) => ({ ...row, key: row.decision_key })) } }, drafts: {}, approvedItems: [], busy: false }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review mapping').props.onClick()
  tree = await harness.render(props)
  assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Target interface for root / port29'))
})

test('reference role stays editable after upload and a failed rebuild revokes artifacts and preserves edits', async () => {
  let state = { ...workspace.workspace(), workflowMode: 'destination', targetSource: { vendor: 'palo_alto', source_text: '<config />' } }
  const requests = []
  let fail = false
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING' }
  const result = { decisions: { decisions: [decision] }, decision_document: { decisions: [decision] }, target_devices: [],
    decision_candidates: {}, review_groups: [], rule_suggestions: [], draft: { digest: 'draft', context: { overrides: {} }, decisions: [], configuration: [] } }
  const documents = []
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': { workspace: () => state, saveWorkspace: async (update) => { state = { ...state, ...update } } },
    '../../api/client': { RequestError: api.RequestError, postJson: async (_, payload) => { requests.push(payload); if (fail) throw new Error('role rebuild failed'); return result } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', onDecisionDocument: (value) => documents.push(value) }
  let tree = await harness.render(props)
  const queues = () => elements(tree).find((node) => node.type === 'Queues')
  queues().props.setDrafts({ port: 'ethernet1/9' })
  tree = await harness.render(props)
  state.artifact = { artifact_id: 'approved' }
  const before = documents.length
  queues().props.setDrafts((current) => ({ ...current }))
  tree = await harness.render(props)
  assert.equal(documents.length, before)
  assert.equal(state.artifact.artifact_id, 'approved')
  fail = true
  await elements(tree).find((node) => node.props['aria-label'] === 'Reference role').props.onChange({ target: { value: 'DESTINATION' } })
  tree = await harness.render(props)
  assert.equal(requests.at(-1).reference_role, 'DESTINATION')
  assert.equal(state.referenceRole, 'DESTINATION')
  assert.equal(state.artifact, null)
  assert.equal(state.decisionDocument, null)
  assert.equal(documents.at(-1), null)
  assert.equal(queues().props.drafts.port, 'ethernet1/9')
  assert.equal(queues().props.busy, true)
  fail = false
  await elements(tree).find((node) => node.type === 'button' && node.props.children === 'Retry intended draft update').props.onClick()
  await new Promise((resolve) => setImmediate(resolve))
  tree = await harness.render(props)
  assert.equal(requests.at(-1).reference_role, 'DESTINATION')
  assert.equal(queues().props.drafts.port, 'ethernet1/9')
  await elements(tree).find((node) => node.props['aria-label'] === 'Reference role').props.onChange({ target: { value: 'TEMPLATE' } })
  await harness.render(props)
  assert.equal(requests.at(-1).reference_role, 'TEMPLATE')
})

function workflowHarness(migrationApi) {
  return component('../src/features/migration/MigrationWorkflow.tsx', 'MigrationWorkflow', {
    '../../storage/workspaceStore': workspace, '../../api/client': api,
    '../../components/common/ErrorBanner': { ErrorBanner: 'Error' }, '../../components/common/Button': { Button: 'Button' },
    './PlanReview': { PlanReview: 'PlanReview' }, './migrationApi': migrationApi, './reviewPresentation': presentation,
  })
}

function uploadedReview(count = 1) {
  return { filename: 'commands.set', commands: Array.from({ length: count }, (_, index) => `set vsys vsys1 address host-${index} ip-netmask 192.0.2.1`),
    line_numbers: Array.from({ length: count }, (_, index) => index + 2), command_count: count, command_sha256: 'command-hash', file_sha256: 'file-hash',
    signature: 'signature', expires_at: 2000000000, context: { host: 'fw', port: 22, target_device: 'fw', target_serial: '012345678901' } }
}

test('uploaded command review is paged, requires explicit approval, and ignores replaced or stale inputs', async () => {
  let complete
  let invalidations = 0
  const approvals = []
  const harness = component('../src/features/migration/components/MigrationSetUpload.tsx', 'MigrationSetUpload', {
    '../../source/FileUpload': { FileUpload: 'FileUpload' }, '../../../components/common/ErrorBanner': { ErrorBanner: 'Error' },
    '../migrationApi': { prepareSetReview: async () => new Promise((resolve) => { complete = resolve }) },
  })
  const props = { host: 'fw', port: '22', busy: false, approved: false, canPrepare: true,
    onInvalidate: () => { invalidations++ }, onPrepare: (review) => approvals.push(review) }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.props.title === 'Choose PAN-OS .set file').props.onChange(new File(['set commands'], 'commands.set'))
  elements(tree).find((node) => node.props.title === 'Choose actual destination XML').props.onChange(new File(['<config/>'], 'destination.xml'))
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review uploaded commands').props.onClick()
  tree = await harness.render(props)
  assert.equal(approvals.length, 0)
  complete({ review: uploadedReview(60), devices: ['fw'] })
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.type === 'pre').props.children.split('\n').length, 50)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next commands').props.onClick()
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.type === 'pre').props.children.split('\n').length, 10)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Approve and prepare candidate').props.onClick()
  assert.equal(approvals.length, 1)
  tree = await harness.render({ ...props, host: 'other' })
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Uploaded command review'), undefined)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review uploaded commands').props.onClick()
  tree = await harness.render({ ...props, host: 'other' })
  elements(tree).find((node) => node.props.title === 'Choose PAN-OS .set file').props.onChange(new File(['replacement'], 'other.set'))
  complete({ review: uploadedReview(), devices: ['fw'] })
  tree = await harness.render({ ...props, host: 'other' })
  assert.equal(elements(tree).find((node) => node.type === 'pre'), undefined)
  assert.ok(invalidations >= 4)
})

test('live upload works without a source and approves before pushing with explicit commit', async () => {
  const calls = []
  const review = uploadedReview()
  const artifact = { ...review, artifact_id: 'upload-artifact', envelope_type: 'panos_set_import_v1' }
  const harness = workflowHarness({
    buildPlan: () => assert.fail('Upload must not invoke the planner'),
    approveSetReview: async (value) => { calls.push('approve'); assert.equal(value, review); return { artifact } },
    deployArtifact: async (value) => { calls.push('push'); assert.equal(value.artifact, artifact); return { deployment_session_id: 'session', candidate_validated: true, result: { commands_succeeded: 1, validation: { status: 'SUCCESS' } } } },
    commitCandidate: async () => { calls.push('commit'); return { result: { job_id: 'job' } } },
  })
  const props = { preview: {}, decisionDocument: null, targetSource: null, targetDevice: '', activeSection: 'live', liveDeviceAccess: true }
  let tree = await harness.render(props)
  assert.ok(elements(tree).some((node) => node.type === 'SetUpload'))
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare Candidate').props.disabled, true)
  elements(tree).find((node) => node.type === 'input' && node.props.type === 'password').props.onChange({ target: { value: 'secret' } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'SetUpload').props.onPrepare(review)
  tree = await harness.render(props)
  assert.deepEqual(calls, ['approve', 'push'])
  assert.equal(elements(tree).find((node) => node.type === 'input' && node.props.type === 'password').props.value, '')
  const previousWindow = globalThis.window
  globalThis.window = { confirm: () => true }
  try {
    await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.onClick()
    tree = await harness.render(props)
    assert.deepEqual(calls, ['approve', 'push', 'commit'])
    elements(tree).find((node) => node.type === 'SetUpload').props.onInvalidate()
    tree = await harness.render(props)
    assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Candidate recovery'), undefined)
  } finally { globalThis.window = previousWindow }
})

test('failed upload approval cannot push and a superseded approval cannot resume execution', async () => {
  let complete
  let fail = true
  let pushes = 0
  const harness = workflowHarness({
    approveSetReview: async () => { if (fail) throw new Error('Review expired'); return new Promise((resolve) => { complete = resolve }) },
    deployArtifact: async () => { pushes++; assert.fail('Stale approval must not push') },
  })
  const props = { preview: {}, decisionDocument: null, targetSource: null, targetDevice: '', activeSection: 'live', liveDeviceAccess: true }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'SetUpload').props.onPrepare(uploadedReview())
  tree = await harness.render(props)
  assert.ok(JSON.stringify(tree).includes('No commands were submitted'))
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Candidate recovery'), undefined)
  fail = false
  elements(tree).find((node) => node.type === 'SetUpload').props.onPrepare(uploadedReview())
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'SetUpload').props.onInvalidate()
  complete({ artifact: { ...uploadedReview(), artifact_id: 'superseded' } })
  tree = await harness.render(props)
  assert.equal(pushes, 0)
  assert.equal(elements(tree).find((node) => node.type === 'SetUpload').props.approved, false)
})

test('a replaced upload retains read-only recovery after partial writes and cannot replay', async () => {
  const artifact = { ...uploadedReview(), artifact_id: 'upload', envelope_type: 'panos_set_import_v1' }
  let pushes = 0
  const inspected = []
  const harness = workflowHarness({
    approveSetReview: async () => ({ artifact }),
    deployArtifact: async () => { pushes++; const error = new api.RequestError('Rejected'); error.details = { failed_line_number: 2, recovery: { state: 'PARTIAL_PUSH', commands_attempted: 1, commands_succeeded: 0 } }; throw error },
    inspectCandidate: async (value) => { inspected.push(value.artifact.artifact_id); return { inspection: { state: 'CLEAN_BASELINE', device_serial: '012345678901', baseline_matches: true, candidate_clean: true }, recovery: { state: 'CLEAN_BASELINE' } } },
  })
  const props = { preview: {}, decisionDocument: null, targetSource: null, targetDevice: '', activeSection: 'live', liveDeviceAccess: true }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'SetUpload').props.onPrepare(uploadedReview())
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.disabled, true)
  assert.ok(JSON.stringify(tree).includes('Uploaded file line 2 failed'))
  elements(tree).find((node) => node.type === 'SetUpload').props.onInvalidate()
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'SetUpload').props.onPrepare(uploadedReview())
  tree = await harness.render(props)
  assert.equal(pushes, 1)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Inspect candidate (read-only)').props.onClick()
  tree = await harness.render(props)
  assert.deepEqual(inspected, ['upload'])
  assert.equal(pushes, 1)
})

async function buildArtifact(harness, props) {
  let tree = await harness.render({ ...props, activeSection: 'plan' })
  await elements(tree).find((node) => node.type === 'Button' && String(node.props.children).startsWith('Build approved')).props.onClick()
  return harness.render(props)
}

test('approved partial plans build only on request and downloads identify excluded traffic rules', async () => {
  let builds = 0
  let filename = ''
  const reviewRequests = []
  const artifact = { artifact_id: 'partial', plan_status: 'NEEDS_MAPPING', render_summary: { create: 1, blocked: 2 },
    blocking_reasons: [], recommendations: [], report: { export_counts: { INCLUDED: 1, NOT_APPROVED: 1, UNSUPPORTED: 1 }, items: [
      { source_object_type: 'service', render_disposition: 'CREATE' },
      { source_object_type: 'security_rule', render_disposition: 'BLOCK', export_category: 'NOT_APPROVED' },
      { source_object_type: 'nat_rule', render_disposition: 'BLOCK', export_category: 'UNSUPPORTED' }], deployment_eligibility: { eligible: false } },
    artifact: { commands: ['set service x'], command_count: 1 } }
  const harness = workflowHarness({ buildPlan: async () => { builds++; return artifact }, downloadBundle: async () => new Blob(['zip']), downloadFile: (_blob, name) => { filename = name } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {}, decisions: [{ mode: 'REQUIRED', review_state: 'PENDING' }] }, targetSource: null, targetDevice: '', activeSection: 'plan', onReviewDecision: (key) => reviewRequests.push(key) }
  let tree = await harness.render(props)
  assert.equal(builds, 0)
  assert.ok(elements(tree).some((node) => node.props?.role === 'status' && String(node.props.children).includes('Design approved')))
  tree = await buildArtifact(harness, props)
  assert.equal(builds, 1)
  assert.ok(elements(tree).some((node) => node.props.role === 'status' && JSON.stringify(node.props.children).includes('supported configuration items were not selected for approval')))
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review remaining changes').props.onClick()
  assert.deepEqual(reviewRequests, [''])
  assert.ok(elements(tree).some((node) => typeof node.props?.children === 'string' && node.props.children.includes('No security policies, NAT rules or static routes')))
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Download partial bundle').props.onClick()
  assert.equal(filename, 'migration_fortigate_to_palo_alto_PARTIAL.zip')
  tree = await harness.render({ ...props, targetDevice: 'changed-device' })
  assert.equal(builds, 1)
  assert.ok(!elements(tree).some((node) => node.type === 'Button' && node.props.children === 'Download partial bundle'))
})

for (const family of ['security_rule', 'nat_rule', 'static_route']) test(`included ${family} suppresses the supporting-only export notice`, async () => {
  const artifact = { artifact_id: family, plan_status: 'READY', render_summary: { create: 1 },
    blocking_reasons: [], recommendations: [], report: { workflow_mode: 'OFFLINE_EXPORT', items: [
      { source_object_type: family, render_disposition: 'CREATE', export_category: 'INCLUDED' },
    ] }, artifact: { commands: ['set reviewed configuration'], command_count: 1 } }
  const harness = workflowHarness({ buildPlan: async () => artifact })
  const tree = await buildArtifact(harness, { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {}, decisions: [] }, targetSource: null, targetDevice: '', activeSection: 'plan' })
  assert.ok(!elements(tree).some((node) => typeof node.props?.children === 'string' && node.props.children.includes('No security policies, NAT rules or static routes')))
})

test('ready offline export shows unverified destination separately and hides live deployment', async () => {
  const artifact = { artifact_id: 'offline', plan_status: 'READY', render_summary: { create: 1 },
    blocking_reasons: [], recommendations: [], report: { workflow_mode: 'OFFLINE_EXPORT', destination_verified: false,
      deployment_eligibility: { eligible: false } }, artifact: { commands: ['set vsys vsys1 address host ip-netmask 192.0.2.1/32'], command_count: 1 } }
  let mode
  const harness = workflowHarness({ buildPlan: async (...args) => { mode = args[4]; return artifact } })
  const tree = await buildArtifact(harness, { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {}, decisions: [] }, targetSource: null, targetDevice: '', activeSection: 'plan' })
  assert.equal(mode, 'offline')
  assert.ok(elements(tree).some((node) => node.props.children === 'Ready for export'))
  assert.ok(elements(tree).some((node) => String(node.props.children).startsWith('Destination unverified. Check')))
  assert.ok(!elements(tree).some((node) => node.props.children === 'Open live migration'))
})

test('a context change suppresses an in-flight artifact download', async () => {
  let finishDownload
  let downloads = 0
  const artifact = { artifact_id: 'one', plan_status: 'READY', render_summary: {}, blocking_reasons: [], recommendations: [],
    report: {}, artifact: { commands: ['set service x'], command_count: 1 } }
  const harness = workflowHarness({ buildPlan: async () => artifact,
    downloadBundle: () => new Promise((resolve) => { finishDownload = resolve }), downloadFile: () => { downloads++ } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'one', source_evidence: {} },
    decisionDocument: { design_approval: {}, decisions: [] }, targetSource: null, targetDevice: '', activeSection: 'plan' }
  const tree = await buildArtifact(harness, props)
  const pending = elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Download migration bundle').props.onClick()
  await harness.render({ ...props, targetDevice: 'different' })
  finishDownload(new Blob(['zip']))
  await pending
  assert.equal(downloads, 0)
})

test('candidate preparation fails closed and explains missing destination evidence', async () => {
  for (const eligibility of [undefined, { eligible: false, reason: 'Approved destination serial evidence is required' }]) {
    const artifact = { plan_status: 'READY', render_summary: {}, report: { deployment_eligibility: eligibility }, artifact: { commands: ['set address x'], command_count: 1 } }
    const harness = workflowHarness({ buildPlan: async () => artifact, deployArtifact: async () => assert.fail('Ineligible artifact must not deploy') })
    const tree = await buildArtifact(harness, { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
      decisionDocument: { design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'live', liveDeviceAccess: true })
    const prepare = elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare Candidate')
    assert.equal(prepare.props.disabled, true)
    await prepare.props.onClick()
    assert.ok(elements(tree).some((node) => node.props?.role === 'status' && String(node.props.children).includes(eligibility?.reason || 'check candidate deployment eligibility')))
  }
})

test('plan blockers retain VDOM, object identity and mapping links while grouping exact repeats', async () => {
  const harness = component('../src/features/migration/PlanReview.tsx', 'PlanReview', {
    '../report/reportPresentation': { asRecord: (value) => value, safeValue: (value) => value, compactValue: String },
    './reviewPresentation': presentation,
  })
  const blocker = { code: 'DESIGN_GROUP_NOT_APPROVED', message: 'Design group not approved', source_vdom: 'root', source_kind: 'address', source_name: 'net' }
  const rows = [blocker, { ...blocker, source_vdom: 'blue' }, { ...blocker, source_name: 'other' },
    { ...blocker, decision_keys: ['mapping'] }, blocker]
  const tree = await harness.render({ artifact: { blocking_reasons: rows, recommendations: [], report: {} }, onReviewDecision: () => {} })
  const groups = elements(tree).find((node) => node.type?.name === 'PlanRows' && node.props.kind === 'blockers').props.rows
  assert.equal(groups.length, 3)
  assert.equal(groups[0].count, 3)
  assert.deepEqual(groups[0].affected.map((row) => row.source_name), ['net', 'other', 'net'])
  assert.equal(groups[1].source_vdom, 'blue')
  assert.deepEqual(groups[2].decision_keys, ['mapping'])
})

test('unsigned legacy decisions never build and expose the design review action', async () => {
  let builds = 0
  let reviews = 0
  const harness = workflowHarness({ buildPlan: async () => { builds++; assert.fail('Unsigned build') } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { decisions: [] }, targetSource: null, targetDevice: '', activeSection: 'plan',
    onReviewDecision: () => { reviews++ } }
  let tree = await harness.render(props)
  const build = elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Build approved artifact')
  assert.equal(build.props.disabled, true)
  await build.props.onClick()
  assert.equal(builds, 0)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review and approve design').props.onClick()
  assert.equal(reviews, 1)
  tree = await harness.render({ ...props, activeSection: 'live', liveDeviceAccess: true })
  for (const label of ['Prepare Candidate', 'Revalidate Candidate', 'Commit']) {
    assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === label).props.disabled, true)
  }
})

test('stale approval offers reapproval and candidate drift revokes commit', async () => {
  const artifact = { artifact_id: 'artifact', plan_status: 'READY', render_summary: {}, report: { deployment_eligibility: { eligible: true, reason: null } }, artifact: { commands: ['set address x'], command_count: 1 } }
  const stale = workflowHarness({ buildPlan: async () => { throw new Error('Approved design is stale') } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'plan', onReviewDecision: () => {} }
  let tree = await buildArtifact(stale, props)
  assert.ok(elements(tree).some((node) => node.type === 'Button' && node.props.children === 'Review and approve design'))
  assert.ok(elements(tree).some((node) => node.type === 'Error' && node.props.message.includes('stale')))
  const live = workflowHarness({ buildPlan: async () => artifact,
    deployArtifact: async () => ({ deployment_session_id: 'session', candidate_validated: true, result: { validation: { status: 'SUCCESS' } } }),
    validateCandidate: async () => { throw new Error('Candidate changed after validation; prepare the candidate again') },
    commitCandidate: async () => assert.fail('Drifted candidate must not commit'),
  })
  const liveProps = { ...props, activeSection: 'live', liveDeviceAccess: true }
  tree = await buildArtifact(live, liveProps)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare Candidate').props.onClick()
  tree = await live.render(liveProps)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.disabled, false)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Revalidate Candidate').props.onClick()
  tree = await live.render(liveProps)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.disabled, true)
  assert.ok(elements(tree).some((node) => node.type === 'Error' && node.props.message.includes('Candidate changed')))
  assert.ok(elements(tree).some((node) => node.props?.role === 'status' && node.props.children.includes('Inspect the candidate')))
})

test('expired deployment approval revokes the artifact and offers reapproval', async () => {
  const artifact = { artifact_id: 'artifact', plan_status: 'READY', render_summary: {}, report: { deployment_eligibility: { eligible: true, reason: null } }, artifact: { commands: ['set address x'], command_count: 1 } }
  const error = new api.RequestError('Design approval has expired')
  error.details = { error_code: 'artifact_ineligible' }
  const harness = workflowHarness({ buildPlan: async () => artifact, deployArtifact: async () => { throw error } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'live', liveDeviceAccess: true, onReviewDecision: () => {} }
  let tree = await buildArtifact(harness, props)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare Candidate').props.onClick()
  tree = await harness.render(props)
  for (const label of ['Prepare Candidate', 'Revalidate Candidate', 'Commit']) {
    assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === label).props.disabled, true)
  }
  assert.ok(elements(tree).some((node) => node.type === 'Button' && node.props.children === 'Review and approve design'))
})

test('manual proposal edits use draft preparation, conflict membership and visible blocker navigation', async () => {
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port1',
    target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null, suggested_value: null }
  const calls = []
  const review = { decisions: { decisions: [decision] }, decision_document: { draft_required: true, decisions: [decision] },
    target_devices: [], target_device: null, target_evidence: null, decision_candidates: {}, rule_suggestions: [],
    review_groups: [{ source_vdom: 'root', source_kind: 'interface', source_name: 'port1', queue: 'CONFLICT',
      decision_keys: ['port'], conflicts: [{ decision_key: 'port' }] }],
    draft: { digest: 'draft', context: { overrides: {} }, decisions: [{ decision_key: 'port', proposed_value: null }], configuration: [] } }
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': destinationWorkspace,
    '../../api/client': { ...api, postJson: async (path, payload) => { calls.push({ path, payload }); return review } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' },
    './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' },
    './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate' }
  let tree = await harness.render(props)
  let table = elements(tree).find((node) => node.type === 'Decisions')
  table.props.setEvidenceFilter('conflict')
  tree = await harness.render(props)
  table = elements(tree).find((node) => node.type === 'Decisions')
  assert.deepEqual(table.props.visibleDecisions.map((row) => row.key), ['port'])
  await table.props.updateProposal(decision, 'ethernet1/2')
  assert.equal(calls.at(-1).path, '/api/migration/design/prepare')
  assert.equal(calls.at(-1).payload.reference_role, 'TEMPLATE')
  assert.deepEqual(calls.at(-1).payload.draft_overrides, { port: 'ethernet1/2' })
  assert.equal(calls.at(-1).payload.decision_document.decisions[0].review_state, 'PENDING')
  tree = await harness.render(props)
  const tools = elements(tree).find((node) => node.type === 'details' && node.props.ref)
  tools.props.ref.current = { open: false }
  const oldDocument = globalThis.document
  globalThis.document = { getElementById: () => null }
  try {
    await harness.render({ ...props, requestedDecision: { key: 'port', request: 1 } })
    assert.equal(tools.props.ref.current.open, true)
  } finally { globalThis.document = oldDocument }
})

test('review invalidation preserves live connection and history while revoking candidate actions', async () => {
  let prepares = 0
  const artifact = { artifact_id: 'artifact', plan_status: 'READY', render_summary: {}, report: { deployment_eligibility: { eligible: true, reason: null } }, artifact: { commands: ['set address x'], command_count: 1 } }
  const harness = component('../src/features/migration/MigrationWorkflow.tsx', 'MigrationWorkflow', {
    '../../storage/workspaceStore': workspace, '../../api/client': api,
    '../../components/common/ErrorBanner': { ErrorBanner: 'Error' }, '../../components/common/Button': { Button: 'Button' },
    './PlanReview': { PlanReview: 'PlanReview' },
    './reviewPresentation': presentation,
    './migrationApi': { buildPlan: async () => artifact, deployArtifact: async () => {
      prepares++
      return { deployment_session_id: 'session', candidate_validated: true,
        result: { commands_succeeded: 1, validation: { status: 'SUCCESS' } } }
    } },
  })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { draft_required: true, design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'live', liveDeviceAccess: true }
  let tree = await buildArtifact(harness, props)
  const host = () => elements(tree).find((node) => node.type === 'input' && node.props.spellCheck === false)
  host().props.onChange({ target: { value: '192.0.2.10' } })
  tree = await harness.render(props)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare Candidate').props.onClick()
  tree = await harness.render(props)
  assert.equal(prepares, 1)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.disabled, false)
  tree = await harness.render({ ...props, decisionDocument: null })
  assert.equal(host().props.value, '192.0.2.10')
  assert.ok(elements(tree).some((node) => typeof node.props?.children === 'string' && node.props.children.includes('[PREPARE] Pushed 1')))
  for (const title of ['Prepare Candidate', 'Revalidate Candidate', 'Commit']) {
    assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === title).props.disabled, true)
  }
})

test('a server-validated mapping proposal is reported as pending approval without approving or building', async () => {
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port8', target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null, suggested_value: null }
  const group = { decision_keys: ['port'], source_vdom: 'root', source_kind: 'interface', source_name: 'port8', queue: 'NEEDS_INPUT', decisions: [decision], candidates: {}, source_evidence: {}, affected_count: 0, dependent_decision_count: 0, conflicts: [] }
  const result = { decisions: { decisions: [decision] }, decision_document: { decisions: [decision] }, target_devices: [], target_device: null,
    target_evidence: null, decision_candidates: {}, review_groups: [group], review_summary: {}, rule_suggestions: [], decision_context: {},
    draft: { digest: 'fresh', context: { overrides: {}, service_names: {} }, decisions: [{ decision_key: 'port', proposed_value: 'ethernet1/2', status: 'READY', approved: false, dependencies: [] }], configuration: [] } }
  const calls = []
  const saves = []
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': { ...destinationWorkspace, saveWorkspace: async (value) => saves.push(value) },
    '../../api/client': { RequestError: api.RequestError, postJson: async (path, payload) => { calls.push({ path, payload }); return result } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate' }
  let tree = await harness.render(props)
  let queues = elements(tree).find((node) => node.type === 'Queues')
  queues.props.setDrafts({ port: 'ethernet1/2' })
  tree = await harness.render(props)
  queues = elements(tree).find((node) => node.type === 'Queues')
  await queues.props.updateGroup(group)
  tree = await harness.render(props)
  assert.equal(calls.length, 1, 'reviewing staged values makes no request')
  await elements(tree).find((node) => node.type === 'button' && node.props.children === 'Validate staged changes').props.onClick()
  tree = await harness.render(props)
  assert.ok(elements(tree).some((node) => node.props?.role === 'status' && node.props.children?.[0] === 'Staged changes validated — awaiting approval.'))
  assert.deepEqual(calls.map((call) => call.path), ['/api/migration/design/prepare', '/api/migration/design/prepare'])
  assert.deepEqual(calls[1].payload.draft_overrides, { port: 'ethernet1/2' })
  assert.ok(saves.some((value) => value.artifact === null))
  tree = await harness.render({ ...props, stage: 'review' })
  assert.ok(elements(tree).some((node) => node.type === 'Design'))
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Resolve mappings').props.hidden, true)
  tree = await harness.render({ ...props, stage: 'place' })
  assert.equal(elements(tree).find((node) => node.type === 'Queues').props.drafts.port, 'ethernet1/2')
  elements(tree).find((node) => node.type === 'button' && node.props.children === 'Bulk editing').props.onClick()
  tree = await harness.render({ ...props, stage: 'place' })
  const guided = elements(tree).find((node) => node.type === 'div' && elements(node.props.children).some((child) => child.type === 'Queues'))
  const bulk = elements(tree).find((node) => node.type === 'div' && elements(node.props.children).some((child) => child.type === 'Interfaces'))
  assert.equal(guided.props.hidden, true)
  assert.equal(bulk.props.hidden, false)
})

test('a failed proposal save keeps the staged target value for retry', async () => {
  const decision = { key: 'port', source_vdom: 'root', source_kind: 'interface', source_name: 'port8', target_field: 'target_interface', mode: 'REQUIRED', review_state: 'PENDING', value: null, suggested_value: null }
  const group = { decision_keys: ['port'], source_vdom: 'root', source_kind: 'interface', source_name: 'port8', queue: 'NEEDS_INPUT', decisions: [decision], candidates: {}, source_evidence: {}, affected_count: 0, dependent_decision_count: 0, conflicts: [] }
  const result = { decisions: { decisions: [decision] }, decision_document: { decisions: [decision] }, target_devices: [], target_device: null, target_evidence: null,
    decision_candidates: {}, review_groups: [group], review_summary: {}, rule_suggestions: [], decision_context: {},
    draft: { digest: 'draft', context: { overrides: {} }, decisions: [{ decision_key: 'port', status: 'NEEDS_INPUT', approved: false, dependencies: [] }], configuration: [] } }
  let prepareCount = 0
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': destinationWorkspace,
    '../../api/client': { RequestError: api.RequestError, postJson: async () => { if (prepareCount++ === 1) throw new Error('prepare failed'); return result } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate' }
  let tree = await harness.render(props)
  let queues = elements(tree).find((node) => node.type === 'Queues')
  queues.props.setDrafts({ port: 'ethernet1/9' })
  tree = await harness.render(props)
  queues = elements(tree).find((node) => node.type === 'Queues')
  await queues.props.updateGroup(group)
  tree = await harness.render(props)
  await elements(tree).find((node) => node.type === 'button' && node.props.children === 'Validate staged changes').props.onClick()
  tree = await harness.render(props)
  queues = elements(tree).find((node) => node.type === 'Queues')
  assert.equal(queues.props.drafts.port, 'ethernet1/9')
  assert.equal(queues.props.selectedGroupKey, 'port')
  assert.ok(elements(tree).some((node) => node.props.role === 'alert' && node.props.children?.[0] === 'prepare failed'))
  assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Bulk proposal review'))
})

test('one validation request batches scoped mappings, skips blanks, and keeps incomplete tasks selected', async () => {
  const decisions = [
    { key: 'root-port', source_vdom: 'root', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface' },
    { key: 'blue-port', source_vdom: 'blue', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface' },
    { key: 'root-zone', source_vdom: 'root', source_kind: 'interface', source_name: 'port1', target_field: 'target_zone' },
  ].map((row) => ({ ...row, mode: 'REQUIRED', review_state: 'PENDING', value: null, suggested_value: null }))
  const group = { decision_keys: ['root-port', 'root-zone'], source_vdom: 'root', source_kind: 'interface', source_name: 'port1', queue: 'NEEDS_INPUT', decisions: [decisions[0], decisions[2]], candidates: {}, source_evidence: {}, affected_count: 2, dependent_decision_count: 0 }
  const blue = { ...group, source_vdom: 'blue', decision_keys: ['blue-port'], decisions: [decisions[1]] }
  const calls = [], documents = [], saves = []
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': { ...destinationWorkspace, saveWorkspace: async (value) => saves.push(value) },
    '../../api/client': { RequestError: api.RequestError, postJson: async (path, payload) => {
      calls.push({ path, payload })
      const overrides = payload.draft_overrides ?? {}
      return { decisions: { decisions }, decision_document: { decisions }, target_devices: [], target_device: null,
        decision_candidates: {}, review_groups: [group, blue], rule_suggestions: [],
        draft: { digest: 'draft', context: { overrides }, decisions: decisions.map((row) => ({ ...row, decision_key: row.key, proposed_value: overrides[row.key], status: overrides[row.key] ? 'READY' : 'NEEDS_INPUT', dependencies: row.key === 'root-zone' ? ['root-port'] : [] })), configuration: [] } }
    } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', stage: 'place', onDecisionDocument: (value) => documents.push(value) }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Queues').props.setSelectedGroupKey('root-port')
  elements(tree).find((node) => node.type === 'Queues').props.setDrafts({ 'root-port': ' ethernet1/1 ', 'blue-port': 'ethernet1/2', 'root-zone': ' ' })
  tree = await harness.render(props)
  assert.equal(documents.at(-1), null)
  assert.ok(saves.some((save) => save.artifact === null))
  assert.equal(calls.length, 1)
  await elements(tree).find((node) => node.type === 'Queues').props.updateGroup(group)
  tree = await harness.render(props)
  assert.equal(calls.length, 1)
  const preview = elements(tree).find((node) => node.props['aria-label'] === 'Bulk proposal review')
  assert.equal(elements(preview).filter((node) => node.type === 'li').length, 3)
  assert.ok(elements(preview).some((node) => node.type === 'summary' && node.props.children === 'Review direct dependents'))
  await elements(tree).find((node) => node.type === 'button' && node.props.children === 'Validate staged changes').props.onClick()
  tree = await harness.render(props)
  assert.deepEqual(calls[1].payload.draft_overrides, { 'root-port': 'ethernet1/1', 'blue-port': 'ethernet1/2' })
  assert.equal(calls.length, 2)
  assert.equal(elements(tree).find((node) => node.type === 'Queues').props.selectedGroupKey, 'root-port')
  assert.ok(!documents.at(-1).design_approval)
  assert.equal(elements(tree).find((node) => node.type === 'Design').props.busy, false)
})

for (const lateInitial of [false, true]) test(`target upload supersedes initial preparation with initial response ${lateInitial ? 'last' : 'first'}`, async () => {
  const initial = Promise.withResolvers()
  const upload = Promise.withResolvers()
  const fresh = Promise.withResolvers()
  const saves = [], contexts = [], documents = [], requests = []
  let orderCalls = 0
  const result = (digest, device = '') => ({ decisions: { decisions: [] }, decision_document: { decisions: [], source_digest: digest },
    target_devices: device ? [device] : [], target_device: device, decision_candidates: {}, review_groups: [], rule_suggestions: [],
    draft: { digest, context: { overrides: {} }, decisions: [], configuration: [] } })
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': { ...workspace, saveWorkspace: async (value) => saves.push(value) },
    '../../api/client': { ...api, postForm: () => upload.promise, postJson: (path, payload) => {
      requests.push({ path, payload }); return requests.length === 1 ? initial.promise : fresh.promise
    } },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {},
    './reviewDrafts': { ...drafts, orderReviewGroups: (...args) => { orderCalls++; return drafts.orderReviewGroups(...args) } },
    './reviewPresentation': presentation, './components/MigrationDesignReview': { MigrationDesignReview: 'Design' },
    './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' },
    './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate',
    onContextChange: (...args) => contexts.push(args), onDecisionDocument: (value) => documents.push(value) }
  const oldInterval = globalThis.setInterval, oldClear = globalThis.clearInterval
  globalThis.setInterval = () => 0
  globalThis.clearInterval = () => {}
  try {
    let tree = await harness.render(props)
    const input = elements(tree).find((node) => node.type === 'FileUpload')
    assert.equal(input.props.disabled, false)
    input.props.onChange(new Blob(['<config/>'], { type: 'application/xml' }))
    tree = await harness.render(props)
    assert.equal(elements(tree).find((node) => node.type === 'FileUpload').props.disabled, true)
    if (!lateInitial) { initial.resolve(result('stale')); await harness.render(props) }
    const target = { vendor: 'palo_alto', source_text: '<config/>' }
    upload.resolve({ source_evidence: target })
    await harness.render(props)
    assert.deepEqual(requests[1].payload.target_source, target)
    fresh.resolve(result('fresh', 'fw'))
    tree = await harness.render(props)
    if (lateInitial) { initial.resolve(result('stale')); tree = await harness.render(props) }
    assert.deepEqual(contexts, [[target, 'fw']])
    assert.equal(documents.filter(Boolean).length, 1)
    assert.equal(documents.filter(Boolean)[0].source_digest, 'fresh')
    assert.equal(saves.filter((value) => value.deterministicDraft).length, 1)
    assert.equal(saves.find((value) => value.deterministicDraft).deterministicDraft.digest, 'fresh')
    const ordered = orderCalls
    await harness.render(props)
    assert.equal(orderCalls, ordered, 'Unchanged draft must not be sorted again on render')
    assert.ok(elements(tree).some((node) => node.props?.role === 'status' && String(node.props.children).includes('Target evidence loaded')))
  } finally { globalThis.setInterval = oldInterval; globalThis.clearInterval = oldClear }
})

test('failed target upload releases the input and ignores the superseded initial draft', async () => {
  const initial = Promise.withResolvers()
  const upload = Promise.withResolvers()
  const documents = []
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': workspace,
    '../../api/client': { ...api, postJson: () => initial.promise, postForm: () => upload.promise },
    '../source/FileUpload': { FileUpload: 'FileUpload' }, './download': {}, './reviewDrafts': drafts, './reviewPresentation': presentation,
    './components/MigrationDesignReview': { MigrationDesignReview: 'Design' }, './components/MigrationReviewQueues': { MigrationReviewQueues: 'Queues' },
    './components/MigrationDecisionTable': { MigrationDecisionTable: 'Decisions' }, './components/MigrationInterfaceMappings': { MigrationInterfaceMappings: 'Interfaces' },
  })
  const props = { preview: { source_digest: 'source', source_evidence: {} }, vendor: 'fortigate', onDecisionDocument: (value) => documents.push(value) }
  const oldInterval = globalThis.setInterval, oldClear = globalThis.clearInterval
  globalThis.setInterval = () => 0
  globalThis.clearInterval = () => {}
  try {
    let tree = await harness.render(props)
    elements(tree).find((node) => node.type === 'FileUpload').props.onChange(new Blob(['invalid']))
    await harness.render(props)
    upload.reject(new Error('Invalid PAN-OS XML'))
    tree = await harness.render(props)
    assert.equal(elements(tree).find((node) => node.type === 'FileUpload').props.disabled, false)
    assert.ok(elements(tree).some((node) => node.props?.role === 'alert' && Array.isArray(node.props.children) && node.props.children.includes('Invalid PAN-OS XML')))
    initial.resolve({})
    await harness.render(props)
    assert.deepEqual(documents.filter(Boolean), [])
  } finally { globalThis.setInterval = oldInterval; globalThis.clearInterval = oldClear }
})


test('guided mappings use named compact choices, keep evidence closed, and preserve draft saves', async () => {
  const harness = component('../src/features/migration/components/MigrationReviewQueues.tsx', 'MigrationReviewQueues', {
    '../reviewDrafts': drafts, '../../../components/common/tabKeyboard': { tabKeyboard() {} },
    '../reviewPresentation': presentation,
  })
  const port = { key: 'port', source_vdom: 'root', source_name: 'wan1', source_kind: 'interface', target_field: 'target_interface', mode: 'REQUIRED' }
  const zone = { ...port, key: 'zone', target_field: 'target_zone' }
  const group = { source_vdom: 'root', source_name: 'wan1', source_kind: 'interface', queue: 'CHOOSE_CANDIDATE', decision_keys: ['port', 'zone'], decisions: [port, zone], candidates: {
    port: [{ value: 'ethernet1/1' }, { value: 'ethernet1/2', available: false }, { value: 'ethernet1/3', contested: true }],
    zone: [{ value: 'WAN' }, { value: 'TRUST' }, { value: 'duplicate', target_scope: 'a' }, { value: 'duplicate', target_scope: 'b' }],
  }, source_evidence: {}, affected_count: 1, dependent_decision_count: 1 }
  let values = {}
  let saved = 0
  const props = { review: { decision_candidates: {}, rule_suggestions: [] }, selectedGroupKey: 'port', setSelectedGroupKey() {}, reviewGroups: [group], queueNames: ['CHOOSE_CANDIDATE'], activeQueue: 'CHOOSE_CANDIDATE', setActiveQueue() {}, search: '', setSearch() {}, vdomFilter: 'all', setVdomFilter() {}, vdoms: ['root'], visibleGroups: [group], setDecisionPage() {}, decisions: [port, zone], proposals: [{ decision_key: 'port', status: 'NEEDS_INPUT', dependencies: [] }, { decision_key: 'zone', status: 'NEEDS_INPUT', dependencies: ['port'] }], busy: false, run: async (action) => action(), updateGroup: async () => { saved++ }, setDrafts: (update) => { values = update(values) } }
  const render = async () => elements(await harness.render({ ...props, drafts: values }))
  let nodes = await render()
  const choice = (field) => nodes.find((node) => node.type === 'select' && node.props['aria-label'] === `${field} for root / wan1`)
  assert.ok(nodes.some((node) => node.type === 'option' && String(node.props.children).includes('WAN')))
  assert.ok(!nodes.some((node) => node.type === 'input' && node.props.type === 'radio'))
  assert.ok(!nodes.some((node) => node.type === 'button' && String(node.props.children).includes('Resolve prerequisite')))
  assert.ok(nodes.some((node) => node.type === 'p' && String(node.props.children).includes('below before completing')))
  assert.ok(nodes.filter((node) => node.type === 'details').every((node) => !node.props.open))
  for (const value of ['ethernet1/2', 'ethernet1/3', 'duplicate']) assert.ok(nodes.filter((node) => node.type === 'option' && node.props.value === value).every((node) => node.props.disabled))
  assert.equal(nodes.find((node) => node.type === 'button' && node.props.children === 'Review staged changes').props.disabled, false)
  assert.ok(!nodes.some((node) => node.type === 'button' && node.props.children === 'Save draft'))
  assert.equal(saved, 0, 'Editing stays local until validation')
  choice('target_interface').props.onChange({ target: { value: 'ethernet1/1' } })
  nodes = await render()
  choice('target_zone').props.onChange({ target: { value: 'WAN' } })
  nodes = await render()
  assert.deepEqual(values, { port: 'ethernet1/1', zone: 'WAN' })
  assert.ok(nodes.some((node) => node.type === 'p' && node.props.children === 'Staged change — needs validation.'))
  assert.equal(nodes.find((node) => node.type === 'button' && node.props.children === 'Review staged changes').props.disabled, false)
  choice('target_zone').props.onChange({ target: { value: '__custom__' } })
  nodes = await render()
  const custom = nodes.find((node) => node.type === 'input' && node.props['aria-label'] === 'Custom target_zone for root / wan1')
  assert.ok(custom)
  custom.props.onChange({ target: { value: 'new-zone' } })
  nodes = await render()
  await nodes.find((node) => node.type === 'button' && node.props.children === 'Review staged changes').props.onClick()
  assert.deepEqual(values, { port: 'ethernet1/1', zone: 'new-zone' })
  assert.equal(saved, 1)
  nodes = elements(await harness.render({ ...props, drafts: values, proposals: [
    { decision_key: 'port', proposed_value: 'ethernet1/1', status: 'READY', dependencies: [] },
    { decision_key: 'zone', proposed_value: 'new-zone', status: 'READY', dependencies: ['port'] },
  ] }))
  assert.equal(nodes.filter((node) => node.type === 'p' && node.props.children === 'Validated proposal — awaiting approval.').length, 2)
})

test('approved selection closes its preview and does not remain ready; failed approval preserves it', async () => {
  const harness = component('../src/features/migration/components/MigrationDesignReview.tsx', 'MigrationDesignReview', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const row = { group_key: 'item:address', item_key: 'address', source_vdom: 'root', source_kind: 'address', source_name: 'host',
    family: 'address', status: 'READY', operation: 'CREATE', target_scope: 'vsys1', target_name: 'host', dependencies: [], blocking_reasons: [] }
  const props = { draft: { decisions: [], configuration: [row], findings: [] }, approvedItems: [], busy: false,
    onApprove: () => { throw new Error('approval failed') } }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review all ready changes (').props.onClick()
  tree = await harness.render(props)
  assert.throws(() => elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Approve selection and generate commands').props.onClick(), /approval failed/)
  tree = await harness.render(props)
  assert.ok(elements(tree).some((node) => node.props['aria-label'] === 'Approval preview'))
  tree = await harness.render({ ...props, approvedItems: ['address'] })
  assert.ok(!elements(tree).some((node) => node.props['aria-label'] === 'Approval preview'))
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review all ready changes (').props.disabled, true)
})

test('review list keeps cross-page selections and reviews all ready items across filters', async () => {
  const harness = component('../src/features/migration/components/MigrationDesignReview.tsx', 'MigrationDesignReview', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const mapping = { decision_key: 'vsys', item_key: 'vsys', source_vdom: 'root', source_kind: 'vdom', source_name: 'root', target_field: 'vsys',
    status: 'READY', proposed_value: 'vsys1', dependencies: [], blocking_reasons: [] }
  const configuration = Array.from({ length: 27 }, (_, index) => ({ group_key: `host-${index}`, item_key: `host-${index}`, source_vdom: 'root', source_kind: 'address',
    source_name: `host-${index}`, target_name: `host-${index}`, target_scope: 'vsys1', family: 'address', operation: 'CREATE', status: 'READY', dependencies: ['vsys'], blocking_reasons: [] }))
  const props = { draft: { decisions: [mapping], configuration, findings: [] }, approvedItems: [], busy: false, onApprove: () => assert.fail('Review must not approve') }
  const articles = (tree) => elements(tree).filter((node) => node.props.className === 'migration-proposal-row')
  const button = (tree, label) => elements(tree).find((node) => node.props.children === label)
  let tree = await harness.render(props)
  assert.equal(articles(tree).length, 25)
  assert.equal(elements(tree).filter((node) => node.type === 'Button' && node.props.children?.[0] === 'Review selected (').length, 0)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Configuration status'), undefined)
  assert.ok(elements(tree).some((node) => node.props.children === 'Configuration by type'))
  assert.equal(elements(tree).filter((node) => node.type === 'table').length, 1)
  elements(articles(tree)[0]).find((node) => node.type === 'input').props.onChange({ target: { checked: true } })
  button(tree, 'Next').props.onClick()
  tree = await harness.render(props)
  assert.equal(articles(tree).length, 2)
  elements(articles(tree)[0]).find((node) => node.type === 'input').props.onChange({ target: { checked: true } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review selected (').props.onClick()
  tree = await harness.render(props)
  assert.equal(articles(tree).length, 0)
  assert.equal(elements(tree).filter((node) => node.type === 'select').length, 0)
  const preview = elements(tree).find((node) => node.props['aria-label'] === 'Approval preview')
  assert.deepEqual(elements(preview).find((node) => node.props.items).props.items, ['host-0', 'host-25', 'vsys'])
  button(tree, 'Back').props.onClick()
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'input' && node.props.placeholder === 'Source or target name').props.onChange({ target: { value: 'host-26' } })
  tree = await harness.render(props)
  assert.equal(articles(tree).length, 1)
  assert.ok(JSON.stringify(tree).includes('selected across all pages and filters'))
  elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review matching changes (').props.onClick()
  tree = await harness.render(props)
  assert.deepEqual(elements(tree).find((node) => node.props.items).props.items, ['host-26', 'vsys'])
  button(tree, 'Back').props.onClick()
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review all ready changes (').props.onClick()
  tree = await harness.render(props)
  const allPreview = elements(tree).find((node) => node.props['aria-label'] === 'Approval preview')
  assert.equal(elements(allPreview).find((node) => node.props.items).props.items.length, 28)
})

test('migration summary counts ready, blocked, excluded and approved configuration separately', async () => {
  const harness = component('../src/features/migration/components/MigrationDesignReview.tsx', 'MigrationDesignSummary', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const configuration = [
    { group_key: 'ready', item_key: 'ready', source_vdom: 'root', source_kind: 'address', source_name: 'ready', status: 'READY', dependencies: [], blocking_reasons: [] },
    { group_key: 'blocked', item_key: 'blocked', source_vdom: 'root', source_kind: 'address', source_name: 'blocked', status: 'NEEDS_INPUT', dependencies: [], blocking_reasons: [] },
    { group_key: 'manual', item_key: 'manual', source_vdom: 'root', source_kind: 'address', source_name: 'manual', status: 'UNSUPPORTED', dependencies: [], blocking_reasons: [] },
    { group_key: 'excluded', item_key: 'excluded', source_vdom: 'root', source_kind: 'interface', source_name: 'excluded', status: 'READY', dependencies: [], blocking_reasons: [] },
    { group_key: 'approved', item_key: 'approved', source_vdom: 'root', source_kind: 'address', source_name: 'approved', status: 'READY', dependencies: [], blocking_reasons: [] },
  ]
  const tree = await harness.render({ draft: { decisions: [], configuration, context: { conversion_settings: { excluded_interfaces: ['root/excluded'] } }, findings: [], destination_verified: false }, approvedItems: ['approved'] })
  assert.ok(JSON.stringify(tree).includes('Ready'))
  assert.ok(JSON.stringify(tree).includes('Blocked'))
  assert.ok(JSON.stringify(tree).includes('Excluded'))
  assert.ok(JSON.stringify(tree).includes('Approved'))
  assert.ok(JSON.stringify(tree).includes('explicitly excluded interfaces'))
  const counts = elements(tree).filter((node) => node.type === 'span').map((node) => [node.props.children].flat().join(''))
  assert.deepEqual(counts, ['Ready 1', 'Blocked 1', 'Manual / unsupported 1', 'Excluded by you 1', 'Approved 1'])
})

test('change browsing supports page sizes, page jumps, type filters and shrinking results', async () => {
  const harness = component('../src/features/migration/components/MigrationDesignReview.tsx', 'MigrationDesignReview', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const configuration = Array.from({ length: 126 }, (_, index) => ({ group_key: `item-${index}`, source_vdom: 'root', source_kind: 'address',
    source_name: `host-${index}`, family: index === 125 ? 'service' : 'address', status: 'READY', dependencies: [], blocking_reasons: [] }))
  const props = { draft: { decisions: [], configuration, findings: [] }, approvedItems: [], busy: false, onApprove: () => assert.fail('Browsing cannot approve') }
  const articles = (tree) => elements(tree).filter((node) => node.props.className === 'migration-proposal-row')
  let tree = await harness.render(props)
  assert.equal(articles(tree).length, 25)
  for (const size of [50, 100]) {
    elements(tree).find((node) => node.props['aria-label'] === 'Changes per page').props.onChange({ target: { value: String(size) } })
    tree = await harness.render(props)
    assert.equal(articles(tree).length, size)
    assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Changes page').props.value, 1)
  }
  elements(tree).find((node) => node.props['aria-label'] === 'Changes page').props.onChange({ target: { value: '999' } })
  tree = await harness.render(props)
  assert.equal(articles(tree).length, 26)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Changes page').props.value, 2)
  tree = await harness.render({ ...props, draft: { ...props.draft, configuration: configuration.slice(0, 1) } })
  assert.equal(articles(tree).length, 1)
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Changes page').props.value, 1)
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'button' && node.props.children === 'service').props.onClick()
  tree = await harness.render(props)
  assert.equal(articles(tree).length, 1)
  assert.equal(articles(tree)[0].key, 'item-125')
})

test('blocked changes link only existing scoped input tasks and keep manual reasons visible', async () => {
  const harness = component('../src/features/migration/components/MigrationDesignReview.tsx', 'MigrationDesignReview', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const row = { group_key: 'root-policy', source_vdom: 'root', source_kind: 'policy', source_name: 'policy', family: 'security_rule',
    status: 'NEEDS_INPUT', dependencies: ['root-port'], blocking_reasons: ['Missing placement'] }
  const issue = { id: 'direct', source_vdom: 'root', source_name: 'policy', explanation: 'Choose target', affected_keys: ['root-policy'], action: { kind: 'EDIT_SETTINGS' } }
  const issues = [issue,
    { ...issue, id: 'prerequisite', source_name: 'port1', affected_keys: [], action: { kind: 'EDIT_MAPPING', decision_key: 'root-port' } },
    { ...issue, id: 'other-vdom', source_vdom: 'branch', affected_keys: ['branch-policy'] },
    { ...issue, id: 'manual', action: null }]
  const routes = []
  const props = { draft: { decisions: [], configuration: [row], findings: [], issues }, approvedItems: [], busy: false,
    onApprove: () => assert.fail('Blocked items cannot approve'), onSelectIssue: (id) => routes.push(id), onResolveInputs: () => routes.push('inputs') }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Resolve required inputs (').props.onClick()
  elements(tree).find((node) => node.type === 'select' && node.props.value === 'READY').props.onChange({ target: { value: 'all' } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'button' && node.props.children === 'Details').props.onClick()
  tree = await harness.render(props)
  const links = elements(tree).filter((node) => node.type === 'Button' && node.props.children?.[0] === 'Open required input: ')
  assert.equal(links.length, 2)
  links.forEach((link) => link.props.onClick())
  assert.deepEqual(routes, ['inputs', 'direct', 'prerequisite'])
  tree = await harness.render({ ...props, draft: { ...props.draft,
    decisions: [{ decision_key: 'root-port', status: 'NEEDS_INPUT', dependencies: ['root-vsys', 'root-policy'] }],
    issues: [...issues, { ...issue, id: 'ancestor', affected_keys: ['root-vsys'] }],
  } })
  assert.equal(elements(tree).filter((node) => node.type === 'Button' && node.props.children?.[0] === 'Open required input: ').length, 3,
    'Transitive and missing prerequisites remain linked even with a dependency cycle')
  tree = await harness.render({ ...props, draft: { ...props.draft, issues: [issues[3]] } })
  assert.ok(JSON.stringify(tree).includes('Missing placement'))
  assert.equal(elements(tree).filter((node) => node.type === 'Button' && node.props.children?.[0] === 'Open required input: ').length, 0)
  tree = await harness.render({ ...props, draft: { ...props.draft, configuration: [{ ...row, status: 'READY' }] } })
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.id === 'review-ready').props.disabled, true)
  assert.equal(elements(tree).find((node) => node.type === 'article').props.children[0].props.children[0].props.disabled, true, 'A missing prerequisite cannot seed approval')
})

test('issue workspace paginates task groups and resets filters on context changes', async () => {
  const harness = component('../src/features/migration/components/MigrationIssueWorkspace.tsx', 'MigrationIssueWorkspace', {
    '../reviewPresentation': presentation,
  })
  const issues = Array.from({ length: 12 }, (_, index) => ({ id: `issue-${index}`, code: 'VPN_PARAMETERS_REQUIRED', category: 'CHOICE',
    source_vdom: index < 6 ? 'root' : 'branch', source_kind: 'ipsec_phase1', source_name: `vpn-${index}`, explanation: `Need values ${index}`,
    resolution_kind: 'CONVERSION_SETTINGS', affected_keys: [`key-${index}`], affected_sources: [], prerequisite_keys: [], explanations: [],
    action: { kind: 'EDIT_SETTINGS', section: 'vpn', finding_code: 'VPN_PARAMETERS_REQUIRED', member_keys: [] } }))
  let selectedId = ''
  const props = { issues, configurationKeys: new Set(issues.flatMap((issue) => issue.affected_keys)), tab: 'decisions', contextKey: 'source-1', selectedId: '', onSelect: (id) => { selectedId = id }, onRoute: () => {}, renderAction: () => 'editor' }
  let tree = await harness.render(props)
  const cards = (tree) => elements(tree).filter((node) => node.props.className === 'migration-issue-task')
  assert.equal(cards(tree).length, 10)
  assert.equal([elements(tree).find((node) => node.type === 'span' && String(node.props.children).startsWith('Page'))?.props.children].flat().join(''), 'Page 1 of 2')
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next').props.onClick()
  tree = await harness.render(props)
  assert.equal(cards(tree).length, 2)
  assert.equal(elements(tree).find((node) => node.type === 'article').props.children[1].props.children[2], 'vpn-10')
  const search = elements(tree).find((node) => node.props['aria-label'] === 'Search tasks')
  search.props.onChange({ target: { value: 'vpn-11' } })
  tree = await harness.render(props)
  assert.equal(cards(tree).length, 1)
  tree = await harness.render({ ...props, contextKey: 'source-2' })
  assert.equal(elements(tree).find((node) => node.props['aria-label'] === 'Search tasks').props.value, '')
  assert.equal(cards(tree).length, 10)
  tree = await harness.render({ ...props, contextKey: 'source-2', selectedId: 'issue-11' })
  assert.equal(cards(tree).length, 2, 'A linked issue opens its own page')
  assert.equal(cards(tree)[1].props['aria-current'], 'true')
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Previous').props.onClick()
  assert.equal(selectedId, '', 'Paging clears an off-page selection')
  tree = await harness.render({ ...props, contextKey: 'source-2', selectedId })
  assert.equal(cards(tree).length, 10)
  assert.equal(cards(tree)[0].props['aria-current'], 'true')
})

test('manual workspace groups matching reasons and keeps filtered findings and evidence reachable', async () => {
  const harness = component('../src/features/migration/components/MigrationIssueWorkspace.tsx', 'MigrationIssueWorkspace', {
    '../reviewPresentation': presentation,
  })
  const issues = Array.from({ length: 35 }, (_, index) => ({ id: `manual-${index}`, code: 'MIGRATION_REVIEW', category: 'MANUAL',
    source_vdom: 'root', source_kind: 'vpn', source_name: `site-${index}`, explanation: 'Separate target VPN design required.',
    resolution_kind: 'MANUAL_IMPLEMENTATION', affected_keys: [`config-${index}`, 'shared'],
    affected_sources: [{ source_vdom: 'root', source_kind: 'vpn', source_name: `site-${index}` }],
    prerequisite_keys: [], explanations: [`Evidence for site-${index}`], action: null }))
  const props = { issues, configurationKeys: new Set([...issues.flatMap((issue) => issue.affected_keys)]), tab: 'manual', contextKey: 'source',
    selectedId: 'manual-34', onSelect: () => {}, onRoute: () => assert.fail('Manual work cannot execute an action') }
  let tree = await harness.render(props)
  assert.equal(elements(tree).filter((node) => node.props.className === 'migration-issue-task').length, 1)
  const members = elements(tree).find((node) => node.type.name === 'IssueMembers')
  assert.deepEqual(members.props.issues, issues, 'All members, including those after the first page, reach the detail view')
  assert.equal(elements(tree).filter((node) => node.type === 'input').length, 1, 'Only the search input is editable')
  assert.ok(JSON.stringify(tree).includes('Reading these findings does not resolve them'))
  elements(tree).find((node) => node.props['aria-label'] === 'Search tasks').props.onChange({ target: { value: 'site-34' } })
  tree = await harness.render(props)
  assert.deepEqual(elements(tree).find((node) => node.type.name === 'IssueMembers').props.issues, [issues[34]])
  elements(tree).find((node) => node.props['aria-label'] === 'Search tasks').props.onChange({ target: { value: 'missing' } })
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.type === 'article'), undefined)
  assert.ok(JSON.stringify(tree).includes('No tasks match these filters.'))
})

test('issue workspace routes source review and navigates prerequisites across pages', async () => {
  const harness = component('../src/features/migration/components/MigrationIssueWorkspace.tsx', 'MigrationIssueWorkspace', {
    '../reviewPresentation': presentation,
  })
  const issues = Array.from({ length: 12 }, (_, index) => ({ id: `choice-${index}`, code: 'MAPPING_CHOICE', category: 'CHOICE',
    source_vdom: 'root', source_kind: 'interface', source_name: `port-${index}`, explanation: 'Choose interface',
    resolution_kind: 'MAPPING', affected_keys: [], affected_sources: [], prerequisite_keys: [], explanations: [],
    action: { kind: 'EDIT_MAPPING', decision_key: `key-${index}` } }))
  issues[11] = { ...issues[11], prerequisite_keys: ['key-0', 'missing-key'], action: { kind: 'REVIEW_SOURCE' } }
  let selectedId = 'choice-11'
  const routes = []
  const props = { issues, configurationKeys: new Set(), tab: 'decisions', contextKey: 'source', selectedId,
    onSelect: (id) => { selectedId = id }, onRoute: (issue) => routes.push(issue.id) }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review source').props.onClick()
  assert.deepEqual(routes, ['choice-11'])
  assert.ok(JSON.stringify(tree).includes('Related placement requires review in Target setup.'))
  const prerequisite = elements(tree).find((node) => node.type === 'Button' && node.props.className === 'text-button')
  prerequisite.props.onClick()
  tree = await harness.render({ ...props, selectedId })
  assert.equal(selectedId, 'choice-0')
  assert.equal(elements(tree).find((node) => node.props.className === 'migration-issue-task').props['aria-current'], 'true')
  tree = await harness.render({ ...props, issues: issues.slice(0, 1), selectedId: 'choice-11' })
  assert.ok(JSON.stringify(tree).includes('port-0'), 'A resolved or removed selection falls back to a current task')
})

test('approval preview expands prerequisites, shows exact scopes, and leaves manual work excluded', async () => {
  const calls = []
  const harness = component('../src/features/migration/components/MigrationDesignReview.tsx', 'MigrationDesignReview', {
    '../reviewDrafts': drafts, '../reviewPresentation': presentation,
  })
  const mapping = { decision_key: 'port', source_vdom: 'root', source_name: 'port1', source_kind: 'interface', target_field: 'target_interface', proposed_value: 'ethernet1/1', target_scope: 'vsys1', operation: 'CONFIGURE', status: 'READY', dependencies: [], blocking_reasons: [] }
  const config = { group_key: 'vlan', source_vdom: 'root', source_name: 'vlan10', source_kind: 'interface', family: 'interface', target_name: 'ethernet1/1.10', target_scope: 'vsys1', operation: 'CREATE', status: 'READY', dependencies: ['port'], blocking_reasons: [], configuration: { vlan_tag: 10 } }
  const manual = { ...config, group_key: 'vpn', status: 'UNSUPPORTED', operation: null, family: 'VPN' }
  const another = { ...config, group_key: 'other', source_name: 'vlan20' }
  const props = { draft: { decisions: [mapping], configuration: [config, another, manual], findings: [] }, approvedItems: [], busy: false, onApprove: (keys) => calls.push(keys) }
  let tree = await harness.render(props)
  const bulk = elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review all ready changes (')
  bulk.props.onClick()
  tree = await harness.render(props)
  let bulkPreview = elements(tree).find((node) => node.props['aria-label'] === 'Approval preview')
  assert.deepEqual(elements(bulkPreview).find((node) => node.props.items).props.items, ['vlan', 'other', 'port'])
  assert.equal(calls.length, 0, 'Bulk selection must not approve automatically')
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Back').props.onClick()
  tree = await harness.render(props)
  assert.equal(elements(tree).find((node) => node.type === 'select' && node.props.value === 'READY').props.value, 'READY')
  const configInput = elements(tree).find((node) => node.type === 'article' && node.key === 'vlan')
  elements(configInput).find((node) => node.type === 'input').props.onChange({ target: { checked: true } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children?.[0] === 'Review selected (').props.onClick()
  tree = await harness.render(props)
  const preview = elements(tree).find((node) => node.props['aria-label'] === 'Approval preview')
  const list = elements(preview).find((node) => node.props.items)
  assert.deepEqual(list.props.items, ['vlan', 'port'])
  assert.ok(JSON.stringify(list.props.render('vlan')).includes('vsys1'))
  assert.ok(JSON.stringify(list.props.render('vlan')).includes('vlan tag: 10'))
  elements(preview).find((node) => node.type === 'Button' && node.props.children === 'Approve selection and generate commands').props.onClick()
  assert.deepEqual(calls, [['vlan', 'port']])
  assert.deepEqual(drafts.draftDependencies([mapping, config], ['vlan'], ['port']), ['vlan'])
  tree = await harness.render({ ...props, draft: { ...props.draft, decisions: [{ ...mapping, status: 'NEEDS_INPUT' }] } })
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Approve selection and generate commands').props.disabled, true)
})

test('SRX approval preview expands dependencies and atomic groups before signed approval', async () => {
  const calls = []
  const items = [
    { key: 'address', family: 'address', source_vdom: 'root', source_name: 'web', target_name: 'web', settings: { prefix: '192.0.2.1/32' }, dependencies: [], decision_keys: [], blockers: [], guidance: [], render_disposition: 'CREATE' },
    { key: 'policy', family: 'policy', source_vdom: 'root', source_name: 'allow-web', target_name: 'allow-web', settings: { action: 'permit' }, dependencies: ['address'], decision_keys: [], blockers: [], guidance: [], approval_group: 'traffic', render_disposition: 'CREATE' },
    { key: 'schedule', family: 'schedule', source_vdom: 'root', source_name: 'work-hours', target_name: 'work-hours', settings: { timezone: 'Asia/Kuala_Lumpur' }, dependencies: [], decision_keys: [], blockers: [], guidance: [], approval_group: 'traffic', render_disposition: 'CREATE' },
  ]
  const requirements = [{ key: 'scope', source_vdom: null, source_kind: 'source', source_name: 'FortiGate', target_field: 'source_vdom', label: 'FortiGate VDOM', value: null, choices: ['root'] }]
  const report = { plan_status: 'READY_FOR_REVIEW', items, findings: [], deployment_available: false, destination_verified: false }
  const draft = { envelope_type: 'draft', digest: 'draft-1' }
  const artifact = { artifact_id: 'artifact-1', envelope_type: 'fortigate_to_juniper_srx_artifact_v1', command_text: 'set system host-name srx\n', command_count: 1, command_sha256: 'sha', expires_at: 9999999999, report: { ...report, verification: 'Offline only' } }
  const source = { vendor: 'fortigate', source_text: 'config system global\nend\n' }
  const harness = component('../src/features/migration/fortigateToJuniperSrx/MigrationWorkflow.tsx', 'JuniperSRXMigrationWorkflow', {
    '../../../storage/workspaceStore': { workspace: () => ({}), saveWorkspace: async () => {} },
    '../migrationApi': { downloadFile: () => {} },
    './migrationApi': {
      requirements: async () => ({ requirements, report }),
      prepare: async () => ({ draft, requirements, report }),
      approve: async (_source, _options, _draft, selected) => { calls.push(selected); return { approval: { signature: 'signed' } } },
      build: async () => ({ artifact }),
      commandPreview: async () => ({ text: artifact.command_text, command_sha256: artifact.command_sha256 }),
      exportDecisions: async () => ({ document: {} }),
      importDecisions: async () => ({ options: {} }),
      download: async () => new Blob(),
    },
  })
  const props = { source, sourceKey: 'source-1', stage: 'place', onStageChange: () => {} }
  let tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare migration review').props.onClick()
  tree = await harness.render({ ...props, stage: 'review' })
  elements(tree).find((node) => node.props['aria-label'] === 'Select root allow-web').props.onChange({ target: { checked: true } })
  tree = await harness.render({ ...props, stage: 'review' })
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review selected changes').props.onClick()
  tree = await harness.render({ ...props, stage: 'review' })
  assert.ok(JSON.stringify(tree).includes('Approve these exact changes'))
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Approve these changes and build export').props.onClick()
  tree = await harness.render({ ...props, stage: 'export' })
  assert.deepEqual(calls, [['address', 'policy', 'schedule']])
  assert.equal(elements(tree).find((node) => node.type === 'textarea' && node.props['aria-label'] === 'Juniper SRX command preview').props.value, artifact.command_text)
})

test('a failed SRX revalidation keeps staged target choices for correction', async () => {
  const requirements = [{ key: 'scope', source_vdom: null, source_kind: 'source', source_name: 'FortiGate', target_field: 'source_vdom', label: 'FortiGate VDOM', value: null, choices: ['root'] }]
  const report = { plan_status: 'BLOCKED', items: [], findings: [], deployment_available: false, destination_verified: false }
  const harness = component('../src/features/migration/fortigateToJuniperSrx/MigrationWorkflow.tsx', 'JuniperSRXMigrationWorkflow', {
    '../../../storage/workspaceStore': { workspace: () => ({}), saveWorkspace: async () => {} },
    '../migrationApi': { downloadFile: () => {} },
    './migrationApi': {
      requirements: async () => ({ requirements, report }),
      prepare: async () => { throw new Error('A target mapping is incomplete') },
    },
  })
  const props = { source: { vendor: 'fortigate', source_text: 'config system global\nend\n' }, sourceKey: 'source-2', stage: 'place', onStageChange: () => {} }
  let tree = await harness.render(props)
  const scope = elements(tree).find((node) => node.type === 'select' && elements(node).some((child) => child.type === 'option' && child.props.children === 'root'))
  scope.props.onChange({ target: { value: 'root' } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare migration review').props.onClick()
  tree = await harness.render(props)
  const retainedScope = elements(tree).find((node) => node.type === 'select' && elements(node).some((child) => child.type === 'option' && child.props.children === 'root'))
  assert.equal(retainedScope.props.value, 'root')
})

test('ASA approval preview expands dependencies and previews the signed export bytes', async () => {
  const approvals = []
  const downloads = []
  const items = [
    { key: 'address', family: 'address', source_vdom: 'root', source_name: 'clients', target_name: 'clients', settings: { subnet: '10.0.0.0/24' }, dependencies: [], blockers: [], render_disposition: 'CREATE' },
    { key: 'policy', family: 'policy', source_vdom: 'root', source_name: 'allow-https', target_name: 'allow-https', settings: { action: 'permit' }, dependencies: ['address'], blockers: [], render_disposition: 'CREATE' },
  ]
  const requirements = [
    { key: 'scope', source_vdom: null, source_kind: 'source', source_name: 'FortiGate', target_field: 'source_vdom', label: 'FortiGate VDOM', value: null, choices: ['root'] },
    { key: 'context', source_vdom: null, source_kind: 'target', source_name: 'Cisco ASA', target_field: 'target_context', label: 'ASA context', value: null, choices: ['single'] },
    { key: 'version', source_vdom: null, source_kind: 'target', source_name: 'Cisco ASA', target_field: 'target_version', label: 'Cisco ASA syntax baseline', value: null, choices: ['9.20'] },
    { key: 'mode', source_vdom: null, source_kind: 'target', source_name: 'Cisco ASA', target_field: 'target_mode', label: 'ASA firewall mode', value: null, choices: ['routed'] },
    { key: 'inside', source_vdom: 'root', source_kind: 'interface', source_name: 'inside', target_field: 'asa_interface', label: 'ASA interface, nameif, and security level', value: null, choices: [] },
  ]
  const report = { plan_status: 'READY_FOR_REVIEW', items, findings: [], deployment_available: false, destination_verified: false }
  const draft = { envelope_type: 'draft', digest: 'draft-asa' }
  const artifact = { artifact_id: 'asa-1', envelope_type: 'fortigate_to_cisco_asa_artifact_v1', command_text: 'access-list inside_access extended permit tcp object clients object web eq 443\n', command_count: 1, command_sha256: 'asa-sha', expires_at: 9999999999, report }
  const source = { vendor: 'fortigate', source_text: 'config system global\nend\n' }
  const harness = component('../src/features/migration/fortigateToCiscoAsa/MigrationWorkflow.tsx', 'CiscoAsaMigrationWorkflow', {
    '../../../storage/workspaceStore': { workspace: () => ({}), saveWorkspace: async () => {} },
    '../migrationApi': { downloadFile: (_blob, name) => downloads.push(name) },
    './migrationApi': {
      requirements: async () => ({ requirements, report }),
      prepare: async (_source, options) => { approvals.push(['prepare', options]); return { draft, requirements, report } },
      approve: async (_source, _options, _draft, selected) => { approvals.push(['approve', selected]); return { approval: { signature: 'signed' } } },
      build: async () => ({ artifact }),
      commandPreview: async () => ({ text: artifact.command_text, command_sha256: artifact.command_sha256 }),
      exportDecisions: async () => ({ document: {} }),
      importDecisions: async () => ({ options: {} }),
      download: async (_source, passedArtifact, kind) => { approvals.push(['download', passedArtifact, kind]); return new Blob([artifact.command_text]) },
    },
  })
  let stage = 'place'
  const props = { source, sourceKey: 'asa-source', stage, onStageChange: (value) => { stage = value } }
  const setField = async (label, value, elementType) => {
    const tree = await harness.render({ ...props, stage })
    const fieldLabel = elements(tree).find((node) => node.type === 'label' && JSON.stringify(node.props.children).includes(label))
    const field = elements(fieldLabel).find((node) => node.type === elementType)
    field.props.onChange({ target: { value } })
  }
  let tree = await harness.render(props)
  await setField('FortiGate VDOM', 'root', 'select')
  await setField('ASA context', 'single', 'select')
  await setField('Cisco ASA syntax baseline', '9.20', 'select')
  await setField('ASA firewall mode', 'routed', 'select')
  await setField('ASA interface', 'GigabitEthernet0/1', 'input')
  await setField('ASA nameif', 'inside', 'input')
  await setField('ASA security level', '100', 'input')
  tree = await harness.render({ ...props, stage })
  const prepareButton = elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare migration review')
  assert.ok(prepareButton, `ASA stage ${stage} did not expose review preparation: ${JSON.stringify(tree).slice(0, 1800)}`)
  prepareButton.props.onClick()
  await harness.render({ ...props, stage })
  tree = await harness.render({ ...props, stage: 'review' })
  assert.equal(approvals[0][1].interfaces.root.inside.security_level, 100)
  assert.equal(stage, 'review')
  assert.ok(JSON.stringify(tree).includes('allow-https'), `ASA review did not render: ${JSON.stringify(tree).slice(0, 2400)}`)
  elements(tree).find((node) => node.props['aria-label'] === 'Select root allow-https').props.onChange({ target: { checked: true } })
  tree = await harness.render({ ...props, stage })
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Review selected changes').props.onClick()
  tree = await harness.render({ ...props, stage })
  assert.ok(JSON.stringify(tree).includes('address'))
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Approve these changes and build export').props.onClick()
  await harness.render({ ...props, stage })
  tree = await harness.render({ ...props, stage: 'export' })
  assert.deepEqual(approvals.find(([kind]) => kind === 'approve')[1], ['address', 'policy'])
  assert.equal(elements(tree).find((node) => node.type === 'textarea' && node.props['aria-label'] === 'Cisco ASA command preview').props.value, artifact.command_text)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Download ASA configuration').props.onClick()
  await harness.render({ ...props, stage })
  assert.deepEqual(downloads, ['asa_config.cfg'])
  assert.equal(approvals.find(([kind]) => kind === 'download')[1], artifact)
})

test('a failed ASA review preserves target choices for correction', async () => {
  const requirements = [{ key: 'scope', source_vdom: null, source_kind: 'source', source_name: 'FortiGate', target_field: 'source_vdom', label: 'FortiGate VDOM', value: null, choices: ['root'] }]
  const harness = component('../src/features/migration/fortigateToCiscoAsa/MigrationWorkflow.tsx', 'CiscoAsaMigrationWorkflow', {
    '../../../storage/workspaceStore': { workspace: () => ({}), saveWorkspace: async () => {} },
    '../migrationApi': { downloadFile: () => {} },
    './migrationApi': {
      requirements: async () => ({ requirements, report: { items: [], findings: [] } }),
      prepare: async () => { throw new Error('A target mapping is incomplete') },
    },
  })
  const props = { source: { vendor: 'fortigate', source_text: 'config system global\nend\n' }, sourceKey: 'asa-source-2', stage: 'place', onStageChange: () => {} }
  let tree = await harness.render(props)
  const scope = elements(tree).find((node) => node.type === 'select' && elements(node).some((child) => child.type === 'option' && child.props.children === 'root'))
  scope.props.onChange({ target: { value: 'root' } })
  tree = await harness.render(props)
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare migration review').props.onClick()
  tree = await harness.render(props)
  const retainedScope = elements(tree).find((node) => node.type === 'select' && elements(node).some((child) => child.type === 'option' && child.props.children === 'root'))
  assert.equal(retainedScope.props.value, 'root')
})

test('migration pair discovery reads the server registered workflow list', async () => {
  const compiled = ts.transpileModule(readFileSync(new URL('../src/features/migration/pairApi.ts', import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS },
  }).outputText
  const exports = {}
  new Function('require', 'exports', compiled)((key) => {
    assert.equal(key, '../../api/client')
    return { apiFetch: async (path) => {
      assert.equal(path, '/api/migration/pairs')
      return { ok: true, json: async () => ({ pairs: [{ pair_id: 'fortigate_to_juniper_srx', export_available: true }] }) }
    } }
  }, exports)
  assert.deepEqual(await exports.loadMigrationPairs(), [{ pair_id: 'fortigate_to_juniper_srx', export_available: true }])
})

test('source coverage paginates repeated scoped records and clamps after replacement', async () => {
  const harness = component('../src/features/migration/components/MigrationCoverage.tsx', 'MigrationCoverage', {})
  const coverage = {
    source_record_count: 26, inventory_available: true, status_counts: { MANUAL: 26 },
    records: Array.from({ length: 26 }, (_, index) => ({ source_scope: 'vdom', source_vdom: 'root',
      source_path: 'firewall address', source_name: `host-${index}`, status: 'MANUAL' })),
  }
  let tree = await harness.render({ coverage })
  assert.equal(elements(tree).filter((node) => node.type === 'tr').length, 26)
  assert.ok(!JSON.stringify(tree).includes('host-25'))
  elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next coverage page').props.onClick()
  tree = await harness.render({ coverage })
  assert.ok(JSON.stringify(tree).includes('host-25'))
  assert.equal(elements(tree).filter((node) => node.type === 'tr').length, 2)
  tree = await harness.render({ coverage: { ...coverage, records: coverage.records.slice(0, 1), source_record_count: 1 } })
  assert.ok(JSON.stringify(tree).includes('host-0'))
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Next coverage page').props.disabled, true)
  assert.equal(await harness.render({}), null)
})

test('Check Point VDOM choices survive review preparation and workspace restoration', async () => {
  for (const restored of [false, true]) {
    let saved = restored ? {
      pairId: 'fortigate_to_checkpoint', sourceKey: 'cp-source',
      options: { source_vdom: 'root', management_target: '', management_domain: '', management_api_version: '1.8.1',
        gaia_target: '', policy_package: '', access_layer: '', install_on: [], insertion_anchor: '', insertion_relation: '', target_cleanup_action: '' },
      requirements: [], review: null, approval: null, artifact: null, preview: null,
    } : undefined
    let stage = 'place'
    const report = { items: [], findings: [], plan_status: 'BLOCKED' }
    const harness = component('../src/features/migration/fortigateToCheckPoint/MigrationWorkflow.tsx', 'CheckPointMigrationWorkflow', {
      '../../../storage/workspaceStore': {
        workspace: () => ({ newPairMigration: saved }),
        saveWorkspace: async (value) => { saved = value.newPairMigration },
      },
      './migrationApi': {
        requirements: async (_source, options) => {
          assert.equal(options.source_vdom, '')
          return { requirements: [{ key: 'checkpoint:source_vdom', choices: ['root', 'branch'] }], report }
        },
        prepare: async () => ({ draft: { digest: 'current' }, requirements: [], report }),
      },
    })
    const props = { source: { vendor: 'fortigate', source_text: 'config vdom\nend\n' }, sourceKey: 'cp-source', onStageChange: (value) => { stage = value } }
    const render = () => harness.render({ ...props, stage })
    const selector = (tree) => elements(tree).find((node) => node.type === 'select' && elements(node).some((child) => child.type === 'option' && child.props.value === 'branch'))
    let tree = await render()
    assert.ok(selector(tree))
    selector(tree).props.onChange({ target: { value: 'root' } })
    tree = await render()
    elements(tree).find((node) => node.type === 'button' && node.props.children === 'Prepare review').props.onClick()
    await render()
    tree = await render()
    assert.equal(stage, 'review')
    assert.deepEqual(saved.requirements, [])
    assert.equal(selector(tree).props.value, 'root')
    selector(tree).props.onChange({ target: { value: 'branch' } })
    await render()
    assert.equal(saved.options.source_vdom, 'branch')
    assert.equal(saved.review, null)
    assert.equal(saved.approval, null)
    assert.equal(saved.artifact, null)
  }
})
