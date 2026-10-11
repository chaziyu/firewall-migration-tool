import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as drafts from '../src/features/migration/reviewDrafts.ts'
import * as presentation from '../src/features/migration/reviewPresentation.ts'

// Exercise component handlers and effects with the same hook harness used by validationReport tests.
function component(file, name, modules) {
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
      hooks.useMemo(() => { effects.push(callback) }, dependencies)
    },
  }
  const compiled = ts.transpileModule(readFileSync(new URL(file, import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText
  const exports = {}
  const requireModule = (key) => {
    if (key === 'react') return hooks
    if (key === 'react/jsx-runtime') return jsxRuntime
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
      let tree
      for (let attempt = 0; attempt < 20; attempt++) {
        pending = false
        cursor = 0
        tree = exports[name](props)
        const currentEffects = effects
        effects = []
        currentEffects.forEach((effect) => effect())
        await new Promise((resolve) => setImmediate(resolve))
        if (!pending) return tree
      }
      assert.fail('Component did not settle')
    },
  }
}

function elements(tree) {
  if (Array.isArray(tree)) return tree.flatMap(elements)
  if (!tree || typeof tree !== 'object') return []
  return [tree, ...elements(tree.props?.children)]
}

const workspace = { workspace: () => ({ referenceRole: 'TEMPLATE', targetSource: null,
  targetDevice: '', deterministicDraft: null, artifact: null }), saveWorkspace: async () => {} }
const api = { RequestError: class extends Error {} }

function workflowHarness(migrationApi) {
  return component('../src/features/migration/MigrationWorkflow.tsx', 'MigrationWorkflow', {
    '../../storage/workspaceStore': workspace, '../../api/client': api,
    '../../components/common/ErrorBanner': { ErrorBanner: 'Error' }, '../../components/common/Button': { Button: 'Button' },
    './PlanReview': { PlanReview: 'PlanReview' }, './migrationApi': migrationApi,
  })
}

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
  tree = await harness.render({ ...props, activeSection: 'live' })
  for (const label of ['Prepare Candidate', 'Revalidate Candidate', 'Commit']) {
    assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === label).props.disabled, true)
  }
})

test('stale approval offers reapproval and candidate drift revokes commit', async () => {
  const artifact = { artifact_id: 'artifact', plan_status: 'READY', artifact: { commands: ['set address x'], command_count: 1 } }
  const stale = workflowHarness({ buildPlan: async () => { throw new Error('Approved design is stale') } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'plan', onReviewDecision: () => {} }
  let tree = await stale.render(props)
  assert.ok(elements(tree).some((node) => node.type === 'Button' && node.props.children === 'Review and approve design'))
  assert.ok(elements(tree).some((node) => node.type === 'Error' && node.props.message.includes('stale')))
  const live = workflowHarness({ buildPlan: async () => artifact,
    deployArtifact: async () => ({ deployment_session_id: 'session', candidate_validated: true, result: { validation: { status: 'SUCCESS' } } }),
    validateCandidate: async () => { throw new Error('Candidate changed after validation; prepare the candidate again') },
    commitCandidate: async () => assert.fail('Drifted candidate must not commit'),
  })
  const liveProps = { ...props, activeSection: 'live' }
  tree = await live.render(liveProps)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Prepare Candidate').props.onClick()
  tree = await live.render(liveProps)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.disabled, false)
  await elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Revalidate Candidate').props.onClick()
  tree = await live.render(liveProps)
  assert.equal(elements(tree).find((node) => node.type === 'Button' && node.props.children === 'Commit').props.disabled, true)
  assert.ok(elements(tree).some((node) => node.type === 'Error' && node.props.message.includes('Candidate changed')))
  assert.ok(elements(tree).some((node) => node.props?.role === 'status' && node.props.children.includes('Prepare the candidate again')))
})

test('expired deployment approval revokes the artifact and offers reapproval', async () => {
  const artifact = { artifact_id: 'artifact', plan_status: 'READY', artifact: { commands: ['set address x'], command_count: 1 } }
  const error = new api.RequestError('Design approval has expired')
  error.details = { error_code: 'artifact_ineligible' }
  const harness = workflowHarness({ buildPlan: async () => artifact, deployArtifact: async () => { throw error } })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'live', onReviewDecision: () => {} }
  let tree = await harness.render(props)
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
    draft: { digest: 'draft', context: { overrides: {} }, decisions: [{ decision_key: 'port', proposed_value: null }] } }
  const harness = component('../src/features/migration/MigrationReview.tsx', 'MigrationReview', {
    '../../storage/workspaceStore': workspace,
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
  const artifact = { artifact_id: 'artifact', plan_status: 'READY', artifact: { commands: ['set address x'], command_count: 1 } }
  const harness = component('../src/features/migration/MigrationWorkflow.tsx', 'MigrationWorkflow', {
    '../../storage/workspaceStore': workspace, '../../api/client': api,
    '../../components/common/ErrorBanner': { ErrorBanner: 'Error' }, '../../components/common/Button': { Button: 'Button' },
    './PlanReview': { PlanReview: 'PlanReview' },
    './migrationApi': { buildPlan: async () => artifact, deployArtifact: async () => {
      prepares++
      return { deployment_session_id: 'session', candidate_validated: true,
        result: { commands_succeeded: 1, validation: { status: 'SUCCESS' } } }
    } },
  })
  const props = { preview: { vendor: 'fortigate', source_digest: 'source', source_evidence: {} },
    decisionDocument: { draft_required: true, design_approval: {} }, targetSource: null, targetDevice: '', activeSection: 'live' }
  let tree = await harness.render(props)
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
