import test from 'node:test'
import assert from 'node:assert/strict'
import { harness, nodes } from './offlineWorkflowHarness.mjs'

const button = (tree, text) => {
  const found = nodes(tree).find((node) => node.type === 'button' && node.props.children === text)
  assert.ok(found, text)
  return found
}
const rows = [
  { key: 'object', family: 'address', source_name: 'clients', settings: { management_operation: { path: '/web_api/add-network' } }, dependencies: [], render_disposition: 'CREATE' },
  { key: 'first', family: 'policy', source_name: 'deny', settings: { position: { above: 'cleanup-uid' } }, dependencies: ['object'], render_disposition: 'CREATE' },
  { key: 'last', family: 'policy', source_name: 'allow', settings: { uid: { $response_binding: 'first' } }, dependencies: ['first'], render_disposition: 'CREATE' },
]
const make = (opts = {}) => harness('fortigateToCheckPoint', { items: rows, ...opts })

async function selectLast(h) {
  let tree = await h.render()
  nodes(tree).find((n) => n.props?.['aria-label'] === 'Select all ready changes').props.onChange({ target: { checked: false } })
  tree = await h.render()
  nodes(tree).find((n) => n.props?.['aria-label'] === 'Select root allow').props.onChange({ target: { checked: true } })
  return h.render()
}

test('preview expands prior rules and UID dependencies; retry uses the same signed approval', async () => {
  const h = make()
  let tree = await selectLast(h)
  const preview = nodes(tree).find((n) => n.props?.['aria-label'] === 'Check Point approval preview')
  for (const value of ['Added prerequisite', '/web_api/add-network', 'cleanup-uid', '$response_binding']) assert.ok(JSON.stringify(preview).includes(value), value)
  assert.equal(h.calls.approvals.length, 0)
  button(tree, 'Approve and generate').props.onClick(); tree = await h.render()
  const approval = h.state().approval
  assert.deepEqual(h.calls.approvals[0], ['first', 'last', 'object'])
  button(tree, 'Retry with current approval').props.onClick(); await h.render()
  assert.equal(h.state().approval, approval)
  assert.equal(h.calls.approvals.length, 1)
  assert.equal(h.calls.builds.length, 2)
})

test('cancel and option edits invalidate preview without creating approval', async () => {
  const h = make()
  let tree = await h.render()
  button(tree, 'Cancel approval preview').props.onClick(); tree = await h.render()
  assert.ok(!nodes(tree).some((n) => n.props?.['aria-label'] === 'Check Point approval preview'))
  const input = nodes(tree).find((n) => n.type === 'input' && n.props.value === 'package')
  input.props.onChange({ target: { value: 'changed' } }); await h.render()
  assert.equal(h.state().options.policy_package, 'changed')
  assert.equal(h.state().approval, null)
  assert.equal(h.calls.approvals.length, 0)
})

test('blocked dependencies prevent confirmation without hiding independent evidence', async () => {
  const h = make({ items: rows.map((row) => row.key === 'object' ? { ...row, render_disposition: 'BLOCK' } : row) })
  const tree = await selectLast(h)
  assert.ok(!nodes(tree).some((n) => n.type === 'button' && n.props.children === 'Approve and generate'))
  assert.equal(h.calls.approvals.length, 0)
})

test('destination edits clear the expanded approval and old artifacts', async () => {
  const h = make({ setup: true })
  let tree = await h.render()
  // Existing-target setup exposes the optional snapshot control.
  const mode = nodes(tree).find((n) => n.type === 'select' && n.props.value === 'new')
  mode.props.onChange({ target: { value: 'existing' } }); tree = await h.render()
  const snapshot = nodes(tree).find((n) => n.type === 'DestinationSnapshot')
  snapshot.props.onChange({ source: { vendor: 'checkpoint', source_text: '{}' } }); await h.render()
  assert.equal(h.state().approval, null)
  assert.equal(h.state().artifact, null)
})

test('new target reviews automatically without a snapshot or engineer approval', async () => {
  let prepared = 0
  const h = make({ api: { prepare: async (...args) => { prepared++; assert.equal(args[2], undefined); return h.review } } })
  const tree = await h.render()
  assert.ok(prepared >= 1)
  assert.ok(nodes(tree).some((n) => n.props?.['aria-label'] === 'Check Point approval preview'))
  assert.equal(h.calls.approvals.length, 0)
  assert.equal(h.state().options.target_mode, 'new')
})

test('technical findings preserve every affected source record across bounded pages', async () => {
  const h = make()
  h.review.report.findings = Array.from({ length: 61 }, (_, i) => ({ code: 'UNSUPPORTED', source_name: `source-${i}` }))
  let tree = await h.render()
  const texts = []
  for (let page = 0; page < 3; page++) {
    texts.push(JSON.stringify(tree))
    if (page < 2) { button(tree, 'Next findings').props.onClick(); tree = await h.render() }
  }
  for (let i = 0; i < 61; i++) assert.ok(texts.some((text) => text.includes(`source-${i}`)))
})

test('approval pages preserve every exact setting in the signed selection', async () => {
  const items = Array.from({ length: 61 }, (_, i) => ({ key: `object-${i}`, family: 'address', dependencies: [], render_disposition: 'CREATE', settings: { exact: `setting-${i}` } }))
  const h = make({ items })
  let tree = await h.render()
  const previews = []
  for (let page = 0; page < 3; page++) {
    previews.push(JSON.stringify(nodes(tree).find((n) => n.props?.['aria-label'] === 'Check Point approval preview')))
    if (page < 2) { button(tree, 'Next approval details').props.onClick(); tree = await h.render() }
  }
  for (let i = 0; i < 61; i++) assert.ok(previews.some((text) => text.includes(`setting-${i}`)))
  button(tree, 'Approve and generate').props.onClick(); await h.render()
  assert.deepEqual(h.calls.approvals[0], items.map((row) => row.key).sort())
})

test('blocker codes stay inside collapsed details with disabled selection', async () => {
  const h = make({ items: [{ key: 'blocked', dependencies: [], render_disposition: 'BLOCK', blockers: ['EXPLICIT_SOURCE_REQUIRED'] }] })
  const tree = await h.render()
  assert.ok(nodes(tree).some((n) => n.type === 'details' && JSON.stringify(n.props.children).includes('EXPLICIT_SOURCE_REQUIRED')))
  assert.equal(nodes(tree).find((n) => n.props?.['aria-label'] === 'Select root blocked').props.disabled, true)
})
