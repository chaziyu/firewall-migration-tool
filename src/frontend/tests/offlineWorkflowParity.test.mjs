import test from 'node:test'
import assert from 'node:assert/strict'
import { harness, nodes, pairs } from './offlineWorkflowHarness.mjs'

const button = (tree, label) => {
  const result = nodes(tree).find((node) => node.type === 'button' && node.props.children === label)
  assert.ok(result, label)
  return result
}

for (const folder of Object.keys(pairs)) {
  test(`${folder}: defaults show exact eligible selection, exclusions survive approval, retry keeps signed approval`, async () => {
    const h = harness(folder)
    let tree = await h.render()
    assert.equal(h.calls.approvals.length, 0)
    assert.equal(h.calls.builds.length, 0)
    const confirm = button(tree, 'Approve and generate')
    assert.equal(confirm.props.disabled, false)
    const exclude = nodes(tree).find((node) => node.type === 'input' && node.props['aria-label']?.endsWith(' independent'))
    assert.ok(exclude)
    exclude.props.onChange({ target: { checked: false } })
    tree = await h.render()
    button(tree, 'Approve and generate').props.onClick()
    tree = await h.render()
    assert.deepEqual([...h.calls.approvals[0]].sort(), ['object', 'policy'])
    const signed = h.state().approval
    assert.ok(signed)
    const retry = nodes(tree).find((node) => node.type === 'button' && String(node.props.children).startsWith('Retry'))
    assert.ok(retry)
    retry.props.onClick(); await h.render()
    assert.equal(h.calls.approvals.length, 1)
    assert.equal(h.calls.builds.length, 2)
    assert.equal(h.state().approval, signed)
  })

  test(`${folder}: no eligible rows never creates an approval`, async () => {
    const h = harness(folder, { items: [{ key: 'blocked', family: 'address', dependencies: [], render_disposition: 'BLOCK', blockers: ['UNSUPPORTED'] }] })
    const tree = await h.render()
    assert.ok(!nodes(tree).some((node) => node.type === 'button' && node.props.children === 'Approve and generate'))
    assert.equal(h.calls.approvals.length, 0)
  })

  for (const pending of ['approval', 'build']) test(`${folder}: context edits discard a stale ${pending} response`, async () => {
    let finish
    const signed = { signature: 'signed', selected_items: ['object', 'policy', 'independent'] }
    const h = harness(folder, { api: pending === 'approval'
      ? { approve: () => new Promise((resolve) => { finish = resolve }) }
      : { approve: async () => ({ approval: signed }), build: () => new Promise((resolve) => { finish = resolve }) } })
    h.options.target_mode = folder.includes('CheckPoint') || folder.includes('CiscoFtd') ? 'existing' : h.options.target_mode
    let tree = await h.render()
    button(tree, 'Approve and generate').props.onClick(); await h.render()
    h.stage('place'); tree = await h.render()
    const snapshot = nodes(tree).find((node) => node.type === 'DestinationSnapshot')
    if (snapshot) snapshot.props.onChange({ source: { vendor: 'target', source_text: 'changed' }, metadata: {} })
    else {
      const vdom = nodes(tree).find((node) => node.type === 'input' && node.props.value === 'root')
      assert.ok(vdom)
      vdom.props.onChange({ target: { value: 'branch' } })
    }
    await h.render()
    assert.ok(finish)
    finish(pending === 'approval' ? { approval: signed } : { artifact: { artifact_id: 'stale' } })
    await h.render()
    assert.equal(h.state().approval, null)
    assert.equal(h.state().artifact, null)
  })
}

test('FTD counts unresolved parameters rather than seven populated fields', async () => {
  const h = harness('paloAltoToCiscoFtd')
  h.review.requirements = ['source_scope', 'target_mode', 'domain_id', 'domain_name', 'policy_name', 'manager_target', 'fmc_api_version']
    .map((key) => ({ key, value: h.options[key], choices: [] }))
  const tree = await h.render()
  const inputTab = nodes(tree).find((node) => node.props?.id === 'panos-ftd-tab-decisions')
  assert.equal(nodes(inputTab).find((node) => node.type === 'span').props.children, 0)
})

test('normalized proposals revoke restored authority before exposing the new review', async () => {
  let resolveCurrent
  let requests = 0
  const h = harness('paloAltoToJuniperSrx', { api: { prepare: async (_source, options) => {
    if (++requests === 1) return { ...h.review, options: { ...options, zones: { proposed: 'proposed' } } }
    return new Promise((resolve) => { resolveCurrent = resolve })
  } } })
  // The saved workspace holds authority for the previous options.
  h.state().approval = { signature: 'old' }
  h.state().artifact = { artifact_id: 'old' }
  let tree = await h.render()
  assert.equal(h.state().approval, null)
  assert.equal(h.state().artifact, null)
  assert.ok(!nodes(tree).some((node) => node.type === 'button' && node.props.children === 'Approve and generate'))
  resolveCurrent({ ...h.review, options: h.state().options })
  tree = await h.render()
  assert.equal(button(tree, 'Approve and generate').props.disabled, false)
})

for (const reuseOnly of [false, true]) test(`PAN-OS SRX generated status reflects ${reuseOnly ? 'reuse only' : 'excluded selection'}`, async () => {
  const rows = reuseOnly ? [{ key: 'object', family: 'address', dependencies: [], render_disposition: 'REUSE' }] : undefined
  const h = harness('paloAltoToJuniperSrx', { items: rows, api: { build: async () => ({ artifact: {
    artifact_id: 'current', command_text: reuseOnly ? '' : 'set security address-book global address object 192.0.2.1/32\n',
    command_count: reuseOnly ? 0 : 1, command_sha256: 'hash', report: { ...h.review.report,
      items: h.review.report.items.map((row) => row.key === 'independent' ? { ...row, render_disposition: 'NOT_APPROVED' } : row) },
  } }) } })
  let tree = await h.render()
  if (!reuseOnly) {
    nodes(tree).find((node) => node.props?.['aria-label'] === 'Select vsys:one independent').props.onChange({ target: { checked: false } })
    tree = await h.render()
  }
  button(tree, 'Approve and generate').props.onClick(); tree = await h.render()
  assert.ok(nodes(tree).some((node) => node.type === 'h3' && node.props.children === (reuseOnly ? 'No changes needed' : 'Partial export')))
})
