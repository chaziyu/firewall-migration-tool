import test from 'node:test'
import assert from 'node:assert/strict'
import { groupEffectiveValues, groupReviewIssues, isReady, orderPlacementRequirements } from '../src/features/migration/paloAltoToFortigate/reviewPresentation.ts'

const item = (key, extra = {}) => ({ key, family: 'address', source_scope: 'vsys:one', source_name: key,
  dependencies: [], blocking_reasons: [], render_disposition: 'CREATE', ...extra })

test('issue groups retain distinct scope and impact without repeating global blockers', () => {
  const global = 'Source needs correction'
  const configuration = [item('a', { blocking_reasons: [global, 'Choose target'] }), item('b', { blocking_reasons: [global, 'Choose target'] }),
    item('c', { source_scope: 'vsys:two', blocking_reasons: ['Choose target'] })]
  const issues = configuration.flatMap((row) => row.blocking_reasons.map((explanation) => ({ id: row.key + explanation, item_key: row.key,
    category: 'CHOICE', source_scope: row.source_scope, source_name: row.source_name, explanation })))
  const review = { draft: { findings: [global], configuration }, issues }
  const before = structuredClone(review)
  const groups = groupReviewIssues(review)
  assert.equal(groups.length, 2)
  assert.deepEqual(groups[0].affected.map((row) => row.key), ['a', 'b'])
  assert.equal(groups[1].source_scope, 'vsys:two')
  assert.deepEqual(review, before)
})

test('dependency noise becomes one prerequisite group while preserving exact reasons and all affected items', () => {
  const configuration = Array.from({ length: 60 }, (_, i) => item(`child-${i}`, { dependencies: [`parent-${i}`], blocking_reasons: [`Blocked dependency: parent-${i}`] }))
  const groups = groupReviewIssues({ draft: { findings: [], configuration }, issues: [] })
  assert.equal(groups.length, 1)
  assert.equal(groups[0].category, 'PREREQUISITE')
  assert.equal(groups[0].affected.length, 60)
  assert.equal(groups[0].reasons.length, 60)
})

test('legacy missing issue links and unfamiliar categories keep every blocker visible', () => {
  const configuration = [item('a', { blocking_reasons: ['Unknown constraint', 'Another blocker'] }), item('manual', { family: 'manual', blocking_reasons: ['Separate implementation'] })]
  const groups = groupReviewIssues({ draft: { findings: [], configuration }, issues: [
    { id: 'old', source_scope: 'vsys:one', source_name: 'a', category: 'NEW_CATEGORY', explanation: 'Unknown constraint' },
  ] })
  assert.deepEqual(groups.map((group) => group.category), ['NEW_CATEGORY', 'UNCLASSIFIED', 'MANUAL'])
  assert.equal(groups.filter((group) => group.explanation === 'Unknown constraint').length, 1)
  assert.equal(isReady(configuration[0]), false)
  assert.equal(isReady(item('blocked', { render_disposition: 'BLOCK' })), false)
  assert.equal(isReady(item('reuse', { render_disposition: 'REUSE' })), true)
})

test('interface placement follows planner parent order without mutating requirements', () => {
  const rows = [{ key: 'interfaces:ethernet1/1.201' }, { key: 'interfaces:ethernet1/1' }, { key: 'interfaces:ethernet1/10' }]
  const before = structuredClone(rows)
  const configuration = [item('parent', { family: 'interface', source_name: 'ethernet1/1' }), item('vlan', { family: 'interface', source_name: 'ethernet1/1.201' })]
  assert.deepEqual(orderPlacementRequirements(rows, configuration).map((row) => row.key), ['interfaces:ethernet1/1', 'interfaces:ethernet1/1.201', 'interfaces:ethernet1/10'])
  assert.deepEqual(rows, before)
})

test('effective-value summaries preserve provenance and values beyond the former limit', () => {
  const values = Array.from({ length: 139 }, (_, i) => ({ identity: ['vsys:one', 'policy', `policy-${i}`], field: 'log_end', value: 'yes', version: '11.0', reference: 'https://example.test/reference', origin: 'DOCUMENTED' }))
  values.push({ ...values[0], version: '11.1' }, { ...values[0], reference: 'https://example.test/other' })
  const before = structuredClone(values)
  const groups = groupEffectiveValues(values)
  assert.deepEqual(groups.map((row) => row.count), [139, 1, 1])
  assert.equal(groups.reduce((sum, row) => sum + row.count, 0), values.length)
  assert.deepEqual(values, before)
})
