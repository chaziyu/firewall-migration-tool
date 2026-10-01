import test from 'node:test'
import assert from 'node:assert/strict'
import { candidateLabel, confirmationEvidenceType, decisionLabel, interfaceMappingRows, reconcileReviewDrafts, draftDependencies, portExceptionGroups } from '../src/features/migration/reviewDrafts.ts'

test('one unresolved parent groups dependent VLAN and route exceptions without blocking unrelated objects', () => {
  const rows = [
    { decision_key: 'scope', status: 'READY', dependencies: [], approved: true },
    { decision_key: 'port', target_field: 'target_interface', status: 'NEEDS_INPUT', dependencies: ['scope'] },
    { decision_key: 'vlan', target_field: 'target_interface', status: 'NEEDS_INPUT', dependencies: ['port'] },
    { group_key: 'route', status: 'NEEDS_INPUT', dependencies: ['vlan', 'scope'] },
    { group_key: 'address', status: 'READY', dependencies: ['scope'] },
  ]
  const original = structuredClone(rows)
  assert.deepEqual([...portExceptionGroups(rows).keys()], ['port'])
  assert.deepEqual(portExceptionGroups(rows).get('port').map((row) => row.decision_key || row.group_key), ['vlan', 'route'])
  assert.deepEqual(draftDependencies(rows, ['route']), ['route', 'vlan', 'port'])
  assert.deepEqual(draftDependencies(rows, ['address']), ['address'])
  assert.deepEqual(rows, original)
})

test('single usable interface candidate prefills only a pending draft', () => {
  const decision = { key: 'root:port1', source_kind: 'interface', target_field: 'target_interface', value: null, suggested_value: null, mode: 'REQUIRED', review_state: 'PENDING' }
  for (const classification of ['STRONG', 'POSSIBLE']) {
    const candidates = { [decision.key]: [{ value: 'ethernet1/1', class: classification, available: true, contested: false }] }
    const original = structuredClone(decision)
    const drafts = reconcileReviewDrafts({}, [], [decision], false, candidates)
    assert.equal(drafts[decision.key], 'ethernet1/1')
    assert.equal(interfaceMappingRows([decision], drafts, candidates)[0].ready, classification === 'STRONG')
    assert.deepEqual(decision, original)
  }
})

test('ambiguous, unavailable and contested interface candidates stay blank', () => {
  const decision = { key: 'port1', source_kind: 'interface', target_field: 'target_interface', value: null, suggested_value: null }
  for (const options of [
    [],
    [{ value: 'ethernet1/1' }, { value: 'ethernet1/2' }],
    [{ value: 'ethernet1/1', available: false }],
    [{ value: 'ethernet1/1', contested: true }],
    [{ value: 'ethernet1/1', target_scope: 'vsys1' }, { value: 'ethernet1/1', target_scope: 'vsys2', available: false }],
  ]) {
    assert.equal(reconcileReviewDrafts({}, [], [decision], false, { port1: options }).port1, '')
  }
})

test('candidate prefill respects values, engineer edits and target context changes', () => {
  const decision = { key: 'port1', source_kind: 'interface', target_field: 'target_interface', value: null, suggested_value: null, review_state: 'PENDING' }
  const candidates = { port1: [{ value: 'ethernet1/1' }] }
  assert.equal(reconcileReviewDrafts({}, [], [{ ...decision, suggested_value: 'ethernet1/2' }], false, candidates).port1, 'ethernet1/2')
  const confirmed = { ...decision, value: 'ethernet1/3', suggested_value: 'ethernet1/2', review_state: 'CONFIRMED' }
  assert.equal(reconcileReviewDrafts({ port1: 'edited' }, [decision], [confirmed], false, candidates).port1, 'ethernet1/3')
  const drafts = reconcileReviewDrafts({}, [], [decision], false, candidates)
  drafts.port1 = 'engineer edit'
  const changedCandidates = { port1: [{ value: 'ethernet1/4' }] }
  assert.equal(reconcileReviewDrafts(drafts, [decision], [decision], false, changedCandidates).port1, 'engineer edit')
  assert.equal(reconcileReviewDrafts(drafts, [decision], [decision], true, changedCandidates).port1, 'ethernet1/4')
  assert.equal(reconcileReviewDrafts(drafts, [decision], [decision], true, { port1: [] }).port1, '')
})

test('candidate prefill is limited to interface target_interface decisions', () => {
  for (const fields of [{ source_kind: 'zone', target_field: 'target_interface' }, { source_kind: 'interface', target_field: 'target_zone' }]) {
    const decision = { key: 'other', value: null, suggested_value: null, ...fields }
    assert.equal(reconcileReviewDrafts({}, [], [decision], false, { other: [{ value: 'ethernet1/1' }] }).other, '')
  }
})

test('review refresh preserves unrelated edits but resets changed decisions and target context', () => {
  const previous = [{ key: 'root:port1', value: null, suggested_value: 'ethernet1/1' }, { key: 'other:port1', value: null }]
  const drafts = { 'root:port1': 'ethernet1/2', 'other:port1': 'ethernet1/3', removed: 'old' }
  const next = [{ ...previous[0], value: 'ethernet1/2', review_state: 'CONFIRMED' }, previous[1]]
  assert.deepEqual(reconcileReviewDrafts(drafts, previous, next, false), { 'root:port1': 'ethernet1/2', 'other:port1': 'ethernet1/3' })
  assert.deepEqual(reconcileReviewDrafts(drafts, previous, next, true), { 'root:port1': 'ethernet1/2', 'other:port1': '' })
  assert.equal(reconcileReviewDrafts(drafts, previous, [{ ...previous[0], suggested_value: 'ethernet1/4' }], false)['root:port1'], 'ethernet1/4')
})

test('interface selection excludes draft collisions, reserved and competing suggestions', () => {
  const decisions = ['root', 'branch'].map((vdom) => ({ key: vdom, source_vdom: vdom, source_name: 'port1', source_kind: 'interface', target_field: 'target_interface', suggested_value: `ethernet1/${vdom === 'root' ? 1 : 2}`, mode: 'SUGGESTED', review_state: 'PENDING' }))
  const candidates = { root: [{ value: 'ethernet1/1', class: 'STRONG' }], branch: [{ value: 'ethernet1/2', class: 'STRONG' }] }
  assert.ok(interfaceMappingRows(decisions, {}, candidates).every((row) => row.ready))
  assert.ok(interfaceMappingRows(decisions, { branch: 'ethernet1/1' }, candidates).every((row) => row.conflict && !row.ready))
  candidates.branch[0].available = false
  candidates.branch[0].assigned_to = [{ source_vdom: 'root', source_name: 'port2' }]
  assert.equal(interfaceMappingRows(decisions, {}, candidates)[1].ready, false)
  assert.equal(candidateLabel(candidates.branch[0]), 'Already assigned to root / port2')
  candidates.root[0].contested = true
  assert.equal(interfaceMappingRows(decisions, {}, candidates)[0].ready, false)
  assert.equal(candidateLabel({ value: 'ethernet1/4', supporting_evidence: ['INTERFACE_FAMILY_MATCH', 'physical interface family'] }), 'Available interface')
})

test('prefill preserves engineer edits across impact refreshes and resets stale evidence', () => {
  const decision = { key: 'lan', value: null, suggested_value: 'trust', mode: 'SUGGESTED', review_state: 'PENDING', evidence_source: 'TARGET', evidence_type: 'TARGET_ZONE_ASSIGNMENT' }
  assert.deepEqual(reconcileReviewDrafts({}, [], [decision], false), { lan: 'trust' })
  const refreshed = { ...decision, affected_count: 10, reason: 'Updated impact' }
  assert.deepEqual(reconcileReviewDrafts({ lan: 'edited' }, [decision], [refreshed], false), { lan: 'edited' })
  assert.deepEqual(reconcileReviewDrafts({ lan: 'edited' }, [decision], [refreshed], true), { lan: 'trust' })
  assert.deepEqual(reconcileReviewDrafts({ lan: 'edited' }, [decision], [{ ...refreshed, value: 'confirmed', review_state: 'CONFIRMED' }], false), { lan: 'confirmed' })
})

test('suggestion acceptance records provenance and edits remain manual', () => {
  for (const source of ['TARGET', 'DERIVED', 'SOURCE']) {
    const decision = { suggested_value: 'trust', evidence_source: source }
    assert.equal(confirmationEvidenceType(decision, 'trust'), `ENGINEER_${source}_SUGGESTION`)
    assert.equal(confirmationEvidenceType(decision, 'custom'), 'MANUAL')
  }
  assert.equal(confirmationEvidenceType({ suggested_value: null }, 'trust'), 'MANUAL')
})

test('review labels distinguish pending suggestions, candidates and confirmation', () => {
  const decision = { suggested_value: 'trust', evidence_source: 'DERIVED', review_state: 'PENDING' }
  assert.equal(decisionLabel(decision), 'Derived suggestion')
  assert.equal(decisionLabel({ ...decision, evidence_source: 'TARGET', evidence_type: 'REVIEW_DERIVED_SUGGESTION' }), 'Derived suggestion')
  assert.equal(decisionLabel({ ...decision, evidence_source: 'SOURCE' }), 'Suggested')
  assert.equal(decisionLabel({ ...decision, review_state: 'CONFIRMED' }), 'Confirmed')
  assert.equal(decisionLabel(decision, [], true), 'Conflict')
  assert.equal(decisionLabel({ ...decision, suggested_value: null }, [{ value: 'trust' }]), 'Candidate available')
  assert.equal(decisionLabel({ ...decision, suggested_value: null }, [{ value: 'trust', available: false }]), 'Needs input')
})
