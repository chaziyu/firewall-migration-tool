import test from 'node:test'
import assert from 'node:assert/strict'
import {
  buildBulkPreview,
  reviewQueueNames,
  reviewSuggestions,
  reviewVdoms,
  visibleReviewDecisions,
  visibleReviewGroups,
  orderedCandidates,
  reviewSourceSummary,
  approvedDraftKeys,
} from '../src/features/migration/reviewPresentation.ts'

const decisions = [
  { key: 'zone', source_vdom: 'root', source_kind: 'zone', source_name: 'trust', target_field: 'target_zone',
    suggested_value: 'trust', mode: 'SUGGESTED', review_state: 'PENDING', evidence_source: 'TARGET' },
  { key: 'iface', source_vdom: 'branch', source_kind: 'interface', source_name: 'port1', target_field: 'target_interface',
    suggested_value: null, mode: 'REQUIRED', review_state: 'PENDING', evidence_source: 'SOURCE' },
  { key: 'route', source_vdom: 'root', source_kind: 'static_route', source_name: 'default', target_field: 'target_virtual_router',
    suggested_value: 'vr1', mode: 'SUGGESTED', review_state: 'CONFIRMED', evidence_source: 'DERIVED' },
  { key: 'unsupported', source_vdom: 'root', source_kind: 'zone', source_name: 'legacy', target_field: 'target_zone',
    suggested_value: 'legacy', mode: 'UNSUPPORTED', review_state: 'PENDING', evidence_source: null },
]

test('review presentation filters preserve queue, scope and decision filters', () => {
  const groups = [
    { queue: 'NEEDS_INPUT', source_vdom: 'root', source_kind: 'zone', source_name: 'trust' },
    { queue: 'NEEDS_INPUT', source_vdom: 'branch', source_kind: 'interface', source_name: 'port1' },
    { queue: 'COMPLETE', source_vdom: 'root', source_kind: 'zone', source_name: 'done' },
  ]
  assert.deepEqual(reviewQueueNames, ['NEEDS_INPUT', 'CHOOSE_CANDIDATE', 'READY_TO_CONFIRM', 'CONFLICT', 'COMPLETE'])
  assert.deepEqual(reviewVdoms(groups), ['branch', 'root'])
  assert.deepEqual(visibleReviewGroups(groups, 'NEEDS_INPUT', 'root', 'TRUST'), [groups[0]])
  assert.deepEqual(visibleReviewDecisions(decisions, 'zones', 'all', 'all', false).map((item) => item.key), ['zone', 'unsupported'])
  assert.deepEqual(visibleReviewDecisions(decisions, 'all', 'target', 'all', false).map((item) => item.key), ['zone'])
  assert.deepEqual(visibleReviewDecisions(decisions, 'route-nat', 'all', 'all', false).map((item) => item.key), ['route'])
  assert.deepEqual(visibleReviewDecisions(decisions, 'all', 'all', 'all', true).map((item) => item.key), ['zone', 'iface', 'unsupported'])
})

test('suggestions and bulk preview stay presentation-only and exclude unsupported rows', () => {
  assert.deepEqual(reviewSuggestions(decisions).map((item) => item.key), ['zone'])
  assert.deepEqual(buildBulkPreview(decisions, ['zone', 'iface', 'unsupported'], (item) =>
    item.key === 'iface' ? ' ethernet1/1 ' : item.suggested_value ?? ''), [
    { key: 'zone', scope: 'root · zone · trust · target_zone', value: 'trust' },
    { key: 'iface', scope: 'branch · interface · port1 · target_interface', value: 'ethernet1/1' },
  ])
})

test('candidate evidence sorts ahead of available choices without changing eligibility or input order', () => {
  const candidates = [{ value: 'unused' }, { value: 'occupied', class: 'STRONG', available: false },
    { value: 'possible', supporting_evidence: ['source IP match'] }, { value: 'strong', class: 'STRONG' },
    { value: 'contested', class: 'STRONG', contested: true }, { value: 'family', supporting_evidence: ['INTERFACE_FAMILY_MATCH'] }]
  const snapshot = structuredClone(candidates)
  assert.deepEqual(orderedCandidates(candidates).map((row) => row.value), ['strong', 'possible', 'unused', 'family', 'occupied', 'contested'])
  assert.deepEqual(candidates, snapshot)
})

test('ownership and zone tasks do not invent missing interface evidence', () => {
  assert.equal(reviewSourceSummary({ source_kind: 'vdom', source_evidence: {} }), 'Choose target VSYS and virtual-router ownership for this VDOM.')
  assert.equal(reviewSourceSummary({ source_kind: 'zone', source_name: 'trust', source_evidence: {} }), 'Source zone: trust. Review its explicit member evidence below.')
  assert.equal(reviewSourceSummary({ source_kind: 'interface', source_evidence: { source_vlan: 0, source_parent: 'port1' } }), 'Parent: port1 · VLAN: 0')
})

test('approved presentation requires signed design selection rather than saved or legacy confirmed mappings', () => {
  assert.deepEqual(approvedDraftKeys({ decisions: [{ key: 'legacy', review_state: 'CONFIRMED' }] }), [])
  assert.deepEqual(approvedDraftKeys({ design_approval: { configuration: { item: {} }, decisions: {
    mapping: { review_state: 'CONFIRMED', approved_operation: 'CREATE' },
    suggested: { review_state: 'PENDING', approved_operation: null },
    legacy: { review_state: 'CONFIRMED', approved_operation: null },
  } } }), ['item', 'mapping'])
})
