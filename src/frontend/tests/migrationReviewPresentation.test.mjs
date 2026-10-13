import test from 'node:test'
import assert from 'node:assert/strict'
import {
  buildBulkPreview,
  reviewQueueNames,
  reviewSuggestions,
  reviewVdoms,
  visibleReviewDecisions,
  visibleReviewGroups,
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
