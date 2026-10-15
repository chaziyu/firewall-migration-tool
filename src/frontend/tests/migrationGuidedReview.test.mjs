import test from 'node:test'
import assert from 'node:assert/strict'
import { draftReviewRows, draftStatusCounts, groupPlanBlockers, planFamilySummary, taskCategory } from '../src/features/migration/reviewPresentation.ts'
import { orderInterfaceMappings } from '../src/features/migration/reviewDrafts.ts'

test('actionable view hides parent-dependent noise while full and manual views preserve evidence', () => {
  const rows = [{ decision_key: 'parent', source_vdom: 'root', source_name: 'port1', source_kind: 'interface', status: 'NEEDS_INPUT' },
    { group_key: 'rule', source_vdom: 'root', source_name: 'allow', family: 'security_rule', status: 'NEEDS_INPUT' },
    { group_key: 'vpn', source_vdom: 'root', source_name: 'vpn', family: 'VPN', status: 'UNSUPPORTED' },
    { group_key: 'object', source_vdom: 'root', source_name: 'address', family: 'address', status: 'READY' }]
  const grouped = new Set(['rule'])
  assert.deepEqual(draftReviewRows(rows, 'ACTIONABLE', 'all', '', grouped).map((row) => row.source_name), ['port1'])
  assert.equal(draftReviewRows(rows, 'all', 'all', '', grouped).length, 4)
  assert.equal(draftReviewRows(rows, 'UNSUPPORTED', 'VPN', 'vpn', grouped).length, 1)
  assert.deepEqual(draftStatusCounts(rows), { NEEDS_INPUT: 2, UNSUPPORTED: 1, READY: 1 })
})

test('parent allocations sort ahead of blocked children without mutating rows', () => {
  const rows = ['child', 'small', 'parent'].map((key, index) => ({ decision: { key, source_vdom: 'root', source_name: key, affected_count: [500, 1, 20][index] } }))
  const proposals = [{ decision_key: 'parent', status: 'NEEDS_INPUT', dependencies: [] }, { decision_key: 'child', status: 'NEEDS_INPUT', dependencies: ['parent'] }]
  const result = orderInterfaceMappings(rows, { parent: { source_type: 'physical' }, small: { source_type: 'physical' }, child: { source_parent: 'parent', source_type: 'vlan' } }, proposals)
  assert.deepEqual(result.map((row) => row.decision.key), ['parent', 'small', 'child'])
  assert.deepEqual(rows.map((row) => row.decision.key), ['child', 'small', 'parent'])
})

test('family export counts and root-cause groups retain excluded identities and VDOMs', () => {
  assert.deepEqual(planFamilySummary([{ source_object_type: 'service', render_disposition: 'CREATE' }, { source_object_type: 'policy', render_disposition: 'BLOCK' }]),
    { service: { included: 1, blocked: 0 }, policy: { included: 0, blocked: 1 } })
  const reasons = ['one', 'two'].map((source_name) => ({ source_vdom: 'root', source_name, code: 'missing', decision_key: 'parent' }))
  const groups = groupPlanBlockers([...reasons, { ...reasons[0], source_vdom: 'blue' }])
  assert.equal(groups.length, 2)
  assert.deepEqual(groups[0].affected.map((row) => row.source_name), ['one', 'two'])
  assert.equal(groups[0].count, 2)
  assert.deepEqual(groups[0].decision_keys, ['parent'])
})

test('task categories distinguish unresolved parents, scoped children, ready, approved and manual work', () => {
  const rows = [
    { decision_key: 'root-port', source_vdom: 'root', source_name: 'port1', status: 'NEEDS_INPUT', dependencies: [] },
    { decision_key: 'root-vlan', source_vdom: 'root', source_name: 'vlan10', status: 'NEEDS_INPUT', dependencies: ['root-port'] },
    { decision_key: 'blue-port', source_vdom: 'blue', source_name: 'port1', status: 'READY', dependencies: [] },
    { group_key: 'missing', status: 'NEEDS_INPUT', dependencies: ['absent'] },
    { group_key: 'ready', status: 'READY', dependencies: ['blue-port'] },
    { group_key: 'approved', item_key: 'signed-item', status: 'READY', dependencies: [] },
    { group_key: 'vpn', status: 'UNSUPPORTED', dependencies: ['root-port'] },
  ]
  const byKey = new Map(rows.map((row) => [row.decision_key || row.group_key, row]))
  const approved = new Set(['signed-item'])
  assert.deepEqual(rows.map((row) => taskCategory(row, byKey, approved)),
    ['Needs decision', 'Blocked', 'Ready for review', 'Blocked', 'Ready for review', 'Approved', 'Manual work'])
  assert.deepEqual(draftReviewRows(rows, 'READY', 'all', '', new Set(), approved), [rows[2], rows[4]])
  assert.deepEqual(draftReviewRows(rows, 'APPROVED', 'all', '', new Set(), approved), [rows[5]])
  assert.deepEqual(draftReviewRows(rows, 'BLOCKED', 'all', '', new Set(), approved), [rows[1], rows[3]])
  assert.equal(taskCategory({ ...rows[6], approved: false }, byKey, approved), 'Manual work')
})
