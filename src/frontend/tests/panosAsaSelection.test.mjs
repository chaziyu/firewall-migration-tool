import test from 'node:test'
import assert from 'node:assert/strict'
import { approvalSelection } from '../src/features/migration/paloAltoToCiscoAsa/reviewSelection.ts'

test('ASA preview expands the complete traffic unit and dependencies in plan order', () => {
  const rows = [
    { key: 'object', dependencies: [], blockers: [] },
    { key: 'interface', approval_group: 'traffic', dependencies: [], blockers: [] },
    { key: 'policy', approval_group: 'traffic', dependencies: ['object', 'interface'], blockers: [] },
    { key: 'default', approval_group: 'traffic', dependencies: ['policy'], blockers: [] },
    { key: 'binding', approval_group: 'traffic', dependencies: ['default'], blockers: [] },
  ]
  assert.deepEqual(approvalSelection(rows, ['policy']), rows.map((row) => row.key))
  assert.deepEqual(approvalSelection(rows, ['object']), ['object'])
  assert.throws(() => approvalSelection(rows.map((row) => row.key === 'binding' ? { ...row, blockers: ['conflict'] } : row), ['policy']))
  assert.throws(() => approvalSelection(rows, ['missing']))
})
