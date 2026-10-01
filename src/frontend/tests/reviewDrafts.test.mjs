import test from 'node:test'
import assert from 'node:assert/strict'
import { reconcileReviewDrafts } from '../src/features/migration/reviewDrafts.ts'

test('review refresh preserves unrelated edits but resets changed decisions and target context', () => {
  const previous = [{ key: 'root:port1', value: null, suggested_value: 'ethernet1/1' }, { key: 'other:port1', value: null }]
  const drafts = { 'root:port1': 'ethernet1/2', 'other:port1': 'ethernet1/3', removed: 'old' }
  const next = [{ ...previous[0], value: 'ethernet1/2', review_state: 'CONFIRMED' }, previous[1]]
  assert.deepEqual(reconcileReviewDrafts(drafts, previous, next, false), { 'root:port1': 'ethernet1/2', 'other:port1': 'ethernet1/3' })
  assert.deepEqual(reconcileReviewDrafts(drafts, previous, next, true), { 'root:port1': 'ethernet1/2', 'other:port1': '' })
  assert.equal(reconcileReviewDrafts(drafts, previous, [{ ...previous[0], suggested_value: 'ethernet1/4' }], false)['root:port1'], 'ethernet1/4')
})
