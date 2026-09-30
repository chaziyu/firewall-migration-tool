import test from 'node:test'
import assert from 'node:assert/strict'
import { postJson, RequestError } from '../src/api/client.ts'

for (const [path, result] of [
  ['/api/deploy', { failed_command_index: 2, failure_message: 'command 2 rejected', validation: { status: 'FAILED', response: 'Invalid zone trust' } }],
  ['/api/validate-candidate', { status: 'FAILED', response: 'Invalid zone trust' }],
  ['/api/commit', { status: 'FAILED', response: 'Commit failed' }],
]) {
  test(`${path} retains structured device diagnostics`, async (context) => {
    const feedback = { mapping_status: 'MAPPED', migration_items: [{ source_name: 'trust', decision_keys: ['zone:trust'] }] }
    context.mock.method(globalThis, 'fetch', async () => ({ ok: false, status: 502,
      json: async () => ({ success: false, result, validation_feedback: feedback }) }))
    await assert.rejects(postJson(path, {}), (error) => {
      assert.ok(error instanceof RequestError)
      assert.equal(error.details.result, result)
      assert.equal(error.details.validation_feedback, feedback)
      assert.ok(error.message.includes(result.response || result.failure_message))
      assert.ok(error.message.includes(result.validation?.response || result.response))
      return true
    })
  })
}

test('ordinary API errors and success keep their contract', async (context) => {
  context.mock.method(globalThis, 'fetch', async () => ({ ok: false, status: 400,
    json: async () => ({ success: false, error: 'Missing artifact' }) }))
  await assert.rejects(postJson('/api/deploy', {}), /Missing artifact/)
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ success: true }) })
  assert.deepEqual(await postJson('/api/deploy', {}), { success: true })
})
