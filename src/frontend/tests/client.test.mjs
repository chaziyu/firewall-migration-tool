import test from 'node:test'
import assert from 'node:assert/strict'
import { apiFetch, postBlob, postForm, postJson, RequestError } from '../src/api/client.ts'

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

test('API transport uses same-origin paths', async (context) => {
  context.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, '/api/vendors')
    assert.deepEqual(init, {})
    return { ok: true, status: 200, json: async () => ({ sources: [] }) }
  })

  await apiFetch('/api/vendors')
})

for (const [name, request] of [
  ['JSON', () => postJson('/api/migration/design/prepare', {})],
  ['form', () => postForm('/api/preview', new FormData())],
  ['download', () => postBlob('/api/migration/bundle', {})],
]) {
  test(`${name} requests report an HTML gateway failure without exposing its body or retrying`, async (context) => {
    const fetch = context.mock.method(globalThis, 'fetch', async () => new Response(
      '<html>PRIVATE-UPSTREAM-DIAGNOSTIC</html>', { status: 502, headers: { 'Content-Type': 'text/html' } }))
    await assert.rejects(request(), (error) => {
      assert.ok(error instanceof RequestError)
      assert.equal(error.message, 'Request failed (502)')
      assert.deepEqual(error.details, {})
      assert.ok(!error.message.includes('PRIVATE-UPSTREAM-DIAGNOSTIC'))
      return true
    })
    assert.equal(fetch.mock.callCount(), 1)
  })
}

test('invalid successful JSON responses are errors rather than successful workflow data', async (context) => {
  context.mock.method(globalThis, 'fetch', async () => new Response('<html>PRIVATE-UPSTREAM-DIAGNOSTIC</html>', { status: 200 }))
  await assert.rejects(postJson('/api/migration/design/prepare', {}), (error) => {
    assert.ok(error instanceof RequestError)
    assert.equal(error.message, 'Server returned an invalid JSON response (200)')
    return true
  })
})

test('interrupted response reads retain their original abort error', async (context) => {
  const interrupted = new DOMException('Request was aborted', 'AbortError')
  context.mock.method(globalThis, 'fetch', async () => ({ ok: true, status: 200, json: async () => { throw interrupted } }))
  await assert.rejects(postJson('/api/migration/design/prepare', {}), (error) => error === interrupted)
})

test('successful binary downloads do not require JSON parsing', async (context) => {
  const bytes = new Uint8Array([80, 75, 3, 4])
  context.mock.method(globalThis, 'fetch', async () => new Response(bytes, { status: 200, headers: { 'Content-Type': 'application/zip' } }))
  const blob = await postBlob('/api/migration/bundle', {})
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), bytes)
})


test('compact plan client derives aliases from one signed artifact and preserves downloads', async (context) => {
  const { readFile } = await import('node:fs/promises')
  const ts = await import('typescript')
  const source = await readFile(new URL('../src/features/migration/migrationApi.ts', import.meta.url), 'utf8')
  const clientUrl = new URL('../src/api/client.ts', import.meta.url).href
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
    .replace('../../api/client', clientUrl)
  const { buildPlan, downloadCommands } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
  const artifact = { commands: ['set address test ip-netmask 192.0.2.1/32'], command_count: 1,
    command_sha256: 'digest', signature: 'signed', decision_document: { decisions: [] },
    report: { items: [], review: { recommendations: [{ code: 'review' }], support_guidance: [] } } }
  context.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, '/api/migrate')
    assert.equal(JSON.parse(init.body).compact_response, true)
    return { ok: true, status: 200, json: async () => ({ artifact, artifact_id: 'id', plan_status: 'READY',
      command_count: 1, counts: {}, render_summary: {}, blocking_reasons: [] }) }
  })
  const result = await buildPlan({ vendor: 'fortigate', source_text: 'source' }, { decisions: [] })
  assert.equal(result.commands, artifact.commands)
  assert.equal(result.report, artifact.report)
  assert.equal(result.decision_document, artifact.decision_document)
  assert.equal(result.recommendations, artifact.report.review.recommendations)
  assert.equal(result.support_guidance, artifact.report.review.support_guidance)
  assert.equal(await (await downloadCommands(result)).text(), artifact.commands.join('\n'))
})
