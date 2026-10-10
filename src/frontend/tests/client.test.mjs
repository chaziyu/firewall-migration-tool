import test from 'node:test'
import assert from 'node:assert/strict'
import { apiFetch, apiUrl, isDesktopRuntime, postJson, RequestError, waitForDesktopRuntime } from '../src/api/client.ts'
import { mockIPC, clearMocks } from '@tauri-apps/api/mocks'

test('desktop startup waits for readiness without sending requests to the web origin', async (context) => {
  globalThis.window = globalThis
  globalThis.__FWMIGRATE_DESKTOP__ = { starting: true }
  context.after(() => { clearMocks(); delete globalThis.window; delete globalThis.__FWMIGRATE_DESKTOP__ })
  assert.equal(isDesktopRuntime(), true)
  let fetched = false
  context.mock.method(globalThis, 'fetch', async () => { fetched = true })
  await assert.rejects(apiFetch('/api/vendors'), /still starting/)
  assert.equal(fetched, false)
  let calls = 0
  mockIPC((command) => {
    assert.equal(command, 'desktop_runtime_status')
    return ++calls === 1 ? null : { apiBase: 'http://127.0.0.1:54321', token: 'per-launch' }
  })
  await waitForDesktopRuntime(new AbortController().signal)
  assert.equal(calls, 2)
  assert.equal(apiUrl('/api/vendors'), 'http://127.0.0.1:54321/api/vendors')
})

test('startup failure and cancellation never enable backend transport', async (context) => {
  globalThis.window = globalThis
  globalThis.__FWMIGRATE_DESKTOP__ = { starting: true }
  context.after(() => { clearMocks(); delete globalThis.window; delete globalThis.__FWMIGRATE_DESKTOP__ })
  mockIPC(() => { throw new Error('Desktop backend startup timed out') })
  await assert.rejects(waitForDesktopRuntime(new AbortController().signal), /timed out/)
  const controller = new AbortController()
  mockIPC(() => { controller.abort(); return { apiBase: 'http://127.0.0.1:54321', token: 'cancelled' } })
  await waitForDesktopRuntime(controller.signal)
  await assert.rejects(apiFetch('/api/vendors'), /still starting/)
})

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

test('API transport stays relative in web mode and uses authenticated loopback in desktop mode', async (context) => {
  delete globalThis.__FWMIGRATE_DESKTOP__
  assert.equal(isDesktopRuntime(), false)
  assert.equal(apiUrl('/api/vendors'), '/api/vendors')

  context.after(() => { delete globalThis.__FWMIGRATE_DESKTOP__ })
  globalThis.__FWMIGRATE_DESKTOP__ = { apiBase: 'http://127.0.0.1:54321', token: 'desktop-secret' }
  assert.equal(isDesktopRuntime(), true)
  assert.equal(apiUrl('/api/vendors'), 'http://127.0.0.1:54321/api/vendors')

  context.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, 'http://127.0.0.1:54321/api/vendors')
    assert.equal(new Headers(init.headers).get('X-FWMigrate-Desktop-Token'), 'desktop-secret')
    return { ok: true, status: 200, json: async () => ({ sources: [] }) }
  })

  await apiFetch('/api/vendors')
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
