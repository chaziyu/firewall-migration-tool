import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import * as jsxRuntime from 'react/jsx-runtime'
import { createHookHarness, createSharedVite, loadCjs, nodes } from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

test('renderMarkdownBlocks formats markdown cleanly and escapes text without dangerouslySetInnerHTML', async () => {
  const { renderMarkdownBlocks } = await vite.load('/src/features/chat/markdown.tsx')
  const { ConfigChatWidget } = await vite.load('/src/features/chat/ConfigChatWidget.tsx')
  const md = renderMarkdownBlocks('**ALLOW** via `port1`\n\n- rule `allow-web`\n\n```cli\nset status enable\n```')
  const html = renderToStaticMarkup(createElement('div', null, md))
  assert.ok(html.includes('<strong>ALLOW</strong>'))
  assert.ok(html.includes('<code>port1</code>'))
  assert.ok(html.includes('<ul><li>rule <code>allow-web</code></li></ul>'))
  assert.ok(html.includes('<pre><code>set status enable</code></pre>'))

  const fabHtml = renderToStaticMarkup(createElement(ConfigChatWidget, {
    vendor: 'FortiGate',
    filename: 'fw.conf',
    preview: { vendor: 'fortigate', sections: {} },
  }))
  assert.ok(fabHtml.includes('id="fw-chat-fab"'))
})

test('ConfigChatWidget toggles panel, saves session key, and sends chat prompt', async () => {
  const { hooks, resetCursor } = createHookHarness()
  const modExports = loadCjs('../src/features/chat/ConfigChatWidget.tsx', {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    './markdown': { renderMarkdownBlocks: (s) => [s] },
  })
  const render = () => {
    resetCursor()
    return nodes(modExports.ConfigChatWidget({
      vendor: 'FortiGate',
      filename: 'edge.conf',
      preview: { vendor: 'fortigate', source_evidence: { source_name: 'edge.conf', source_text: 'config system global\nend' } },
    }))
  }

  let tree = render()
  const fab = tree.find((n) => n.props?.id === 'fw-chat-fab')
  fab.props.onClick()
  tree = render()
  assert.ok(tree.some((n) => n.props?.id === 'fw-chat-panel'))
  assert.ok(tree.some((n) => n.props?.className === 'fw-chat-privacy-notice'))

  const origFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body })
    return {
      ok: true,
      json: async () => ({
        ok: true,
        history: [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'Summary ready.' }],
        key_status: { configured: true, source: 'session', masked: 'AIza...9999' },
      }),
    }
  }
  try {
    const keyToggle = tree.find((n) => n.props?.id === 'fw-chat-key-toggle')
    keyToggle.props.onClick()
    tree = render()
    assert.ok(tree.some((n) => n.props?.id === 'fw-chat-key-drawer'))
    const chip = tree.find((n) => n.props?.className === 'fw-chat-suggestion-chip')
    await chip.props.onClick()
    tree = render()
    assert.ok(calls.some((c) => c.url === '/api/chat' && c.method === 'POST'))
  } finally {
    globalThis.fetch = origFetch
  }
})

test('UpdateChecker renders Check update button, hides in cloud mode, and auto-triggers install without manual click', async () => {
  const { UpdateChecker } = await vite.load('/src/components/layout/UpdateChecker.tsx')
  const html = renderToStaticMarkup(createElement(UpdateChecker, { collapsed: false }))
  assert.ok(html.includes('Check update'))

  const origStorage = globalThis.sessionStorage
  const cloudMem = new Map([['fwmigrate_update_status', JSON.stringify({ mode: 'cloud', checked: true, current_version: '0.2.3', update_available: false, can_auto_install: false })]])
  globalThis.sessionStorage = {
    getItem: (k) => cloudMem.get(k) ?? null,
    setItem: (k, v) => cloudMem.set(k, v),
  }
  try {
    const cloudHtml = renderToStaticMarkup(createElement(UpdateChecker, { collapsed: false }))
    assert.equal(cloudHtml, '')
  } finally {
    globalThis.sessionStorage = origStorage
  }

  // Test automatic install invocation without needing a manual "Update & Restart" click
  const { hooks, resetCursor } = createHookHarness()
  const modExports = loadCjs('../src/components/layout/UpdateChecker.tsx', {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    './markdown': { renderMarkdownBlocks: (s) => [s] },
  })

  const mem = new Map()
  globalThis.sessionStorage = {
    getItem: (k) => mem.get(k) ?? null,
    setItem: (k, v) => mem.set(k, v),
  }
  const origFetch = globalThis.fetch
  const fetched = []
  globalThis.fetch = async (url, init = {}) => {
    fetched.push(`${init.method || 'GET'} ${url}`)
    if (url === '/api/update/check') {
      return {
        ok: true,
        json: async () => ({
          mode: 'desktop',
          checked: true,
          current_version: '0.2.3',
          latest_version: '0.3.0',
          update_available: true,
          can_auto_install: true,
          install_method: 'installer',
        }),
      }
    }
    return {
      ok: true,
      json: async () => ({ ok: true, method: 'installer', message: 'Update v0.3.0 verified and launched.' }),
    }
  }
  try {
    resetCursor()
    const tree = nodes(modExports.UpdateChecker({ collapsed: false }))
    const checkBtn = tree.find((n) => n.props?.className === 'fw-update-check-link')
    await checkBtn.props.onClick()
    await new Promise((r) => setTimeout(r, 10))
    assert.deepEqual(fetched, ['GET /api/update/check', 'POST /api/update/install'])
  } finally {
    globalThis.fetch = origFetch
    globalThis.sessionStorage = origStorage
  }
})

test('apiFetch retries 429 and sourceApi sends source_digest with 410 fallback', async () => {
  const { apiFetch } = await vite.load('/src/api/client.ts')
  const { previewSource, fetchSecurityAudit } = await vite.load('/src/features/source/sourceApi.ts')

  const origFetch = globalThis.fetch
  const calls = []
  let auditAttempt = 0
  let retryAttempt = 0
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body })
    if (url === '/api/retry-test') {
      retryAttempt += 1
      if (retryAttempt === 1) {
        return { status: 429, ok: false, headers: { get: () => '0' }, body: { cancel: async () => {} } }
      }
      return { status: 200, ok: true, json: async () => ({ ok: true }) }
    }
    if (url === '/api/preview') {
      return {
        status: 200,
        ok: true,
        json: async () => ({
          vendor: 'fortigate',
          source_digest: 'a'.repeat(64),
          source_evidence: { vendor: 'fortigate', source_text: 'config system global\nend', source_name: 'fw.conf' },
        }),
      }
    }
    if (url === '/api/source/audit') {
      auditAttempt += 1
      if (auditAttempt === 1) {
        return {
          status: 410,
          ok: false,
          json: async () => ({ success: false, error_code: 'source_expired', error: 'expired' }),
        }
      }
      return {
        status: 200,
        ok: true,
        json: async () => ({ success: true, certificates: [], exposure: [], posture: [], hygiene: {}, quick_audit: {} }),
      }
    }
    throw new Error(`Unexpected URL: ${url}`)
  }
  try {
    const retryResp = await apiFetch('/api/retry-test', { method: 'POST' })
    assert.equal(retryResp.status, 200)
    assert.equal(retryAttempt, 2)

    const fakeFile = new File(['config system global\nend'], 'fw.conf', { type: 'text/plain' })
    const pv = await previewSource(fakeFile, 'fortigate')
    const audit = await fetchSecurityAudit('fortigate', pv.source_evidence)
    assert.equal(audit.success, true)
    const auditCalls = calls.filter((c) => c.url === '/api/source/audit').map((c) => JSON.parse(c.body))
    assert.equal(auditCalls.length, 2)
    assert.equal(auditCalls[0].source_digest, 'a'.repeat(64))
    assert.equal(auditCalls[0].source, undefined)
    assert.ok(auditCalls[1].source && auditCalls[1].source.source_text)
  } finally {
    globalThis.fetch = origFetch
  }
})
