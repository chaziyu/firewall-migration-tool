import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'

test('renderMarkdownBlocks formats markdown cleanly and escapes text without dangerouslySetInnerHTML', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { renderMarkdownBlocks } = await server.ssrLoadModule('/src/features/chat/markdown.tsx')
    const { ConfigChatWidget } = await server.ssrLoadModule('/src/features/chat/ConfigChatWidget.tsx')
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
  } finally {
    await server.close()
  }
})

test('ConfigChatWidget toggles panel, saves session key, and sends chat prompt', async () => {
  const slots = []
  let cursor = 0
  const hooks = {
    useState(initial) {
      const idx = cursor++
      if (!(idx in slots)) slots[idx] = initial
      return [slots[idx], (val) => { slots[idx] = typeof val === 'function' ? val(slots[idx]) : val }]
    },
    useRef: (v) => ({ current: v }),
    useEffect() {},
  }
  const source = readFileSync(new URL('../src/features/chat/ConfigChatWidget.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const exports = {}
  new Function('require', 'exports', compiled)(
    (name) => ({ react: hooks, 'react/jsx-runtime': jsxRuntime, './markdown': { renderMarkdownBlocks: (s) => [s] } }[name]),
    exports,
  )
  function nodes(node) {
    if (Array.isArray(node)) return node.flatMap(nodes)
    return node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : []
  }
  const render = () => {
    cursor = 0
    return nodes(exports.ConfigChatWidget({
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
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { UpdateChecker } = await server.ssrLoadModule('/src/components/layout/UpdateChecker.tsx')
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
  } finally {
    await server.close()
  }

  // Test automatic install invocation without needing a manual "Update & Restart" click
  const slots = []
  let cursor = 0
  const effects = []
  const hooks = {
    useState(initial) {
      const idx = cursor++
      if (!(idx in slots)) slots[idx] = typeof initial === 'function' ? initial() : initial
      return [slots[idx], (val) => { slots[idx] = typeof val === 'function' ? val(slots[idx]) : val }]
    },
    useCallback: (fn) => fn,
    useRef: (v) => ({ current: v }),
    useEffect(fn) { effects.push(fn) },
  }
  const source = readFileSync(new URL('../src/components/layout/UpdateChecker.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText
  const exports = {}
  new Function('require', 'exports', compiled)(
    (name) => ({ react: hooks, 'react/jsx-runtime': jsxRuntime, './markdown': { renderMarkdownBlocks: (s) => [s] } }[name]),
    exports,
  )

  const origFetch = globalThis.fetch
  const origStorage = globalThis.sessionStorage
  const mem = new Map()
  globalThis.sessionStorage = {
    getItem: (k) => mem.get(k) ?? null,
    setItem: (k, v) => mem.set(k, v),
  }
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
    function nodes(node) {
      if (Array.isArray(node)) return node.flatMap(nodes)
      return node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : []
    }
    cursor = 0
    const tree = nodes(exports.UpdateChecker({ collapsed: false }))
    const checkBtn = tree.find((n) => n.props?.className === 'fw-update-check-link')
    await checkBtn.props.onClick()
    await new Promise((r) => setTimeout(r, 10))
    assert.deepEqual(fetched, ['GET /api/update/check', 'POST /api/update/install'])
  } finally {
    globalThis.fetch = origFetch
    globalThis.sessionStorage = origStorage
  }
})
