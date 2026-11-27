import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

const SNAPSHOT_CARD = {
  id: 'fg_lifecycle_card',
  vendor: 'fortigate',
  title: 'Lifecycle & Firmware',
  subtitle: 'Model & FortiOS branch support status · Fetching live data… (showing snapshot 2026-11-24)',
  source_label: 'Offline snapshot (2026-11-24)',
  snapshot_updated_at: '2026-11-24',
  needs_live_refresh: true,
  badge: { id: 'fg_lifecycle_badge', text: 'Lifecycle OK · Up to Date', variant: 'allow' },
  rows: [
    { label: 'Hardware Model', value: 'FortiGate-60F' },
    { label: 'Current Firmware', value: '7.4.13 (Branch 7.4)' },
  ],
  refresh_params: { vendor: 'fortigate', model: 'FG-60F', firmware: '7.4.13' },
}

test('LifecycleCard renders initial snapshot card and badge cleanly via SSR', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { LifecycleCard } = await server.ssrLoadModule('/src/features/report/LifecycleCard.tsx')
    const { isLifecycleCardData } = await server.ssrLoadModule('/src/features/report/reportPresentation.ts')
    assert.equal(isLifecycleCardData(SNAPSHOT_CARD), true)
    assert.equal(isLifecycleCardData(null), false)

    const html = renderToStaticMarkup(createElement(LifecycleCard, { lifecycle: SNAPSHOT_CARD }))
    assert.ok(html.includes('id="fg_lifecycle_card"'))
    assert.ok(html.includes('id="fg_lifecycle_badge"'))
    assert.ok(html.includes('fw-badge-allow'))
    assert.ok(html.includes('FortiGate-60F'))
    assert.ok(html.includes('Fetching live data…'))
  } finally {
    await server.close()
  }
})

test('LifecycleCard refreshes from /api/lifecycle when needs_live_refresh is true and keeps snapshot on failure', async () => {
  const source = readFileSync(new URL('../src/features/report/LifecycleCard.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText

  function runEffectCase({ fetchImpl, initialCard }) {
    const slots = []
    let cursor = 0
    let pendingEffects = []
    const hooks = {
      useState(initial) {
        const idx = cursor++
        if (!(idx in slots)) slots[idx] = initial
        return [slots[idx], (val) => {
          slots[idx] = typeof val === 'function' ? val(slots[idx]) : val
        }]
      },
      useEffect(fn) {
        pendingEffects.push(fn)
      },
    }
    const exports = {}
    new Function('require', 'exports', compiled)(
      (name) => ({
        react: hooks,
        'react/jsx-runtime': jsxRuntime,
        '../source/sourceApi': { fetchLifecycleStatus: fetchImpl },
      }[name]),
      exports,
    )
    const render = () => {
      cursor = 0
      pendingEffects = []
      const tree = exports.LifecycleCard({ lifecycle: initialCard })
      return tree
    }
    render()
    const cleanups = pendingEffects.map((fn) => fn()).filter((c) => typeof c === 'function')
    return {
      render,
      cleanups,
      getCard: () => (slots[0]?.forLifecycle === initialCard ? slots[0].card : initialCard),
    }
  }

  // Case 1: Live refresh succeeds and updates card in place
  const liveCard = {
    ...SNAPSHOT_CARD,
    needs_live_refresh: false,
    subtitle: 'Model & FortiOS branch support status · Source: Live (endoflife.date + Fortinet RSS)',
    badge: { id: 'fg_lifecycle_badge', text: 'Patch Available (7.4.99)', variant: 'warn' },
  }
  const calls = []
  const okCase = runEffectCase({
    initialCard: SNAPSHOT_CARD,
    fetchImpl: async (params) => {
      calls.push(params)
      return liveCard
    },
  })
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0], SNAPSHOT_CARD.refresh_params)
  assert.equal(okCase.getCard().badge.text, 'Patch Available (7.4.99)')
  assert.equal(okCase.getCard().needs_live_refresh, false)

  // Case 2: Live refresh fails -> keeps offline snapshot rows and updates subtitle cleanly
  const failCase = runEffectCase({
    initialCard: SNAPSHOT_CARD,
    fetchImpl: async () => {
      throw new Error('offline')
    },
  })
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(failCase.getCard().badge.text, 'Lifecycle OK · Up to Date')
  assert.equal(failCase.getCard().needs_live_refresh, false)
  assert.ok(!failCase.getCard().subtitle.includes('Fetching live data'))
  assert.ok(failCase.getCard().subtitle.includes('Offline snapshot (2026-11-24)'))

  // Case 3: needs_live_refresh=false skips network fetch
  const skippedCalls = []
  runEffectCase({
    initialCard: { ...SNAPSHOT_CARD, needs_live_refresh: false },
    fetchImpl: async (params) => {
      skippedCalls.push(params)
      return liveCard
    },
  })
  await new Promise((r) => setTimeout(r, 0))
  assert.equal(skippedCalls.length, 0)
})
