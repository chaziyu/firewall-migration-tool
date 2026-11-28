import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import { createServer } from 'vite'
import * as presentation from '../src/features/report/reportPresentation.ts'

const compiledCache = new Map()

export function transpileCjs(relPath, append = '') {
  const key = `${relPath}\0${append}`
  if (!compiledCache.has(key)) {
    const source = readFileSync(new URL(relPath, import.meta.url), 'utf8')
    const input = append ? `${source}\n${append}` : source
    compiledCache.set(
      key,
      ts.transpileModule(input, {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          jsx: ts.JsxEmit.ReactJSX,
          target: ts.ScriptTarget.ES2022,
        },
      }).outputText,
    )
  }
  return compiledCache.get(key)
}

export function loadCjs(relPath, resolve, { append = '' } = {}) {
  const compiled = transpileCjs(relPath, append)
  const exports = {}
  const mod = { exports }
  const req = typeof resolve === 'function'
    ? resolve
    : (name) => {
        assert.ok(name in resolve, `Unexpected import in ${relPath}: ${name}`)
        return resolve[name]
      }
  new Function('require', 'exports', 'module', compiled)(req, exports, mod)
  return mod.exports
}

export function nodes(node) {
  if (Array.isArray(node)) return node.flatMap(nodes)
  return node && typeof node === 'object' ? [node, ...nodes(node.props?.children)] : []
}

export function createHookHarness() {
  const slots = []
  let cursor = 0
  let pending = false
  let pendingEffects = []
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) slots[index] = typeof initial === 'function' ? initial() : initial
      return [
        slots[index],
        (value) => {
          const next = typeof value === 'function' ? value(slots[index]) : value
          if (!Object.is(next, slots[index])) {
            slots[index] = next
            pending = true
          }
        },
      ]
    },
    useMemo(factory, dependencies) {
      const index = cursor++
      const previous = slots[index]
      if (!previous || !dependencies || dependencies.some((value, i) => !Object.is(value, previous.dependencies?.[i]))) {
        slots[index] = { dependencies, value: factory() }
      }
      return slots[index].value
    },
    useCallback(callback, dependencies) {
      return hooks.useMemo(() => callback, dependencies)
    },
    useRef(value) {
      return hooks.useMemo(() => ({ current: value }), [])
    },
    useId() {
      return hooks.useMemo(() => 'test-id', [])
    },
    useEffect(fn) {
      pendingEffects.push(fn)
    },
  }
  return {
    hooks,
    slots,
    resetCursor() { cursor = 0 },
    isPending() { return pending },
    clearPending() { pending = false },
    flushEffects() {
      const queued = pendingEffects
      pendingEffects = []
      return queued.map((fn) => fn()).filter((cleanup) => typeof cleanup === 'function')
    },
  }
}

export function createSourceReportMocks(hooks, overrides = {}) {
  return {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    './reportPresentation': presentation,
    '../source/sourceApi': { fetchSecurityAudit: async () => null },
    './ConfigDiffPanel': { ConfigDiffPanel: 'ConfigDiffPanel' },
    './PacketTracePanel': { PacketTracePanel: 'PacketTracePanel' },
    './PmLookupPanel': { PmLookupPanel: 'PmLookupPanel' },
    './PolicyLookupPanel': { PolicyLookupPanel: 'PolicyLookupPanel' },
    './ReportDetails': {},
    './RouteLookupPanel': { RouteLookupPanel: 'RouteLookupPanel' },
    './ExcelExportControls': {},
    './LifecycleCard': { isLifecycleCardData: () => false, LifecycleCard: 'LifecycleCard' },
    './WhereUsedPanel': { WhereUsedPanel: 'WhereUsedPanel' },
    './SdwanView': { SdwanView: 'SdwanView' },
    './VpnInspectorView': { VpnInspectorView: 'VpnInspectorView' },
    './SecurityAuditPanel': { PublicExposureCard: 'PublicExposureCard', SecurityAuditPanel: 'SecurityAuditPanel' },
    './SslToIpsecPanel': { SslToIpsecPanel: 'SslToIpsecPanel' },
    '../../components/common/tabKeyboard': {},
    '../../components/common/ErrorBanner': {},
    ...overrides,
  }
}

export function loadSourceReport(hooks, { overrides = {}, extraExports = [] } = {}) {
  const append = extraExports.length ? `export { ${extraExports.join(', ')} }` : ''
  return loadCjs('../src/features/report/SourceReport.tsx', createSourceReportMocks(hooks, overrides), { append })
}

export function createSharedVite() {
  let server
  return {
    async beforeHook() {
      server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
    },
    async afterHook() {
      await server?.close()
      server = undefined
    },
    load(id) {
      return server.ssrLoadModule(id)
    },
  }
}
