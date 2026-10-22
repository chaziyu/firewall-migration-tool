import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsx from 'react/jsx-runtime'

export const pairs = {
  fortigateToCiscoAsa: ['fortigate_to_cisco_asa', 'CiscoAsaMigrationWorkflow'],
  fortigateToJuniperSrx: ['fortigate_to_juniper_srx', 'JuniperSRXMigrationWorkflow'],
  fortigateToCheckPoint: ['fortigate_to_checkpoint', 'CheckPointMigrationWorkflow'],
  paloAltoToFortigate: ['palo_alto_to_fortigate', 'FortiGateMigrationWorkflow'],
  paloAltoToJuniperSrx: ['palo_alto_to_juniper_srx', 'PaloAltoToJuniperSrxWorkflow'],
  paloAltoToCiscoAsa: ['palo_alto_to_cisco_asa', 'PaloAltoToCiscoAsaWorkflow'],
  paloAltoToCheckPoint: ['palo_alto_to_checkpoint', 'PaloAltoToCheckPointWorkflow'],
  paloAltoToCiscoFtd: ['palo_alto_to_cisco_ftd', 'PaloAltoToCiscoFtdWorkflow'],
}

export function nodes(tree) {
  return Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []
}

export function harness(folder, { api = {}, items, saved, setup = false } = {}) {
  const [pairId, component] = pairs[folder]
  items ??= [
    { key: 'object', family: 'address', dependencies: [], render_disposition: 'REUSE' },
    { key: 'policy', family: 'policy', dependencies: ['object'], render_disposition: 'CREATE' },
    { key: 'independent', family: 'address', dependencies: [], render_disposition: 'CREATE' },
    { key: 'manual', family: 'manual', dependencies: [], render_disposition: 'BLOCK', blockers: ['UNSUPPORTED'] },
  ]
  const rows = items.map((row) => ({ family: 'address', source_vdom: 'root', source_scope: 'vsys:one', source_name: row.key,
    target_name: row.key, target_vdom: 'root', settings: { exact: row.key }, blockers: [], blocking_reasons: row.blockers ?? [], ...row }))
  const options = folder === 'paloAltoToFortigate'
    ? { source_scope: 'vsys:one', vdom: 'root', interfaces: {}, zones: {}, routers: {}, profile: {}, timezone: '', policy_settings: {} }
    : folder === 'fortigateToJuniperSrx'
      ? { source_vdom: 'root', target_context: 'root', target_version: '25.2R1', target_mode: 'standalone', routing_table: 'inet.0', timezone: '', interfaces: {}, zones: {} }
      : folder === 'fortigateToCiscoAsa'
        ? { source_vdom: 'root', target_context: 'single', target_version: '9.20', target_mode: 'routed', interfaces: {}, source_timezone: '', target_timezone: '', nat_evidence: {} }
        : folder === 'paloAltoToCiscoAsa'
          ? { source_scope: 'vsys:one', target_context: 'single', target_version: '9.20', target_mode: 'routed', interfaces: {}, new_target_confirmed: false, routing_complete: false, permit_inter_interface: false, permit_intra_interface: false, ace_limit: 256 }
          : folder === 'paloAltoToJuniperSrx'
            ? { source_scope: 'vsys:one', target_context: 'root', target_version: '25.2R1', target_mode: 'standalone', interfaces: {}, zones: {}, interface_zones: {}, routing_table: 'inet.0', vlan_interfaces_available: false }
            : { source_scope: 'vsys:one', source_vdom: 'root', target_mode: 'new', management_target: '', management_domain: '', management_api_version: '1.8.1', gaia_target: '', policy_package: 'package', access_layer: '', install_on: [], insertion_anchor: '', insertion_relation: '', target_cleanup_action: '', domain_id: 'uuid', domain_name: 'Global', manager_target: 'fmc.example.com', policy_name: 'policy', fmc_api_version: '7.7.0' }
  const requirements = folder.startsWith('fortigate') || ['paloAltoToCiscoFtd', 'paloAltoToCheckPoint'].includes(folder) ? [] : { source_scopes: ['vsys:one'], decisions: [] }
  const review = { draft: { digest: 'draft', configuration: rows, items: rows, findings: [] }, report: { items: rows, findings: [], verification: 'Offline only', plan_status: 'PARTIAL' },
    options, resolved_options: options, source_scopes: ['vsys:one'], source_vdoms: ['root'], requirements, proposals: [], effective_values: [], issues: [] }
  if (folder === 'paloAltoToFortigate') review.requirements = { source_scopes: ['vsys:one'], decisions: [{ key: 'vdom', label: 'Target VDOM', value: 'root' }], findings: [] }
  let state = saved ?? { pairId, sourceKey: 'source', options, review, requirements, approval: null, artifact: null, previewText: null, preview: null, stage: 'review' }
  let stage = setup ? 'place' : 'review'
  const source = { vendor: pairId.startsWith('fortigate') ? 'fortigate' : 'palo_alto', source_text: 'test-source' }
  const contexts = new Map(); let active; let cursor; let dirty; let effects = []
  const hooks = {
    useState(value) { const slots = active; const i = cursor++
      if (!(i in slots)) {
        const cell = { value: typeof value === 'function' ? value() : value }
        cell.set = (next) => { const value = typeof next === 'function' ? next(cell.value) : next; if (!Object.is(cell.value, value)) { cell.value = value; dirty = true } }
        slots[i] = cell
      }
      return [slots[i].value, slots[i].set] },
    useRef(value) { return active[cursor++] ??= { current: value } },
    useMemo(fn, deps) { const i = cursor++; const old = active[i]; if (!old || deps.some((value, j) => value !== old.deps[j])) active[i] = { deps, value: fn() }; return active[i].value },
    useCallback(fn, deps) { return hooks.useMemo(() => fn, deps) },
    useEffect(fn, deps) { const slots = active; const i = cursor++; const old = slots[i]
      if (!old || deps.some((value, j) => value !== old.deps[j])) { slots[i] = { deps }; effects.push(() => { old?.cleanup?.(); slots[i].cleanup = fn() }) } },
  }
  const timer = (fn) => { const token = { cancelled: false }; Promise.resolve().then(() => { if (!token.cancelled) fn() }); return token }
  const modules = new Map()
  const calls = { approvals: [], builds: [], downloads: [] }
  const requests = {
    prepare: async (_source, options) => ({ ...review, options }),
    approve: async (...args) => { const keys = args[3]?.configuration ? args[4] : args[3]; calls.approvals.push([...keys]); return { approval: { selected_items: [...keys], signature: 'signed' } } },
    build: async (...args) => { calls.builds.push(args); throw new Error('Build failed for retry test') },
    ...api,
  }
  function load(file) {
    if (modules.has(file)) return modules.get(file)
    const exports = {}; modules.set(file, exports)
    const code = ts.transpileModule(readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022 } }).outputText
    new Function('require', 'exports', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', code)((name) => {
      if (name === 'react') return hooks
      if (name === 'react/jsx-runtime') return jsx
      if (name.endsWith('/workspaceStore')) return { workspace: () => ({ panosMigration: state }), saveWorkspace: async (value) => { state = value.panosMigration } }
      if (name.endsWith('/Button')) return { Button: 'button' }
      if (name.endsWith('/ErrorBanner')) return { ErrorBanner: 'ErrorBanner' }
      if (name.endsWith('/LoadingState')) return { LoadingState: 'LoadingState' }
      if (name.endsWith('/MigrationCoverage')) return { MigrationCoverage: 'Coverage' }
      if (name.endsWith('/DestinationSnapshot')) return { DestinationSnapshot: 'DestinationSnapshot' }
      if (name.endsWith('/FileUpload')) return { FileUpload: 'FileUpload' }
      if (name.endsWith('/sourceApi')) return {}
      if (name.endsWith('/tabKeyboard')) return { tabKeyboard() {} }
      if (name === './migrationApi') {
        if (folder === 'paloAltoToFortigate') return { ...load(`features/migration/${folder}/migrationApi.ts`), ...requests }
        return requests
      }
      if (name === '../migrationApi') return { downloadFile: (...args) => calls.downloads.push(args) }
      if (name.endsWith('/api/client')) return { RequestError: class extends Error {} }
      const target = new URL(name, `file:///${file}`).pathname.slice(1)
      for (const ext of ['.ts', '.tsx']) {
        try { return load(target + ext) } catch (cause) { if (cause.code !== 'ENOENT') throw cause }
      }
      throw new Error(`Unknown test dependency ${name} from ${file}`)
    }, exports, timer, (token) => { if (token) token.cancelled = true }, () => 1, () => {})
    return exports
  }
  const Component = load(`features/migration/${folder}/MigrationWorkflow.tsx`)[component]
  function expand(tree) {
    if (Array.isArray(tree)) return tree.map(expand)
    if (!tree || typeof tree !== 'object') return tree
    if (typeof tree.type === 'function') {
      const parent = active; const parentCursor = cursor
      active = contexts.get(tree.type) ?? []; contexts.set(tree.type, active); cursor = 0
      const result = expand(tree.type(tree.props)); active = parent; cursor = parentCursor; return result
    }
    return { ...tree, props: { ...tree.props, children: expand(tree.props?.children) } }
  }
  return { calls, review, options, state: () => state, stage: (next) => { stage = next },
    async render() {
      for (let i = 0; i < 40; i++) {
        dirty = false; active = contexts.get(Component) ?? []; contexts.set(Component, active); cursor = 0
        const tree = expand(Component({ source, sourceKey: 'source', stage, onStageChange: (next) => { stage = next; dirty = true } }))
        const pending = effects; effects = []; pending.forEach((fn) => fn())
        await new Promise((resolve) => setImmediate(resolve))
        if (!dirty) return tree
      }
      assert.fail(`${folder} did not settle`)
    },
  }
}
