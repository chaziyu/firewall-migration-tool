import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

function loadWorkflow() {
  const source = readFileSync(new URL('../src/features/migration/MigrationPairWorkflow.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText
  const exports = {}
  const components = {
    './paloAltoToFortigate/MigrationWorkflow': { FortiGateMigrationWorkflow: 'PANOS_FortiGate' },
    './paloAltoToJuniperSrx/MigrationWorkflow': { PaloAltoToJuniperSrxWorkflow: 'PANOS_SRX' },
    './paloAltoToCiscoAsa/MigrationWorkflow': { PaloAltoToCiscoAsaWorkflow: 'PANOS_ASA' },
    './paloAltoToCheckPoint/MigrationWorkflow': { PaloAltoToCheckPointWorkflow: 'PANOS_CheckPoint' },
    './paloAltoToCiscoFtd/MigrationWorkflow': { PaloAltoToCiscoFtdWorkflow: 'PANOS_FTD' },
    './fortigateToJuniperSrx/MigrationWorkflow': { JuniperSRXMigrationWorkflow: 'JuniperSRX' },
    './fortigateToCiscoAsa/MigrationWorkflow': { CiscoAsaMigrationWorkflow: 'CiscoASA' },
    './fortigateToCheckPoint/MigrationWorkflow': { CheckPointMigrationWorkflow: 'CheckPoint' },
  }
  const jsx = {
    jsx: (type, props, key) => ({ type, props, key }),
    jsxs: (type, props, key) => ({ type, props, key }),
  }
  new Function('require', 'exports', compiled)((key) => key === 'react/jsx-runtime' ? jsx : components[key], exports)
  return exports.MigrationPairWorkflow
}

test('migration pair dispatcher keeps each pair on its own workflow and passes the current context', () => {
  const workflow = loadWorkflow()
  const source = { source_text: 'config' }
  const onStageChange = () => {}
  for (const [pairId, component] of [
    ['palo_alto_to_fortigate', 'PANOS_FortiGate'],
    ['palo_alto_to_juniper_srx', 'PANOS_SRX'],
    ['palo_alto_to_cisco_asa', 'PANOS_ASA'],
    ['palo_alto_to_checkpoint', 'PANOS_CheckPoint'],
    ['palo_alto_to_cisco_ftd', 'PANOS_FTD'],
    ['fortigate_to_juniper_srx', 'JuniperSRX'],
    ['fortigate_to_cisco_asa', 'CiscoASA'],
    ['fortigate_to_checkpoint', 'CheckPoint'],
  ]) {
    const tree = workflow({ pairId, source, sourceKey: 'digest', stage: 'place', onStageChange })
    assert.equal(tree.type, component)
    assert.equal(tree.props.source, source)
    assert.equal(tree.props.sourceKey, 'digest')
    assert.equal(tree.props.stage, 'place')
    assert.equal(tree.props.onStageChange, onStageChange)
    assert.equal(tree.key, `${pairId}:digest`)
  }
})

test('migration pair dispatcher explains disabled targets without routing to another pair', () => {
  const tree = loadWorkflow()({ pairId: 'fortigate_to_cisco_ftd', source: {}, sourceKey: 'digest', stage: 'place', onStageChange: () => {} })
  assert.equal(tree.type, 'section')
  assert.equal(tree.props.role, 'status')
  assert.match(JSON.stringify(tree), /no enabled offline export workflow/i)
})

test('selected pair shows capability limits and missing metadata grants no execution', async () => {
  const code = ts.transpileModule(readFileSync(new URL('../src/features/source/SourceConfiguration.tsx', import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText
  async function render(pair) {
    const slots = []; let cursor = 0; let dirty = false; let effects = []
    const hooks = {
      useState(value) { const i = cursor++; if (!(i in slots)) slots[i] = typeof value === 'function' ? value() : value; return [slots[i], (next) => { slots[i] = typeof next === 'function' ? next(slots[i]) : next; dirty = true }] },
      useRef(value) { return slots[cursor++] ??= { current: value } },
      useMemo(fn, deps) { const i = cursor++; const old = slots[i]; if (!old || deps.some((d, j) => d !== old.deps[j])) slots[i] = { deps, value: fn() }; return slots[i].value },
      useEffect(fn, deps) { const i = cursor++; if (!slots[i] || deps.some((d, j) => d !== slots[i][j])) { slots[i] = deps; effects.push(fn) } },
    }
    const exports = {}
    const jsx = { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) }
    new Function('require', 'exports', code)((name) => {
      if (name === 'react') return hooks
      if (name === 'react/jsx-runtime') return jsx
      if (name === '../../storage/workspaceStore') return { restoreWorkspace: async () => ({}), saveWorkspace: async () => {} }
      if (name === './sourceApi') return { loadSourceVendors: async () => [{ vendor_id: 'fortigate', file_extensions: ['.conf'] }] }
      if (name === '../migration/pairApi') return { loadMigrationPairs: async () => [pair] }
      return new Proxy({}, { get: (_target, key) => String(key) })
    }, exports)
    const nodes = (tree) => Array.isArray(tree) ? tree.flatMap(nodes) : tree && typeof tree === 'object' ? [tree, ...nodes(tree.props?.children)] : []
    for (let attempt = 0; attempt < 20; attempt++) {
      cursor = 0; dirty = false
      const tree = exports.SourceConfiguration({ view: 'migration', liveDeviceAccess: false, onViewChange() {} })
      const callbacks = effects; effects = []; callbacks.forEach((fn) => fn())
      await new Promise((resolve) => setImmediate(resolve))
      if (!dirty) return nodes(tree).find((node) => node.props?.['aria-label'] === 'Selected migration workflow limits')
    }
    throw new Error('Did not settle')
  }
  const pair = { pair_id: 'fortigate_to_cisco_asa', source_vendor: 'fortigate', display_name: 'ASA', export_available: true, deployment_available: false }
  const limits = { mapping_workflow: 'Manual mapping', destination_comparison: 'NAT interactions blocked', execution_mode: 'Offline export only', activation_steps: ['Apply manually', 'Save manually'] }
  const summary = JSON.stringify(await render({ ...pair, ...limits }))
  for (const value of [limits.mapping_workflow, limits.destination_comparison, limits.execution_mode, ...limits.activation_steps]) assert.ok(summary.includes(value), value)
  const unknown = JSON.stringify(await render(pair))
  assert.ok(unknown.includes('Execution capabilities are not specified'))
  assert.ok(!unknown.includes('button'))
})
