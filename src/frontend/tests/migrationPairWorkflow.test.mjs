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

test('MigrationPairWorkflow renders pair context without routing to another pair', async () => {
  const code = ts.transpileModule(readFileSync(new URL('../src/features/migration/MigrationPairWorkflow.tsx', import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText
  const exports = {}
  const jsx = { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) }
  new Function('require', 'exports', code)((name) => {
    if (name === 'react/jsx-runtime') return jsx
    return new Proxy({}, { get: (_target, key) => String(key) })
  }, exports)
  const tree = exports.MigrationPairWorkflow({ pairId: 'fortigate_to_cisco_asa', source: {}, sourceKey: 'digest', stage: 'load', onStageChange: () => {} })
  assert.equal(tree.type, 'CiscoAsaMigrationWorkflow')
})
