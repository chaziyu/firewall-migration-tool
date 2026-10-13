import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import * as jsxRuntime from 'react/jsx-runtime'
import * as presentation from '../src/features/report/reportPresentation.ts'

test('warning group selection settles and retains the matching findings', () => {
  const slots = []
  let cursor = 0
  let pending = false
  const hooks = {
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) slots[index] = initial
      return [slots[index], (value) => {
        const next = typeof value === 'function' ? value(slots[index]) : value
        if (!Object.is(next, slots[index])) { slots[index] = next; pending = true }
      }]
    },
    useMemo(factory, dependencies) {
      const index = cursor++
      const previous = slots[index]
      if (!previous || dependencies.some((value, i) => !Object.is(value, previous.dependencies[i]))) {
        slots[index] = { dependencies, value: factory() }
      }
      return slots[index].value
    },
    useRef(value) { return hooks.useMemo(() => ({ current: value }), []) },
    useEffect() {},
  }
  const source = readFileSync(new URL('../src/features/report/SourceReport.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(`${source}\nexport { ValidationReport }`, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText
  const exports = {}
  const modules = { react: hooks, 'react/jsx-runtime': jsxRuntime, './reportPresentation': presentation,
    './ReportDetails': {}, '../../components/common/tabKeyboard': {} }
  new Function('require', 'exports', compiled)((name) => {
    assert.ok(name in modules, `Unexpected import: ${name}`)
    return modules[name]
  }, exports)
  const rows = Array.from({ length: 209 }, (_, i) => ({ severity: 'warning', domain: 'nat', message: i < 204 ? 'wan1' : 'any', object_name: String(i) }))
  function render() {
    let tree
    let attempts = 0
    do {
      assert.ok(++attempts < 25, 'Validation entered a render loop')
      pending = false
      cursor = 0
      tree = exports.ValidationReport({ data: { sections: { validation: rows } }, reportScope: '', onReportScope() {}, active: true })
    } while (pending)
    return tree
  }
  function table(tree) { return tree.props.children[4].props.children[0].props.children[0] }
  let tree = render()
  for (const group of presentation.findingGroups(rows)) {
    tree.props.children[2].props.onGroupChange(group.key)
    tree = render()
    assert.equal(table(tree).props.rows.length, Math.min(group.count, 200))
    assert.ok(table(tree).props.rows.every((row) => presentation.findingGroupKey(row) === group.key))
  }
  tree.props.children[2].props.onGroupChange('')
  assert.equal(table(render()).props.grouped, false)
})
