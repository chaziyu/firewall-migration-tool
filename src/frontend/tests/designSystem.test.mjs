import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

const source = await readFile(new URL('../src/components/common/Button.tsx', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: {
  module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React,
} }).outputText
globalThis.React = { createElement: (type, props, ...children) => ({ type, props, children }) }
const { Button } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)

test('button variants preserve legacy classes without conflicting styles', () => {
  assert.equal(Button({ children: 'Save' }).props.className, 'primary-button')
  for (const variant of ['primary', 'secondary', 'outline', 'text']) {
    assert.equal(Button({ children: 'Save', variant }).props.className, `${variant}-button`)
    assert.equal(Button({ children: 'Save', className: `extra ${variant}-button` }).props.className, `${variant}-button extra`)
  }
  assert.equal(Button({ children: 'Save', variant: 'outline', className: 'primary-button secondary-button extra' }).props.className, 'outline-button extra')
  assert.equal(Button({ children: 'Save', className: 'primary-button text-button' }).props.className, 'text-button')
})

test('button forwards native attributes, children, and callbacks', () => {
  let clicks = 0
  const button = Button({ children: 'Working', variant: 'secondary', size: 'compact', type: 'submit', disabled: true, 'aria-busy': true, 'aria-label': 'Save draft', onClick: () => clicks++ })
  assert.equal(button.type, 'button')
  assert.equal(button.props.className, 'secondary-button button-compact')
  assert.equal(button.props.type, 'submit')
  assert.equal(button.props.disabled, true)
  assert.equal(button.props['aria-busy'], true)
  assert.equal(button.props['aria-label'], 'Save draft')
  assert.equal(button.props.variant, undefined)
  assert.equal(button.props.size, undefined)
  assert.deepEqual(button.children, ['Working'])
  button.props.onClick()
  assert.equal(clicks, 1)
})
