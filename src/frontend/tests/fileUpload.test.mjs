import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

test('upload button opens its input and selection forwards the file', async () => {
  const source = await readFile(new URL('../src/features/source/FileUpload.tsx', import.meta.url), 'utf8')
  const compiled = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React,
  } }).outputText.replace(/import .* from 'react';/, `
    const useRef = () => ({ current: null });
    const useId = () => 'upload-test';
    const useState = () => [null, () => {}];
    const React = { createElement: (type, props, ...children) => ({ type, props, children }) };
  `)
  const { FileUpload } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
  const selected = []
  const render = (disabled = false) => FileUpload({ file: null, onChange: (file) => selected.push(file), disabled })
  const tree = render()
  const [button, input] = tree.children
  assert.equal(button.type, 'button')
  assert.equal(button.props.type, 'button')
  let clicks = 0
  input.props.ref.current = { click: () => clicks++ }
  button.props.onClick()
  assert.equal(clicks, 1)
  const file = { name: 'target.xml', size: 42 }
  const target = { files: [file], value: 'target.xml' }
  input.props.onChange({ currentTarget: target })
  assert.deepEqual(selected, [file])
  assert.equal(target.value, '')
  const disabledTree = render(true)
  assert.equal(disabledTree.children[0].props.disabled, true)
  assert.equal(disabledTree.children[1].props.disabled, true)
  disabledTree.children[0].props.onDrop({ preventDefault() {}, dataTransfer: { files: [file] } })
  assert.equal(selected.length, 1)
})
