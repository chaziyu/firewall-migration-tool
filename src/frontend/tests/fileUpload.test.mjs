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
  `).replace(/import .* from '..\/..\/components\/common\/Button';/, `const Button = 'button';`)
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

  const status = { type: 'span', props: { role: 'status' }, children: ['Reading configuration…'] }
  const cardTree = FileUpload({ file, onChange: (next) => selected.push(next), description: 'PAN-OS', children: status })
  assert.equal(cardTree.children[0], false, 'selected file replaces the empty dropzone')
  const cardInput = cardTree.children[1]
  cardInput.props.ref.current = { click: () => clicks++, value: 'target.xml' }
  const card = cardTree.children[2]
  const header = card.children[0]
  assert.equal(header.children[1].children[0].children[0], 'target.xml')
  assert.equal(header.children[1].children[1].children.join(''), '42 Bytes · PAN-OS')
  assert.equal(card.children[1].children[0], status, 'status stays inside the file card')
  const [replace, remove] = header.children[2].children
  replace.props.onClick()
  assert.equal(clicks, 2)
  remove.props.onClick()
  assert.equal(selected.at(-1), null)
  assert.equal(cardInput.props.ref.current.value, '')
  const lockedCard = FileUpload({ file, onChange() {}, disabled: true })
  for (const action of lockedCard.children[2].children[0].children[2].children) assert.equal(action.props.disabled, true)
})
