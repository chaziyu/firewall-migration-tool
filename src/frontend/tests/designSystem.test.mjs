import test from 'node:test'
import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as jsxRuntime from 'react/jsx-runtime'
import { loadCjs } from './testHelpers.mjs'

const { Button } = loadCjs('../src/components/common/Button.tsx', { 'react/jsx-runtime': jsxRuntime })

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
  assert.deepEqual(button.props.children, 'Working')
  button.props.onClick()
  assert.equal(clicks, 1)
})

const FRONTEND_SRC_DIR = fileURLToPath(new URL('../src', import.meta.url))

test('common design-system primitives render expected semantic markup and classes', () => {
  const loadCommon = (file, exportName) =>
    loadCjs(`../src/components/common/${file}`, { 'react/jsx-runtime': jsxRuntime })[exportName]

  const Badge = loadCommon('Badge.tsx', 'Badge')
  const badge = Badge({ children: 'Allow', variant: 'allow', className: 'extra', title: 'Permitted' })
  assert.equal(badge.type, 'span')
  assert.equal(badge.props.className, 'fw-badge fw-badge-allow extra')
  assert.equal(badge.props.title, 'Permitted')
  assert.equal(badge.props.children, 'Allow')
  assert.equal(Badge({ children: 'Default' }).props.className, 'fw-badge fw-badge-muted')

  const AlertBox = loadCommon('AlertBox.tsx', 'AlertBox')
  const warn = AlertBox({ children: 'Check cert', tone: 'warn', title: 'Notice' })
  assert.equal(warn.type, 'div')
  assert.equal(warn.props.className, 'ui-alert ui-alert-warn')
  assert.equal(warn.props.role, 'status')
  assert.equal(warn.props.children[0].type, 'strong')
  assert.equal(warn.props.children[0].props.className, 'ui-alert-title')
  assert.equal(AlertBox({ children: 'Failed', tone: 'danger' }).props.role, 'alert')

  const CollapsibleSection = loadCommon('CollapsibleSection.tsx', 'CollapsibleSection')
  const details = CollapsibleSection({ title: 'Details', meta: '3 items', defaultOpen: true, children: 'Body' })
  assert.equal(details.type, 'details')
  assert.equal(details.props.className, 'ui-collapsible')
  assert.equal(details.props.open, true)
  const summary = details.props.children[0]
  assert.equal(summary.type, 'summary')
  assert.equal(summary.props.className, 'ui-collapsible-summary')
  assert.equal(summary.props.children[1].props.className, 'ui-collapsible-meta')

  const KeyValueGrid = loadCommon('KeyValueGrid.tsx', 'KeyValueGrid')
  const grid = KeyValueGrid({
    items: [
      { label: 'Vendor', value: 'FortiGate' },
      { label: 'IP', value: '10.0.0.1', mono: true },
    ],
  })
  assert.equal(grid.type, 'dl')
  assert.equal(grid.props.className, 'ui-kv-grid')
  const rows = grid.props.children
  assert.equal(rows.length, 2)
  assert.equal(rows[0].props.children[1].props.className, undefined)
  assert.equal(rows[1].props.children[1].props.className, 'ui-kv-mono')
})

async function collectSourceFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...await collectSourceFiles(fullPath))
    } else if (/\.(css|ts|tsx)$/.test(entry.name)) {
      files.push(fullPath)
    }
  }
  return files
}

test('all CSS var(--*) references resolve to defined design tokens', async () => {
  const files = await collectSourceFiles(FRONTEND_SRC_DIR)
  const defined = new Set()
  const fileContents = []

  for (const filePath of files) {
    const content = await readFile(filePath, 'utf8')
    fileContents.push({ filePath, content })
    if (filePath.endsWith('.css')) {
      for (const match of content.matchAll(/(--[a-zA-Z0-9_-]+)\s*:/g)) {
        defined.add(match[1])
      }
    } else {
      for (const match of content.matchAll(/setProperty\(\s*['"](--[a-zA-Z0-9_-]+)['"]/g)) {
        defined.add(match[1])
      }
    }
  }

  const undefinedRefs = []
  for (const { filePath, content } of fileContents) {
    const relPath = path.relative(FRONTEND_SRC_DIR, filePath).replaceAll('\\', '/')
    const lines = content.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      for (const match of lines[i].matchAll(/var\(\s*(--[a-zA-Z0-9_-]+)/g)) {
        const token = match[1]
        if (!defined.has(token)) {
          undefinedRefs.push(`${relPath}:${i + 1} -> ${token}`)
        }
      }
    }
  }

  assert.deepEqual(
    undefinedRefs,
    [],
    `Found undefined CSS custom properties:\n${undefinedRefs.join('\n')}`,
  )
})

test('App.css does not grow past its line-count ratchet', async () => {
  const appCssPath = path.join(FRONTEND_SRC_DIR, 'App.css')
  const content = await readFile(appCssPath, 'utf8')
  const lineCount = content.split(/\r?\n/).length
  assert.ok(
    lineCount <= 5450,
    `App.css has ${lineCount} lines (limit: 5450). Colocate new feature styles in *.module.css or feature CSS files instead of appending to App.css.`,
  )
})
