import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import * as jsxRuntime from 'react/jsx-runtime'
import { createHookHarness, createSharedVite, loadCjs, nodes } from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

test('TsfExplorer renders split-pane archive tree, indexing badge, and search controls', async () => {
  const { TsfExplorer } = await vite.load('/src/features/tsf/TsfExplorer.tsx')
  const html = renderToStaticMarkup(createElement(TsfExplorer, {
    session: {
      sessionId: '0123456789abcdef0123456789abcdef',
      filename: 'techsupport.zip',
      totalFiles: 42,
      skippedCount: 1,
    },
    initialRootTree: {
      success: true,
      path: '',
      dirs: ['opt', 'var'],
      files: [{ rel_path: 'README.txt', name: 'README.txt', size_bytes: 128, size_human: '128.0 B', is_text: true }],
    },
    initialStatus: {
      success: true,
      total_files: 42,
      content_ready: true,
      content_progress: 1,
      content_error: '',
    },
  }))
  assert.ok(html.includes('Archive Tree'))
  assert.ok(html.includes('README.txt'))
  assert.ok(html.includes('128.0 B'))
  assert.ok(html.includes('Indexed · 42 files'))
  assert.ok(html.includes('1 skipped'))
  assert.ok(html.includes('Filename'))
  assert.ok(html.includes('Content'))
})

test('TsfExplorer opens files, runs search, jumps to matching line, paginates, and downloads', async () => {
  const { hooks, resetCursor } = createHookHarness()
  const savedCalls = []
  const modExports = loadCjs('../src/features/tsf/TsfExplorer.tsx', {
    react: hooks,
    'react/jsx-runtime': jsxRuntime,
    '../../components/common/Button': { Button: 'Button' },
    '../../components/common/ErrorBanner': { ErrorBanner: 'ErrorBanner' },
    '../../utils/desktop': {
      saveBlobWithFallback: async (blob, filename) => {
        savedCalls.push({ size: blob.size, filename })
        return { status: 'downloaded', filename }
      },
    },
    './tsfApi': {
      fetchTsfTree: async () => ({ success: true, path: '', dirs: [], files: [] }),
      fetchTsfStatus: async () => ({ success: true, total_files: 2, content_ready: true, content_progress: 1, content_error: '' }),
      searchTsf: async (_sid, mode, q) => ({
        success: true,
        mode,
        results: [{ rel_path: 'var/log/mp-log.log', line_number: 510, line_text: `hit ${q}` }],
      }),
      fetchTsfFile: async (_sid, relPath, page, jumpLine) => ({
        success: true,
        rel_path: relPath,
        size_human: '12.0 KB',
        truncated: false,
        total_lines: 600,
        total_pages: 2,
        page: jumpLine === 510 ? 1 : page,
        lines: [[510, 'hit failover']],
      }),
      downloadTsfFile: async () => new Blob(['log data']),
    },
  })

  const props = {
    session: { sessionId: '0123456789abcdef0123456789abcdef', filename: 'tsf.zip', totalFiles: 2, skippedCount: 0 },
    initialRootTree: {
      success: true,
      path: '',
      dirs: [],
      files: [{ rel_path: 'var/log/mp-log.log', name: 'mp-log.log', size_bytes: 12288, size_human: '12.0 KB', is_text: true }],
    },
    initialStatus: { success: true, total_files: 2, content_ready: true, content_progress: 1, content_error: '' },
  }

  const renderTree = () => {
    resetCursor()
    return nodes(modExports.TsfExplorer(props))
  }

  let tree = renderTree()
  const searchInput = tree.find((n) => n.type === 'input')
  searchInput.props.onChange({ target: { value: 'failover' } })
  tree = renderTree()
  const searchBtn = tree.find((n) => n.type === 'Button' && n.props.children === 'Search')
  await searchBtn.props.onClick()
  tree = renderTree()

  const hitItem = tree.find((n) => n.type === 'button' && n.props.className === 'tsf-result-item')
  assert.ok(hitItem)
  await hitItem.props.onClick()
  tree = renderTree()

  const highlightRow = tree.find((n) => n.type === 'div' && String(n.props.className || '').includes('highlight'))
  assert.ok(highlightRow, 'jump_line row is highlighted')
  assert.ok(JSON.stringify(tree).includes('Page 2 of 2'))

  const downloadBtn = tree.find((n) => n.type === 'Button' && n.props.children === 'Download')
  await downloadBtn.props.onClick()
  assert.deepEqual(savedCalls, [{ size: 8, filename: 'mp-log.log' }])
})
