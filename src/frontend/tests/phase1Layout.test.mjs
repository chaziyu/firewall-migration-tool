import test, { before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { detectUploadKind } from '../src/features/source/autoDetect.ts'
import { createSharedVite } from './testHelpers.mjs'

const vite = createSharedVite()
before(() => vite.beforeHook())
after(() => vite.afterHook())

test('detectUploadKind classifies FortiGate, Palo Alto XML, TSF ZIP, and unknown files', () => {
  assert.equal(detectUploadKind('panorama.xml'), 'palo_alto')
  assert.equal(detectUploadKind('PAN-OS.XML'), 'palo_alto')
  assert.equal(detectUploadKind('edge.conf'), 'fortigate')
  assert.equal(detectUploadKind('branch.cfg'), 'fortigate')
  assert.equal(detectUploadKind('backup.txt'), 'fortigate')
  assert.equal(detectUploadKind('techsupport.zip'), 'tsf')
  assert.equal(detectUploadKind('archive.tar.gz'), 'unknown')
})

test('QuickSearchModal renders top-right dialog when open and nothing when closed', async () => {
  const { QuickSearchModal } = await vite.load('/src/features/report/QuickSearchModal.tsx')
  const closedHtml = renderToStaticMarkup(createElement(QuickSearchModal, {
    open: false,
    onClose() {},
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
  }))
  assert.equal(closedHtml, '')

  const openHtml = renderToStaticMarkup(createElement(QuickSearchModal, {
    open: true,
    onClose() {},
    vendor: 'fortigate',
    sourceEvidence: { vendor: 'fortigate', source_text: '' },
  }))
  assert.match(openHtml, /role="dialog"/)
  assert.match(openHtml, /aria-modal="true"/)
  assert.match(openHtml, /class="fw-qs-dialog"/)
  assert.match(openHtml, /Global Quick Search/)
})

test('PageHeader renders slim topbar actions and omits ZoomControl and ThemeColorPicker', async () => {
  const { PageHeader } = await vite.load('/src/components/layout/PageHeader.tsx')
  const html = renderToStaticMarkup(createElement(PageHeader, {
    page: { title: 'Firewall Migration Tool', description: '' },
    theme: 'light',
    onToggleTheme() {},
    workspaceMeta: {
      vendorLabel: 'FortiGate FortiOS',
      filename: 'edge.conf',
      activeSection: 'Overview',
    },
    workspaceActions: {
      canSearch: true,
      excelProfile: 'fast',
      exporting: false,
      onOpenSearch() {},
      onExcelProfileChange() {},
      onExportExcel() {},
    },
  }))
  assert.ok(html.includes('FortiGate FortiOS'))
  assert.ok(html.includes('edge.conf'))
  assert.ok(html.includes('Ctrl+K'))
  assert.ok(!html.includes('Audit Report'))
  assert.ok(html.includes('Export to Excel'))
  assert.ok(html.includes('FAST'))
  assert.ok(html.includes('FULL'))
  assert.ok(!html.includes('color-picker-toggle'))
  assert.ok(!html.includes('zoom-control'))
})

test('Sidebar renders monochrome section navigation and Load new config footer without Mode selector', async () => {
  const { Sidebar } = await vite.load('/src/components/layout/Sidebar.tsx')
  const html = renderToStaticMarkup(createElement(Sidebar, {
    collapsed: false,
    onNewWorkspace() {},
    workspaceMeta: {
      vendorLabel: 'Palo Alto PAN-OS',
      filename: 'pa.xml',
      activeSection: 'Overview',
      reportSections: [
        { label: 'Overview', count: null },
        { label: 'Policies & NAT', count: 12 },
      ],
    },
  }))
  assert.ok(html.includes('Load new config'))
  assert.ok(html.includes('Policies &amp; NAT'))
  assert.ok(!html.includes('fw-mode-selector'))
  assert.ok(!html.includes('📊'))
})
