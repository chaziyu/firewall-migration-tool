import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { detectUploadKind } from '../src/features/source/autoDetect.ts'

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
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { QuickSearchModal } = await server.ssrLoadModule('/src/features/report/QuickSearchModal.tsx')
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

    const css = readFileSync(new URL('../src/App.css', import.meta.url), 'utf8')
    const dialogRule = css.match(/\.fw-qs-dialog\s*\{([^}]*)\}/)?.[1] ?? ''
    assert.match(dialogRule, /top:\s*58px/)
    assert.match(dialogRule, /right:\s*16px/)
  } finally {
    await server.close()
  }
})

test('PageHeader renders slim topbar actions and omits ZoomControl and ThemeColorPicker', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { PageHeader } = await server.ssrLoadModule('/src/components/layout/PageHeader.tsx')
    const html = renderToStaticMarkup(createElement(PageHeader, {
      page: { title: 'Firewall Config Reader', description: '' },
      theme: 'light',
      onToggleTheme() {},
      workspaceMeta: {
        vendorLabel: 'FortiGate FortiOS',
        filename: 'edge.conf',
        activeSection: 'Overview',
      },
      workspaceActions: {
        canSearch: true,
        canAudit: true,
        excelProfile: 'fast',
        exporting: false,
        auditExporting: false,
        onOpenSearch() {},
        onExportAuditReport() {},
        onExcelProfileChange() {},
        onExportExcel() {},
      },
    }))
    assert.ok(html.includes('FortiGate FortiOS'))
    assert.ok(html.includes('edge.conf'))
    assert.ok(html.includes('Ctrl+K'))
    assert.ok(html.includes('Audit Report'))
    assert.ok(html.includes('Export to Excel'))
    assert.ok(html.includes('FAST'))
    assert.ok(html.includes('FULL'))
    assert.ok(!html.includes('color-picker-toggle'))
    assert.ok(!html.includes('zoom-control'))
  } finally {
    await server.close()
  }
})

test('Sidebar renders monochrome section navigation and Load new config footer without Mode selector', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { Sidebar } = await server.ssrLoadModule('/src/components/layout/Sidebar.tsx')
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
  } finally {
    await server.close()
  }
})
