import { restoreWorkspace, saveWorkspace } from '../../storage/workspaceStore'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '../../components/common/Button'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { LoadingState } from '../../components/common/LoadingState'
import type { WorkspaceTopbarActions } from '../../components/layout/PageHeader'
import { FileUpload } from './FileUpload'
import { SourceReport } from '../report/SourceReport'
import { QuickSearchModal } from '../report/QuickSearchModal'
import { downloadSecurityAuditReport, downloadSourceWorkbook, previewSource } from './sourceApi'
import { detectUploadKind } from './autoDetect'
import type { SourcePreviewData, SourceVendor } from './types'
import { saveBlobWithFallback } from '../../utils/desktop'
import { ConfigChatWidget } from '../chat/ConfigChatWidget'

export type WorkflowView = 'report' | 'collect' | 'migration'

const MAX_CONFIG_UPLOAD_BYTES = 50 * 1024 * 1024

export function SourceConfiguration({
  liveDeviceAccess = false,
  onWorkspaceActionsChange,
}: {
  view?: WorkflowView
  liveDeviceAccess?: boolean
  onViewChange?: (view: WorkflowView) => void
  onWorkspaceActionsChange?: (actions: WorkspaceTopbarActions | null) => void
}) {
  const [vendor, setVendor] = useState<SourceVendor>('')
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<SourcePreviewData | null>(null)
  const previewId = useMemo(
    () => preview?.source_digest || (preview?.source_evidence ? JSON.stringify(preview.source_evidence) : ''),
    [preview],
  )
  const [workspaceReady, setWorkspaceReady] = useState(false)
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [auditExporting, setAuditExporting] = useState(false)
  const [exportStatus, setExportStatus] = useState('')
  const [exportError, setExportError] = useState<string | null>(null)
  const [excelProfiles, setExcelProfiles] = useState<Record<string, 'fast' | 'full'>>({})
  const excelProfile = excelProfiles[vendor] ?? (vendor === 'palo_alto' ? 'full' : 'fast')
  const setExcelProfile = useCallback(
    (profile: 'fast' | 'full') => setExcelProfiles((current) => ({ ...current, [vendor]: profile })),
    [vendor],
  )
  const [error, setError] = useState<string | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const analysisRequest = useRef(0)
  const exportRequest = useRef(0)
  const exportController = useRef<AbortController | null>(null)

  useEffect(() => () => {
    analysisRequest.current++
    exportRequest.current++
    exportController.current?.abort()
  }, [])

  useEffect(() => {
    let active = true
    restoreWorkspace()
      .then((saved) => {
        if (!active) return
        if (saved.preview && (saved.preview.vendor === 'fortigate' || saved.preview.vendor === 'palo_alto')) {
          setPreview(saved.preview)
          setVendor(saved.preview.vendor)
        }
      })
      .catch((cause) => {
        if (active) setError(`Workspace restore failed: ${String(cause)}`)
      })
      .finally(() => {
        if (active) setWorkspaceReady(true)
      })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (workspaceReady) {
      void saveWorkspace({ preview }).catch((cause) => setError(`Workspace save failed: ${String(cause)}`))
    }
  }, [workspaceReady, preview])

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.dispatchEvent !== 'function') return
    if (!preview) {
      window.dispatchEvent(new CustomEvent('fw-workspace-meta', { detail: null }))
    }
  }, [preview])

  const canSearchAndAudit = Boolean(
    preview?.source_evidence && (vendor === 'fortigate' || vendor === 'palo_alto'),
  )

  useEffect(() => {
    if (!canSearchAndAudit || typeof document === 'undefined') return
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setSearchOpen((current) => !current)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [canSearchAndAudit])

  async function analyse(sourceFile = file) {
    if (!sourceFile) return
    const detected = detectUploadKind(sourceFile.name)
    if (detected === 'tsf') {
      setError(
        'Palo Alto TSF (.zip) Explorer is scheduled for Phase 5. Upload a FortiGate (.conf, .cfg, .txt) or Palo Alto PAN-OS (.xml) configuration.',
      )
      return
    }
    if (detected === 'unknown') {
      setError(
        'Unsupported file type. Upload a FortiGate (.conf, .cfg, .txt) or Palo Alto PAN-OS (.xml) configuration.',
      )
      return
    }

    const request = ++analysisRequest.current
    setLoading(true)
    setError(null)
    try {
      const result = await previewSource(sourceFile, 'auto')
      if (request !== analysisRequest.current) return
      const resolvedVendor = result.vendor || (detected === 'palo_alto' ? 'palo_alto' : 'fortigate')
      setVendor(resolvedVendor)
      setPreview({ ...result, vendor: resolvedVendor, acquisition: 'Uploaded configuration' })
    } catch (cause) {
      if (request !== analysisRequest.current) return
      setError(cause instanceof Error ? cause.message : 'Analysis failed')
    } finally {
      if (request === analysisRequest.current) setLoading(false)
    }
  }

  function clearAnalysis() {
    exportController.current?.abort()
    exportController.current = null
    setExportStatus('')
    setExportError(null)
    setExporting(false)
    setAuditExporting(false)
    setSearchOpen(false)
    exportRequest.current++
    analysisRequest.current++
    void saveWorkspace({ deterministicDraft: null, artifact: null }).catch((cause) => setError(String(cause)))
    setLoading(false)
    setPreview(null)
  }

  function updateFile(nextFile: File | null) {
    setFile(nextFile)
    clearAnalysis()
    setError(null)
    if (nextFile) void analyse(nextFile)
  }

  const exportWorkbook = useCallback(async () => {
    if (!previewId || !preview?.source_evidence) return
    const request = analysisRequest.current
    const exportId = ++exportRequest.current
    exportController.current?.abort()
    const controller = new AbortController()
    exportController.current = controller
    const current = () => request === analysisRequest.current && exportId === exportRequest.current
    setExporting(true)
    setExportStatus('')
    setExportError(null)
    try {
      const blob = await downloadSourceWorkbook(vendor, preview.source_evidence, excelProfile, controller.signal)
      if (!current()) return
      const rawSource = String(preview.source_evidence.source_name || file?.name || '')
      const stem = rawSource
        .replace(/^.*[\\/]/, '')
        .replace(/\.[^.]+$/, '')
        .replace(/[^A-Za-z0-9._-]+/g, '_')
        .replace(/^_+|_+$/g, '')
      const targetName = stem ? `${stem}-${vendor}-report.xlsx` : `${vendor}-source-report.xlsx`
      const result = await saveBlobWithFallback(blob, targetName)
      if (!current()) return
      if (result.status === 'cancelled') setExportStatus('Workbook export cancelled.')
      else if (result.status === 'saved') setExportStatus(`${vendor} ${excelProfile.toUpperCase()} workbook saved to Downloads: ${result.path || result.filename}.`)
      else setExportStatus(`${vendor} ${excelProfile.toUpperCase()} workbook ready. Download started: ${result.filename}.`)
    } catch (cause) {
      if (current() && !controller.signal.aborted) setExportError(cause instanceof Error ? cause.message : 'Workbook export failed')
    } finally {
      if (current()) {
        setExporting(false)
        exportController.current = null
      }
    }
  }, [previewId, preview, vendor, excelProfile, file])

  const exportAuditReport = useCallback(async () => {
    if (!preview?.source_evidence || !canSearchAndAudit) return
    setAuditExporting(true)
    setExportError(null)
    setExportStatus('')
    try {
      const blob = await downloadSecurityAuditReport(vendor, preview.source_evidence)
      const rawName = String(preview.source_evidence.source_name || file?.name || vendor || 'firewall')
      const stem = rawName.replace(/^.*[\\/]/, '').replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9._-]+/g, '_')
      const result = await saveBlobWithFallback(blob, `${stem || vendor}_security_audit_report.html`)
      if (result.status === 'cancelled') setExportStatus('Audit report export cancelled.')
      else if (result.status === 'saved') setExportStatus(`Audit report saved to Downloads: ${result.path || result.filename}.`)
      else setExportStatus(`Audit report ready (${result.filename}) — open in browser to view or Print to PDF.`)
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : 'Audit report export failed')
    } finally {
      setAuditExporting(false)
    }
  }, [preview, canSearchAndAudit, vendor, file])

  useEffect(() => {
    if (!onWorkspaceActionsChange) return
    if (!preview) {
      onWorkspaceActionsChange(null)
      return
    }
    onWorkspaceActionsChange({
      canSearch: canSearchAndAudit,
      canAudit: canSearchAndAudit,
      excelProfile,
      exporting,
      auditExporting,
      onOpenSearch: () => setSearchOpen(true),
      onExportAuditReport: () => void exportAuditReport(),
      onExcelProfileChange: setExcelProfile,
      onExportExcel: () => void exportWorkbook(),
    })
  }, [
    onWorkspaceActionsChange,
    preview,
    canSearchAndAudit,
    excelProfile,
    exporting,
    auditExporting,
    exportAuditReport,
    setExcelProfile,
    exportWorkbook,
  ])

  useEffect(() => () => {
    onWorkspaceActionsChange?.(null)
  }, [onWorkspaceActionsChange])

  if (!workspaceReady) return <LoadingState label="Restoring browser workspace…" />

  const vendorDisplay = vendor === 'palo_alto' ? 'Palo Alto PAN-OS' : vendor === 'fortigate' ? 'FortiGate FortiOS' : 'Firewall'

  return (
    <main className="feature-content">
      {!preview && (
        <section id="source-configuration" className="panel source-configuration fw-landing-panel" aria-label="Source configuration">
          <div className="fw-landing-header">
            <div className="fw-landing-eyebrow">Firewall Analysis Console</div>
            <h2 className="fw-landing-title">Inspect firewall configurations</h2>
            <p className="fw-landing-desc">
              Drop a Palo Alto PAN-OS XML backup, FortiGate FortiOS configuration, or Technical Support File archive to audit policies, objects, interfaces, VPNs, and security posture.
            </p>
          </div>

          <div className="fw-vendor-grid" aria-label="Supported configuration formats">
            <div className="vendor-card">
              <div className="vendor-card-head">
                <div>
                  <h3>Palo Alto Networks</h3>
                  <p>PAN-OS XML running or backup configs</p>
                </div>
                <span className="fw-badge fw-badge-info">PAN-OS</span>
              </div>
              <div className="vendor-card-meta">
                <span className="fw-badge fw-badge-info">PAN-OS 10.x+</span>
                <span className="fw-badge fw-badge-muted">.xml</span>
                <span className="fw-badge fw-badge-muted">Max 50 MB</span>
              </div>
            </div>

            <div className="vendor-card">
              <div className="vendor-card-head">
                <div>
                  <h3>FortiGate</h3>
                  <p>FortiOS CLI configuration exports</p>
                </div>
                <span className="fw-badge fw-badge-warn">FortiOS</span>
              </div>
              <div className="vendor-card-meta">
                <span className="fw-badge fw-badge-warn">FortiOS 6.x / 7.x</span>
                <span className="fw-badge fw-badge-muted">.conf · .cfg · .txt</span>
                <span className="fw-badge fw-badge-muted">Max 50 MB</span>
              </div>
            </div>

            <div className="vendor-card">
              <div className="vendor-card-head">
                <div>
                  <h3>Palo Alto TSF</h3>
                  <p>Technical Support File log archives</p>
                </div>
                <span className="fw-badge fw-badge-muted">Phase 5</span>
              </div>
              <div className="vendor-card-meta">
                <span className="fw-badge fw-badge-muted">Tree &amp; Full-Text Search</span>
                <span className="fw-badge fw-badge-muted">.zip</span>
              </div>
            </div>
          </div>

          <FileUpload
            maxBytes={MAX_CONFIG_UPLOAD_BYTES}
            file={file}
            onChange={updateFile}
            accept=".xml,.conf,.cfg,.txt,.zip"
            title="Drop configuration file (.xml, .conf, .cfg, .txt) or TSF archive (.zip)"
            helpText="Automatic vendor detection for FortiGate and Palo Alto PAN-OS · Config files up to 50 MB"
          >
            {loading ? (
              <LoadingState label="Detecting vendor and preparing configuration inventory…" />
            ) : error ? (
              <>
                <ErrorBanner message={error} />
                <Button type="button" className="text-button" onClick={() => void analyse()}>Retry</Button>
              </>
            ) : null}
          </FileUpload>

          <p className="fw-landing-caption">
            Files are processed in ephemeral session memory and cleared automatically when the workspace resets or expires.
          </p>
        </section>
      )}

      {preview && (
        <div className="workflow-panel">
          <SourceReport
            key={previewId}
            data={preview}
            liveDeviceAccess={liveDeviceAccess}
            excelProfile={excelProfile}
            onExcelProfileChange={setExcelProfile}
            exporting={exporting}
            exportStatus={exportStatus}
            exportError={exportError}
            onExport={() => void exportWorkbook()}
          />
        </div>
      )}

      {error && preview && <ErrorBanner message={error} />}

      {preview && canSearchAndAudit && preview.source_evidence && (
        <QuickSearchModal
          open={searchOpen}
          onClose={() => setSearchOpen(false)}
          vendor={vendor}
          sourceEvidence={preview.source_evidence}
        />
      )}

      {preview && (
        <ConfigChatWidget
          vendor={vendorDisplay}
          filename={String(preview.source_evidence?.source_name || file?.name || 'config')}
          preview={preview}
        />
      )}
    </main>
  )
}
