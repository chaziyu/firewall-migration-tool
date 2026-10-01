import { restoreWorkspace, saveWorkspace } from '../../storage/workspaceStore'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { useEffect, useRef, useState } from 'react'
import { Button } from '../../components/common/Button'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { LoadingState } from '../../components/common/LoadingState'
import { FileUpload } from './FileUpload'
import { SourceReport } from '../report/SourceReport'
import { downloadSourceWorkbook, importCollectionSnapshot, loadSourceVendors, previewSource } from './sourceApi'
import type { SourcePreviewData, SourceVendor, SourceVendorOption } from './types'
import { SourceOverview } from './SourceOverview'
import { VendorSelect } from './VendorSelect'
import { LiveCollection, type CollectionResult } from './LiveCollection'
import { MigrationWorkflow } from '../migration/MigrationWorkflow'
import { MigrationReview } from '../migration/MigrationReview'
import type { MigrationDecisionDocument } from '../migration/types'
import { asRecord } from '../report/reportPresentation'

export type WorkflowView = 'report' | 'collect' | 'migration' | 'live'

export function SourceConfiguration({ view, onViewChange }: {
  view: WorkflowView
  onViewChange: (view: WorkflowView) => void
}) {
  const [vendor, setVendor] = useState<SourceVendor>('')
  const [vendors, setVendors] = useState<SourceVendorOption[]>([])
  const [vendorsLoading, setVendorsLoading] = useState(true)
  const [vendorsError, setVendorsError] = useState<string | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<SourcePreviewData | null>(null)
  const previewId = preview?.source_digest || (preview?.source_evidence ? JSON.stringify(preview.source_evidence) : '')
  const [decisionDocument, setDecisionDocument] = useState<MigrationDecisionDocument | null>(null)
  const [targetSource, setTargetSource] = useState<SourceEvidence | null>(null)
  const [workspaceReady, setWorkspaceReady] = useState(false)
  const [targetDevice, setTargetDevice] = useState('')
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [excelProfile, setExcelProfile] = useState<'fast' | 'full'>('fast')
  const [ingestMode, setIngestMode] = useState<'config' | 'snapshot'>('config')
  const [error, setError] = useState<string | null>(null)
  const [migrationVisited, setMigrationVisited] = useState(false)
  const [migrationView, setMigrationView] = useState<'mappings' | 'plan'>('mappings')
  const [requestedDecision, setRequestedDecision] = useState<{ key: string; request: number } | null>(null)
  const analysisRequest = useRef(0)

  if ((view === 'migration' || view === 'live') && !migrationVisited) setMigrationVisited(true)

  useEffect(() => () => { analysisRequest.current++ }, [])

  useEffect(() => {
    loadSourceVendors()
      .then((availableVendors) => {
        setVendors(availableVendors)
        setVendor((current) => current || availableVendors[0]?.vendor_id || '')
      })
      .catch((cause) => setVendorsError(cause instanceof Error ? cause.message : 'Could not load vendors'))
      .finally(() => setVendorsLoading(false))
  }, [])

  useEffect(() => {
    let active = true
    restoreWorkspace().then((saved) => {
      if (!active) return
      if (saved.preview) { setPreview(saved.preview); setVendor(saved.preview.vendor || ''); setDecisionDocument(saved.decisionDocument); setTargetSource(saved.targetSource); setTargetDevice(saved.targetDevice) }
    }).catch((cause) => { if (active) setError(`Workspace restore failed: ${String(cause)}`) })
      .finally(() => { if (active) setWorkspaceReady(true) })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (workspaceReady) void saveWorkspace({ preview, decisionDocument, targetSource, targetDevice }).catch((cause) => setError(`Workspace save failed: ${String(cause)}`))
  }, [workspaceReady, preview, decisionDocument, targetSource, targetDevice])

  async function analyse(sourceFile = file) {
    if (!sourceFile) return
    const request = ++analysisRequest.current
    setLoading(true)
    setError(null)
    try {
      const result = await previewSource(sourceFile, vendor)
      if (request !== analysisRequest.current) return
      setPreview({ ...result, vendor: result.vendor || vendor, acquisition: 'Uploaded configuration' })
      setDecisionDocument(null)
      setTargetSource(null)
      setTargetDevice('')
    } catch (cause) {
      if (request !== analysisRequest.current) return
      setError(cause instanceof Error ? cause.message : 'Analysis failed')
    } finally {
      if (request === analysisRequest.current) setLoading(false)
    }
  }

  function clearAnalysis() {
    analysisRequest.current++
    void saveWorkspace({ designSession: null, deterministicDraft: null, artifact: null }).catch((cause) => setError(String(cause)))
    setLoading(false)
    setMigrationVisited(false)
    setMigrationView('mappings')
    setRequestedDecision(null)
    setPreview(null)
    setDecisionDocument(null)
    setTargetSource(null)
    setTargetDevice('')
  }

  function updateFile(nextFile: File | null) {
    setFile(nextFile)
    clearAnalysis()
    setError(null)
    if (nextFile) void analyse(nextFile)
  }

  function changeVendor(nextVendor: SourceVendor) {
    if (nextVendor === vendor) return
    setVendor(nextVendor)
    setFile(null)
    clearAnalysis()
    setError(null)
  }

  function acceptCollection(result: CollectionResult) {
    clearAnalysis()
    setError(null)
    const collectedVendor = result.vendor_id || result.collection.vendor || vendor
    setVendor(collectedVendor)
    setPreview({ ...result.preview, source_evidence: result.snapshot, vendor: collectedVendor, collection: result.collection, acquisition: 'Live collection' })
    setFile(null)
    onViewChange('report')
  }

  async function exportWorkbook() {
    if (!previewId) return
    setExporting(true)
    setError(null)
    try {
      const blob = await downloadSourceWorkbook(vendor, preview!.source_evidence!, excelProfile)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${vendor}-source-report.xlsx`
      link.click()
      URL.revokeObjectURL(url)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Workbook export failed')
    } finally {
      setExporting(false)
    }
  }

  async function importSnapshot(file: File | undefined) {
    if (!file) return
    clearAnalysis()
    const request = ++analysisRequest.current
    setLoading(true)
    setError(null)
    try {
      const result = await importCollectionSnapshot(file)
      if (request !== analysisRequest.current) return
      setVendor(result.vendor_id)
      setFile(null)
      setPreview({ ...result.preview, source_evidence: result.snapshot, vendor: result.vendor_id, collection: result.collection, acquisition: 'Imported collection snapshot' })
    } catch (cause) {
      if (request !== analysisRequest.current) return
      setError(cause instanceof Error ? cause.message : 'Snapshot import failed')
    } finally {
      if (request === analysisRequest.current) setLoading(false)
    }
  }

  const selectedVendor = vendors.find((item) => item.vendor_id === vendor)

  if (!workspaceReady) return <LoadingState label="Restoring browser workspace…" />
  return <main className="feature-content">
    <section id="source-configuration" className="panel source-configuration" hidden={view !== 'collect' && Boolean(preview)} aria-labelledby="source-title">
      <h2 id="source-title"><span className="step-num">01</span> Source configuration</h2>
      <div className={`source-vendor-grid${view === 'migration' || view === 'live' ? ' with-target' : ''}`}>
        <VendorSelect value={vendor} onChange={changeVendor} vendors={vendors} />
        {(view === 'migration' || view === 'live') && <label className="field"><span>Target platform</span><span className="vendor-select-wrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 17l10 5 10-5" /></svg><select className="vendor-select" value="palo_alto" disabled><option value="palo_alto">Palo Alto Networks</option></select></span></label>}
      </div>
      {vendorsLoading && <LoadingState label="Loading vendors…" />}
      {vendorsError && <ErrorBanner message={vendorsError} />}
      {view === 'collect' ? <>{selectedVendor?.live_collection ? <LiveCollection key={vendor} vendor={selectedVendor} onCollected={acceptCollection} /> : !vendorsLoading && <p>Live collection is not available for this vendor.</p>}</> : <>
        {!preview && <><div className="ingest-tabs" role="tablist" aria-label="Configuration source">
          <button className={`ingest-tab-btn${ingestMode === 'config' ? ' active' : ''}`} role="tab" aria-selected={ingestMode === 'config'} type="button" onClick={() => setIngestMode('config')}>↑ Upload Config</button>
          <button className={`ingest-tab-btn${ingestMode === 'snapshot' ? ' active' : ''}`} role="tab" aria-selected={ingestMode === 'snapshot'} type="button" onClick={() => setIngestMode('snapshot')}>▤ Upload Snapshot</button>
        </div>
        {ingestMode === 'config' ? selectedVendor && <FileUpload key={vendor} file={file} onChange={updateFile} accept={selectedVendor.file_extensions.join(',')} /> : <FileUpload key="snapshot" file={null} onChange={(snapshot) => { if (snapshot) void importSnapshot(snapshot) }} accept=".json,application/json" disabled={loading} title="Drop your collection snapshot here" helpText="Import a previously collected, sanitized snapshot (.json)" />}</>}
        {preview && <SourceOverview vendor={vendor} vendorName={selectedVendor?.display_name ?? ''} file={file} preview={preview} />}
        {loading && <LoadingState label="Reading configuration and preparing the inventory…" />}
      </>}
    </section>

    <div className="workflow-panel" hidden={view !== 'report'}>
      {preview && <SourceReport key={previewId} data={preview}
        excelProfile={excelProfile}
        onExcelProfileChange={(value) => setExcelProfile(value)}
        exporting={exporting}
        onExport={() => void exportWorkbook()} />}
    </div>

    <div className="workflow-panel" hidden={view !== 'collect'}>
      {preview && <div className="report-actions"><p className="report-source-context">{selectedVendor?.display_name ?? vendor} · Live collection</p><label className="excel-profile">Excel profile<select value={excelProfile} onChange={(event) => setExcelProfile(event.target.value as 'fast' | 'full')}><option value="fast">FAST</option><option value="full">FULL</option></select></label><Button disabled={exporting || !previewId} onClick={() => void exportWorkbook()}>{exporting ? 'Preparing workbook…' : 'Export to Excel'}</Button></div>}
    </div>

    <div className="workflow-panel" hidden={view !== 'migration' && view !== 'live'}>
      {preview && previewId && vendor === 'fortigate' ? migrationVisited && <>
        {view === 'live' && <div className="report-source-context">
          <strong>{selectedVendor?.display_name ?? vendor} → PAN-OS</strong>
          {file && <span className="report-source-item report-source-filename">{file.name}</span>}
          <span>{String(preview.acquisition ?? 'Uploaded configuration')}</span>
          {preview.collection != null && <span>Collection: {String(asRecord(preview.collection).status ?? 'Unknown')}</span>}
        </div>}
        {view === 'migration' && <nav className="migration-view-nav" aria-label="Migration workspace">
          <button className={migrationView === 'mappings' ? 'active' : ''} type="button" onClick={() => setMigrationView('mappings')}>Design review</button>
          <button className={migrationView === 'plan' ? 'active' : ''} type="button" disabled={!decisionDocument} onClick={() => setMigrationView('plan')}>Review plan</button>
        </nav>}
        <section hidden={view !== 'migration' || migrationView !== 'mappings'}>
        <MigrationReview key={previewId} preview={preview} vendor={vendor} requestedDecision={requestedDecision}
          onDecisionDocument={setDecisionDocument}
          onContextChange={(nextSource, nextDevice) => { setTargetSource(nextSource); setTargetDevice(nextDevice) }} />
        </section>
        <div hidden={view === 'migration' && migrationView !== 'plan'}>
        {decisionDocument && <MigrationWorkflow key={`${previewId}:${JSON.stringify(targetSource)}:${targetDevice}:${JSON.stringify(decisionDocument)}`}
          preview={preview} decisionDocument={decisionDocument}
          targetSource={targetSource} targetDevice={targetDevice} activeSection={view === 'live' ? 'live' : 'plan'}
          onReviewDecision={(key) => { setRequestedDecision({ key, request: Date.now() }); setMigrationView('mappings'); onViewChange('migration'); requestAnimationFrame(() => document.getElementById('migration-review-title')?.scrollIntoView({ block: 'start' })) }}
          onViewChange={onViewChange} />}
        </div>
        {!decisionDocument && view === 'live' && <section className="panel"><h2>Migration plan required</h2><p>Review source mappings and generate a plan before preparing a target candidate.</p><Button onClick={() => onViewChange('migration')}>Open plan migration</Button></section>}
      </> : <section className="panel"><h2>Migration source required</h2><p>Load a FortiGate source configuration in Configuration report before planning migration.</p><Button onClick={() => onViewChange('report')}>Open configuration report</Button></section>}
    </div>
    {error && <ErrorBanner message={error} />}
  </main>
}
