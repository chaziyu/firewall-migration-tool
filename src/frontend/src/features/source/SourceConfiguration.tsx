import { restoreWorkspace, saveWorkspace, workspace } from '../../storage/workspaceStore'
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
import type { MigrationStage, MigrationDecisionDocument } from '../migration/types'
import { postJson } from '../../api/client'
import { download } from '../migration/download'
import type { MigrationDraft } from '../migration/types'
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
  const [exportStatus, setExportStatus] = useState('')
  const [excelProfile, setExcelProfile] = useState<'fast' | 'full'>('fast')
  const [ingestMode, setIngestMode] = useState<'config' | 'snapshot'>('config')
  const [error, setError] = useState<string | null>(null)
  const [projectBusy, setProjectBusy] = useState(false)
  const [projectNotice, setProjectNotice] = useState('')
  const [projectRevision, setProjectRevision] = useState(0)
  const [migrationVisited, setMigrationVisited] = useState(false)
  const [migrationView, setMigrationView] = useState<MigrationStage>('load')
  const [generationRequest, setGenerationRequest] = useState(0)
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
      if (saved.preview) { setPreview(saved.preview); setVendor(saved.preview.vendor || ''); setExcelProfile(saved.preview.vendor === 'palo_alto' ? 'full' : 'fast'); setDecisionDocument(saved.decisionDocument); setTargetSource(saved.targetSource); setTargetDevice(saved.targetDevice) }
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
    setExportStatus('')
    analysisRequest.current++
    void saveWorkspace({ deterministicDraft: null, artifact: null }).catch((cause) => setError(String(cause)))
    setLoading(false)
    setMigrationVisited(false)
    setMigrationView('load')
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
    setExcelProfile(nextVendor === 'palo_alto' ? 'full' : 'fast')
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
    const request = analysisRequest.current
    setExporting(true)
    setExportStatus('')
    setError(null)
    try {
      const blob = await downloadSourceWorkbook(vendor, preview!.source_evidence!, excelProfile)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${vendor}-source-report.xlsx`
      link.click()
      URL.revokeObjectURL(url)
      if (request === analysisRequest.current) setExportStatus(`Excel workbook ready. Download started: ${link.download}.`)
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

  async function downloadProject() {
    if (!preview?.source_evidence) return
    setProjectBusy(true); setError(null)
    try {
      const saved = workspace()
      const proposed = { ...Object.fromEntries((saved.deterministicDraft?.decisions ?? []).filter((row) => row.proposed_value).map((row) => [row.decision_key!, row.proposed_value!])), ...saved.proposals }
      const result = await postJson<{ project: unknown }>('/api/migration/project/export', {
        source: preview.source_evidence, target_source: saved.targetSource,
        target_device: saved.targetDevice, reference_role: saved.referenceRole,
        workflow_mode: saved.workflowMode ?? 'offline',
        proposals: Object.fromEntries(Object.entries(proposed).filter(([, value]) => value.trim())),
        service_names: saved.serviceNames ?? saved.deterministicDraft?.context.service_names ?? {},
      })
      download(JSON.stringify(result.project, null, 2), 'migration-project.json', 'application/json')
      setProjectNotice('Project downloaded. It contains sanitized customer topology and proposals; keep it secure. Approval and candidate authority are excluded.')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Project export failed') }
    finally { setProjectBusy(false) }
  }

  async function resumeProject(file: File | undefined) {
    if (!file) return
    const request = ++analysisRequest.current
    setProjectBusy(true); setError(null)
    try {
      if (file.size > 51_000_000) throw new Error('Project exceeds the 51 MB size limit.')
      const result = await postJson<{
        project: { target_source: SourceEvidence | null; target_device: string; reference_role: 'DESTINATION' | 'TEMPLATE'; workflow_mode: 'offline' | 'destination'; proposals: Record<string, string>; service_names: Record<string, Record<string, string>> }
        preview: SourcePreviewData; review: { draft: MigrationDraft; decision_document: MigrationDecisionDocument }
        unmatched_entries: string[]; notice: string
      }>('/api/migration/project/import', JSON.parse(await file.text()))
      if (request !== analysisRequest.current) return
      // Publish only after backend schema validation, redaction and reparsing succeed.
      await saveWorkspace({ preview: result.preview, targetSource: result.project.target_source,
        targetDevice: result.project.target_device, referenceRole: result.project.reference_role,
        workflowMode: result.project.workflow_mode, proposals: result.project.proposals,
        serviceNames: result.project.service_names, decisionDocument: result.review.decision_document,
        deterministicDraft: result.review.draft, artifact: null })
      setPreview(result.preview); setVendor('fortigate'); setFile(null)
      setTargetSource(result.project.target_source); setTargetDevice(result.project.target_device)
      setDecisionDocument(result.review.decision_document); setGenerationRequest(0)
      setProjectRevision((value) => value + 1); setMigrationView('load'); setMigrationVisited(true)
      setProjectNotice(`${result.notice} ${result.unmatched_entries.length} unmatched entries excluded.${result.unmatched_entries.length ? ` ${result.unmatched_entries.slice(0, 10).join(', ')}` : ''}`)
      onViewChange('migration')
    } catch (cause) { if (request === analysisRequest.current) setError(cause instanceof Error ? cause.message : 'Project import failed; current workspace is unchanged.') }
    finally { setProjectBusy(false) }
  }

  const selectedVendor = vendors.find((item) => item.vendor_id === vendor)

  if (!workspaceReady) return <LoadingState label="Restoring browser workspace…" />
  return <main className="feature-content">
    {(view === 'migration' || view === 'live') && <section className="panel" aria-label="Migration project files">
      <p>Work stays in memory. Refresh closes this project; download it to resume later. Project files contain sanitized customer topology.</p>
      <div className="migration-toolbar"><Button disabled={projectBusy || !preview?.source_evidence || vendor !== 'fortigate'} onClick={() => void downloadProject()}>Download project</Button>
      <label className="field">Resume project<input type="file" accept=".json,application/json" disabled={projectBusy} onChange={(event) => { const selected = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void resumeProject(selected) }} /></label></div>
      {projectNotice && <p role="status">{projectNotice}</p>}
    </section>}
    <section id="source-configuration" className="panel source-configuration" hidden={view !== 'collect' && Boolean(preview) && !(file && view === 'report')} aria-labelledby="source-title">
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
        </div></>}
        {ingestMode === 'config' ? selectedVendor && <FileUpload key={vendor} file={file} onChange={updateFile} description={selectedVendor.display_name} accept={selectedVendor.file_extensions.join(',')}>
          {loading ? <LoadingState label="Reading configuration and preparing the inventory…" /> : preview ? <span className="selected-file-success" role="status"><span aria-hidden="true">✓ </span>Configuration loaded</span> : error && <><ErrorBanner message={error} /><Button type="button" className="text-button" onClick={() => void analyse()}>Retry</Button></>}
        </FileUpload> : !preview && <FileUpload key="snapshot" file={null} onChange={(snapshot) => { if (snapshot) void importSnapshot(snapshot) }} accept=".json,application/json" disabled={loading} title="Drop your collection snapshot here" helpText="Import a previously collected, sanitized snapshot (.json)" />}
        {preview && !file && <SourceOverview vendor={vendor} vendorName={selectedVendor?.display_name ?? ''} file={file} preview={preview} />}
        {loading && (ingestMode !== 'config' || !file) && <LoadingState label="Reading configuration and preparing the inventory…" />}
      </>}
    </section>

    <div className="workflow-panel" hidden={view !== 'report'}>
      {preview && <SourceReport key={previewId} data={preview}
        excelProfile={excelProfile}
        onExcelProfileChange={(value) => setExcelProfile(value)}
        exporting={exporting}
        exportStatus={exportStatus}
        onExport={() => void exportWorkbook()} />}
    </div>

    <div className="workflow-panel" hidden={view !== 'collect'}>
      <p className="preview-status" role="status" aria-live="polite">{exportStatus}</p>
      {preview && <div className="report-actions"><p className="report-source-context">{selectedVendor?.display_name ?? vendor} · Live collection</p><label className="excel-profile">Excel profile<select value={excelProfile} onChange={(event) => setExcelProfile(event.target.value as 'fast' | 'full')}><option value="fast">FAST (omits technical evidence sheets)</option><option value="full">FULL</option></select></label><Button disabled={exporting || !previewId} onClick={() => void exportWorkbook()}>{exporting ? 'Preparing workbook…' : 'Export to Excel'}</Button></div>}
    </div>

    <div className="workflow-panel" hidden={view !== 'migration' && view !== 'live'}>
      {preview && previewId && vendor === 'fortigate' ? migrationVisited && <>
        {view === 'live' && <div className="report-source-context">
          <strong>{selectedVendor?.display_name ?? vendor} → PAN-OS</strong>
          {file && <span className="report-source-item report-source-filename">{file.name}</span>}
          <span>{String(preview.acquisition ?? 'Uploaded configuration')}</span>
          {preview.collection != null && <span>Collection: {String(asRecord(preview.collection).status ?? 'Unknown')}</span>}
        </div>}
        {view === 'migration' && <div className="report-source-context"><strong>FortiGate → PAN-OS</strong><span>{preview.source_evidence?.source_name || file?.name || 'Loaded source configuration'}</span><span>Destination: {targetDevice || 'Not selected'}</span></div>}
        {view === 'migration' && <nav className="migration-view-nav" aria-label="Migration workspace">
          {([['load', 'Load configurations'], ['place', 'Place configuration'], ['exceptions', 'Resolve exceptions'], ['review', 'Review changes'], ['export', 'Export or deploy']] as const).map(([stage, label], index) =>
            <button key={stage} type="button" aria-current={migrationView === stage ? 'step' : undefined} onClick={() => setMigrationView(stage)}>{index + 1}. {label}</button>)}
        </nav>}
        <section hidden={view !== 'migration' || migrationView === 'export'}>
        <MigrationReview key={`${previewId}:${projectRevision}`} preview={preview} vendor={vendor} requestedDecision={requestedDecision}
          stage={migrationView} onStageChange={setMigrationView}
          onApproved={() => { setGenerationRequest((value) => value + 1); setMigrationView('export') }}
          onDecisionDocument={setDecisionDocument}
          onContextChange={(nextSource, nextDevice) => { setTargetSource(nextSource); setTargetDevice(nextDevice) }} />
        </section>
        <div hidden={view === 'migration' && migrationView !== 'export'}>
        <MigrationWorkflow key={`${previewId}:${projectRevision}`}
          preview={preview} decisionDocument={decisionDocument}
          targetSource={targetSource} targetDevice={targetDevice} generationRequest={generationRequest} activeSection={view === 'live' ? 'live' : 'plan'}
          onReviewDecision={(key) => { setRequestedDecision({ key, request: Date.now() }); setMigrationView('place'); onViewChange('migration'); requestAnimationFrame(() => document.getElementById('migration-review-title')?.scrollIntoView({ block: 'start' })) }}
           onViewChange={onViewChange} />
        </div>
        {!decisionDocument && view === 'live' && <section className="panel"><h2>Migration plan required</h2><p>Review source mappings and generate a plan before preparing a target candidate.</p><Button onClick={() => onViewChange('migration')}>Open plan migration</Button></section>}
      </> : !loading && <section className="panel"><h2>Migration source required</h2><p>Upload a FortiGate configuration above to start planning. Configuration report also accepts the same source.</p><Button onClick={() => onViewChange('report')}>Open configuration report</Button></section>}
    </div>
    {error && !(file && !preview && ingestMode === 'config' && view !== 'collect') && <ErrorBanner message={error} />}
  </main>
}
