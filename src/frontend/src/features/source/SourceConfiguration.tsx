import { restoreWorkspace, saveWorkspace } from '../../storage/workspaceStore'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { useEffect, useRef, useState } from 'react'
import { Button } from '../../components/common/Button'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { LoadingState } from '../../components/common/LoadingState'
import { FileUpload } from './FileUpload'
import { SourceReport } from '../report/SourceReport'
import { ExcelExportControls } from '../report/ExcelExportControls'
import { downloadSourceWorkbook, importCollectionSnapshot, loadSourceVendors, previewSource } from './sourceApi'
import type { MigrationPairOption, SourcePreviewData, SourceVendor, SourceVendorOption } from './types'
import { SourceOverview } from './SourceOverview'
import { VendorSelect } from './VendorSelect'
import { LiveCollection, type CollectionResult } from './LiveCollection'
import { MigrationWorkflow } from '../migration/MigrationWorkflow'
import { MigrationReview } from '../migration/MigrationReview'
import { FortiGateMigrationWorkflow } from '../migration/paloAltoToFortigate/MigrationWorkflow'
import { loadMigrationPairs } from '../migration/pairApi'
import { MigrationPairWorkflow } from '../migration/MigrationPairWorkflow'
import type { MigrationReviewTab } from '../migration/types'
import type { MigrationStage, MigrationDecisionDocument } from '../migration/types'

export type WorkflowView = 'report' | 'collect' | 'migration' | 'live'

export function SourceConfiguration({ view, onViewChange, liveDeviceAccess }: {
  view: WorkflowView
  liveDeviceAccess: boolean
  onViewChange: (view: WorkflowView) => void
}) {
  const [vendor, setVendor] = useState<SourceVendor>('')
  const [vendors, setVendors] = useState<SourceVendorOption[]>([])
  const [vendorsLoading, setVendorsLoading] = useState(true)
  const [vendorsError, setVendorsError] = useState<string | null>(null)
  const [migrationPairs, setMigrationPairs] = useState<MigrationPairOption[]>([])
  const [migrationPairsLoading, setMigrationPairsLoading] = useState(true)
  const [migrationPairsError, setMigrationPairsError] = useState<string | null>(null)
  const [migrationPairId, setMigrationPairId] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<SourcePreviewData | null>(null)
  const [sourceExpanded, setSourceExpanded] = useState(true)
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
  const [migrationVisited, setMigrationVisited] = useState(false)
  const [migrationView, setMigrationView] = useState<MigrationStage>('load')
  const availableMigrationPairs = migrationPairs.filter((pair) => pair.source_vendor === vendor)
  const preferredPairId = vendor === 'fortigate' ? 'fortigate_to_palo_alto' : 'palo_alto_to_fortigate'
  const selectedMigrationPair = availableMigrationPairs.find((pair) => pair.pair_id === migrationPairId)
    ?? availableMigrationPairs.find((pair) => pair.pair_id === preferredPairId)
    ?? availableMigrationPairs[0]
  const activeMigrationPairId = selectedMigrationPair?.pair_id ?? ''
  const reviewContextKey = JSON.stringify([previewId, activeMigrationPairId, targetSource, targetDevice])
  const [reviewTabState, setReviewTabState] = useState({ contextKey: reviewContextKey, tab: 'changes' as MigrationReviewTab })
  const migrationReviewTab = reviewTabState.contextKey === reviewContextKey ? reviewTabState.tab : 'changes'
  const setMigrationReviewTab = (tab: MigrationReviewTab) => setReviewTabState({ contextKey: reviewContextKey, tab })
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
    loadMigrationPairs()
      .then((available) => setMigrationPairs(available.filter((pair) => pair.export_available)))
      .catch((cause) => setMigrationPairsError(cause instanceof Error ? cause.message : 'Could not load migration targets'))
      .finally(() => setMigrationPairsLoading(false))
  }, [])

  useEffect(() => {
    let active = true
    restoreWorkspace().then((saved) => {
      if (!active) return
      if (saved.preview) { setPreview(saved.preview); setSourceExpanded(false); setVendor(saved.preview.vendor || ''); setExcelProfile(saved.preview.vendor === 'palo_alto' ? 'full' : 'fast'); setDecisionDocument(saved.decisionDocument); setTargetSource(saved.targetSource); setTargetDevice(saved.targetDevice); setMigrationPairId(saved.migrationPairId || ''); setMigrationView(saved.workflowMode === 'destination' ? 'load' : 'place') }
    }).catch((cause) => { if (active) setError(`Workspace restore failed: ${String(cause)}`) })
      .finally(() => { if (active) setWorkspaceReady(true) })
    return () => { active = false }
  }, [])

  useEffect(() => {
    if (workspaceReady && !migrationPairsLoading) void saveWorkspace({ preview, decisionDocument, targetSource, targetDevice, migrationPairId: activeMigrationPairId }).catch((cause) => setError(`Workspace save failed: ${String(cause)}`))
  }, [workspaceReady, migrationPairsLoading, activeMigrationPairId, preview, decisionDocument, targetSource, targetDevice])

  async function analyse(sourceFile = file) {
    if (!sourceFile) return
    const request = ++analysisRequest.current
    setLoading(true)
    setError(null)
    try {
      const result = await previewSource(sourceFile, vendor)
      if (request !== analysisRequest.current) return
      setPreview({ ...result, vendor: result.vendor || vendor, acquisition: 'Uploaded configuration' })
      setSourceExpanded(false)
      setMigrationView('place')
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
    setSourceExpanded(true)
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
    setMigrationPairId('')
    setExcelProfile(nextVendor === 'palo_alto' ? 'full' : 'fast')
    setFile(null)
    clearAnalysis()
    setError(null)
  }

  function changeMigrationPair(nextPairId: string) {
    if (nextPairId === migrationPairId) return
    setMigrationPairId(nextPairId)
    setMigrationView('load')
    setDecisionDocument(null)
    setTargetSource(null)
    setTargetDevice('')
  }

  function acceptCollection(result: CollectionResult) {
    clearAnalysis()
    setError(null)
    const collectedVendor = result.vendor_id || result.collection.vendor || vendor
    setVendor(collectedVendor)
    setPreview({ ...result.preview, source_evidence: result.snapshot, vendor: collectedVendor, collection: result.collection, acquisition: 'Live collection' })
    setSourceExpanded(false)
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
      setSourceExpanded(false)
    } catch (cause) {
      if (request !== analysisRequest.current) return
      setError(cause instanceof Error ? cause.message : 'Snapshot import failed')
    } finally {
      if (request === analysisRequest.current) setLoading(false)
    }
  }

  const selectedVendor = vendors.find((item) => item.vendor_id === vendor)
  const sourceCollapsed = view === 'report' && !!preview && !sourceExpanded && !loading

  if (!workspaceReady) return <LoadingState label="Restoring browser workspace…" />
  if (!liveDeviceAccess && (view === 'collect' || view === 'live')) return <p role="status">Live device access is available only in the local application.</p>
  return <main className="feature-content">
    <section id="source-configuration" className={`panel source-configuration${sourceCollapsed ? ' source-collapsed' : ''}`} hidden={view === 'live' || (view !== 'collect' && Boolean(preview) && view !== 'report' && !(view === 'migration' && migrationView === 'load'))} aria-labelledby="source-title">
      <div className="source-panel-heading">
        <h2 id="source-title" className={sourceCollapsed ? 'visually-hidden' : undefined}><span className="step-num">01</span> Source configuration</h2>
        {sourceCollapsed && <div className="source-compact-summary"><span className="source-loaded" role="status">✓ Configuration loaded</span><strong>{selectedVendor?.display_name || vendor}</strong><span>{preview?.source_evidence?.source_name || file?.name || String(preview?.acquisition || 'Loaded source configuration')}</span></div>}
        {view === 'report' && preview && <Button type="button" className="secondary-button button-compact source-panel-toggle" aria-expanded={!sourceCollapsed} aria-controls="source-configuration-controls" onClick={() => setSourceExpanded((expanded) => !expanded)}>{sourceCollapsed ? 'Change source' : 'Collapse source'}</Button>}
      </div>
      <div id="source-configuration-controls" hidden={sourceCollapsed}>
      <div className={`source-vendor-grid${view === 'migration' || view === 'live' ? ' with-target' : ''}`}>
        <VendorSelect value={vendor} onChange={changeVendor} vendors={vendors} />
        {view === 'migration' && <label className="field"><span>Target platform</span><span className="vendor-select-wrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 17l10 5 10-5" /></svg><select className="vendor-select" value={selectedMigrationPair?.pair_id || ''} disabled={migrationPairsLoading || availableMigrationPairs.length === 0} onChange={(event) => changeMigrationPair(event.target.value)}><option value="" disabled>Choose a target</option>{availableMigrationPairs.map((pair) => <option key={pair.pair_id} value={pair.pair_id}>{pair.display_name}</option>)}</select></span></label>}
        {view === 'live' && <label className="field"><span>Target platform</span><span className="vendor-select-wrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 17l10 5 10-5" /></svg><select className="vendor-select" value={vendor === 'palo_alto' ? 'fortigate' : 'palo_alto'} disabled><option value="palo_alto">Palo Alto Networks</option><option value="fortigate">Fortinet FortiGate</option></select></span></label>}
      </div>
      {vendorsLoading && <LoadingState label="Loading vendors…" />}
      {vendorsError && <ErrorBanner message={vendorsError} />}
      {view === 'migration' && migrationPairsError && <ErrorBanner message={migrationPairsError} />}
      {view === 'collect' ? <>{selectedVendor?.live_collection ? <LiveCollection key={vendor} vendor={selectedVendor} onCollected={acceptCollection} /> : !vendorsLoading && <p>Live collection is not available for this vendor.</p>}</> : <>
        {(!preview || (view === 'report' && sourceExpanded)) && <><div className="ingest-tabs" role="tablist" aria-label="Configuration source">
          <button className={`ingest-tab-btn${ingestMode === 'config' ? ' active' : ''}`} role="tab" aria-selected={ingestMode === 'config'} type="button" onClick={() => setIngestMode('config')}>↑ Upload Config</button>
          <button className={`ingest-tab-btn${ingestMode === 'snapshot' ? ' active' : ''}`} role="tab" aria-selected={ingestMode === 'snapshot'} type="button" onClick={() => setIngestMode('snapshot')}>▤ Upload Snapshot</button>
        </div></>}
        {ingestMode === 'config' ? selectedVendor && <FileUpload key={vendor} file={file} onChange={updateFile} description={selectedVendor.display_name} accept={selectedVendor.file_extensions.join(',')}>
          {loading ? <LoadingState label="Reading configuration and preparing the inventory…" /> : preview ? <span className="selected-file-success" role="status"><span aria-hidden="true">✓ </span>Configuration loaded</span> : error && <><ErrorBanner message={error} /><Button type="button" className="text-button" onClick={() => void analyse()}>Retry</Button></>}
        </FileUpload> : (!preview || (view === 'report' && sourceExpanded)) && <FileUpload key="snapshot" file={null} onChange={(snapshot) => { if (snapshot) void importSnapshot(snapshot) }} accept=".json,application/json" disabled={loading} title="Drop your collection snapshot here" helpText="Import a previously collected, sanitized snapshot (.json)" />}
        {preview && !file && <SourceOverview vendor={vendor} vendorName={selectedVendor?.display_name ?? ''} file={file} preview={preview} />}
        {loading && (ingestMode !== 'config' || !file) && <LoadingState label="Reading configuration and preparing the inventory…" />}
      </>}
      </div>
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
      {preview && <div className="report-actions"><p className="report-source-context">{selectedVendor?.display_name ?? vendor} · Live collection</p><ExcelExportControls vendor={vendor} profile={excelProfile} onProfileChange={setExcelProfile} exporting={exporting} onExport={() => void exportWorkbook()} /></div>}
    </div>

    <div className="workflow-panel" hidden={view !== 'migration' && view !== 'live'}>
      {view === 'migration' && selectedMigrationPair && <section className="panel" aria-label="Selected migration workflow limits">
        <strong>{selectedMigrationPair.display_name}</strong>
        <p>{selectedMigrationPair.mapping_workflow || 'Mapping assistance is not specified. Review target choices explicitly.'}</p>
        <p>{selectedMigrationPair.destination_comparison || 'Destination comparison limits are not specified. Review target evidence before export.'}</p>
        <p>{selectedMigrationPair.execution_mode || 'Execution capabilities are not specified.'}</p>
        {!!selectedMigrationPair.activation_steps?.length && <ul>{selectedMigrationPair.activation_steps.map((step) => <li key={step}>{step}</li>)}</ul>}
      </section>}
      {preview?.source_evidence && previewId && vendor === 'palo_alto' && selectedMigrationPair?.pair_id === 'palo_alto_to_fortigate' && migrationVisited && <div hidden={view !== 'migration'}><FortiGateMigrationWorkflow key={`${selectedMigrationPair.pair_id}:${previewId}`} source={preview.source_evidence} sourceKey={previewId} onStageChange={setMigrationView} onReviewSource={() => onViewChange('report')} /></div>}
      {preview?.source_evidence && previewId && vendor === 'fortigate' && migrationVisited && selectedMigrationPair ? <>
        {view === 'migration' && <div className="report-source-context"><strong>{selectedMigrationPair.display_name}</strong><span>{preview.source_evidence.source_name || file?.name || 'Loaded source configuration'}</span>{selectedMigrationPair.pair_id === 'fortigate_to_palo_alto' && <span>{targetDevice ? `Destination: ${targetDevice}` : 'Destination checks optional for offline export'}</span>}</div>}
        {view === 'migration' && <nav className="migration-view-nav" aria-label="Migration workspace">
          {([['load', 'Source'], ['place', 'Target setup'], ['review', 'Review migration'], ['export', 'Download']] as const).map(([stage, label], index) =>
            <button key={stage} type="button" aria-current={migrationView === stage ? 'step' : undefined} onClick={() => setMigrationView(stage)}>{index + 1}. {label}</button>)}
        </nav>}
        {view === 'migration' && selectedMigrationPair.pair_id !== 'fortigate_to_palo_alto' && <MigrationPairWorkflow pairId={selectedMigrationPair.pair_id} source={preview.source_evidence} sourceKey={previewId} stage={migrationView} onStageChange={setMigrationView} />}
        {(view === 'live' || selectedMigrationPair.pair_id === 'fortigate_to_palo_alto') && <>
          <section hidden={view !== 'migration' || migrationView === 'export'}>
            <MigrationReview key={previewId} preview={preview} vendor={vendor} requestedDecision={requestedDecision}
              stage={migrationView} onStageChange={setMigrationView} reviewTab={migrationReviewTab} onReviewTabChange={setMigrationReviewTab}
              onApproved={() => { setGenerationRequest((value) => value + 1); setMigrationView('export') }}
              onDecisionDocument={setDecisionDocument}
              onContextChange={(nextSource, nextDevice) => { setTargetSource(nextSource); setTargetDevice(nextDevice) }} />
          </section>
        </>}
      </> : !loading && view !== 'live' && (vendor !== 'palo_alto' || !preview?.source_evidence || selectedMigrationPair?.pair_id !== 'palo_alto_to_fortigate') && <section className="panel"><h2>Migration source required</h2><p>Upload a supported source configuration above and choose an available migration target.</p><Button onClick={() => onViewChange('report')}>Open configuration report</Button></section>}
        {migrationVisited && (view === 'live' || (vendor === 'fortigate' && selectedMigrationPair?.pair_id === 'fortigate_to_palo_alto')) && <div hidden={view === 'migration' && migrationView !== 'export'}>
        <MigrationWorkflow key={previewId || 'uploaded-commands'}
          liveDeviceAccess={liveDeviceAccess}
          preview={preview ?? {}} decisionDocument={decisionDocument}
          targetSource={targetSource} targetDevice={targetDevice} generationRequest={generationRequest} activeSection={view === 'live' ? 'live' : 'plan'}
          onReviewDecision={(key) => { setRequestedDecision({ key, request: Date.now() }); setMigrationView('place'); onViewChange('migration'); requestAnimationFrame(() => document.getElementById('migration-review-title')?.scrollIntoView({ block: 'start' })) }}
           onViewChange={onViewChange} />
        </div>}
    </div>
    {error && !(file && !preview && ingestMode === 'config' && view !== 'collect') && <ErrorBanner message={error} />}
  </main>
}
