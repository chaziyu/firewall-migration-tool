import { MigrationCoverage } from '../components/MigrationCoverage'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { useEffect, useMemo, useRef, useState } from 'react'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { MigrationStage } from '../types'
import * as api from './migrationApi'
import type { CheckPointOptions, CheckPointPlanItem, CheckPointWorkspace } from './types'

const PAGE_SIZE = 25
const MANAGEMENT_FILE = 'checkpoint_management_operations.json'
const GAIA_FILE = 'gaia_config.clish'
const BINDINGS_FILE = 'checkpoint_bindings.json'
const EMPTY_ITEMS: CheckPointPlanItem[] = []

const emptyCheckPointOptions = (): CheckPointOptions => ({
  source_vdom: '', management_target: '', management_domain: '', management_api_version: '1.8.1',
  gaia_target: '', policy_package: '', access_layer: '', install_on: [], insertion_anchor: '',
  insertion_relation: '', target_cleanup_action: '',
})

function eligible(item: CheckPointPlanItem) { return ['CREATE', 'REUSE'].includes(item.render_disposition) }

function fileName(kind: 'management-operations' | 'gaia-config' | 'bindings' | 'bundle') {
  return kind === 'management-operations' ? MANAGEMENT_FILE : kind === 'gaia-config' ? GAIA_FILE : kind === 'bindings' ? BINDINGS_FILE : 'migration_fortigate_to_checkpoint.zip'
}

export function CheckPointMigrationWorkflow({ source, sourceKey, stage, onStageChange }: {
  source: SourceEvidence
  sourceKey: string
  stage: MigrationStage
  onStageChange: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<CheckPointWorkspace>(() => {
    const saved = workspace().newPairMigration
    return saved?.pairId === 'fortigate_to_checkpoint' && saved.sourceKey === sourceKey
      ? saved
      : { pairId: 'fortigate_to_checkpoint', sourceKey, options: emptyCheckPointOptions(), requirements: [], review: null, approval: null, artifact: null, preview: null }
  })
  const [targetLoading, setTargetLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [previewFile, setPreviewFile] = useState(MANAGEMENT_FILE)
  const [sourceVdoms, setSourceVdoms] = useState<string[]>([])
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, review, artifact, preview } = state
  const initialOptions = useRef(options)

  useEffect(() => { void saveWorkspace({ newPairMigration: state }) }, [state])
  useEffect(() => () => { requests.current++ }, [])
  useEffect(() => {
    let active = true
    api.requirements(source, { ...initialOptions.current, source_vdom: '' }).then((result) => {
      if (active) {
        setState((current) => ({ ...current, requirements: result.requirements }))
        setSourceVdoms(result.requirements.find((item) => item.key === 'checkpoint:source_vdom')?.choices ?? [])
      }
    }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : 'Could not load Check Point requirements') })
    return () => { active = false }
  }, [source, sourceKey])

  function changeOptions(next: CheckPointOptions) {
    requests.current++
    setState((current) => ({ ...current, options: next, review: null, approval: null, artifact: null, preview: null }))
    setSelected([])
    setError(null)
  }

  function changeDestination(destination: DestinationEvidence | null) {
    requests.current++
    setState((current) => ({ ...current, destination, review: null, approval: null, artifact: null, preview: null }))
    setSelected([]); setError(null)
  }

  async function run(action: () => Promise<void>) {
    if (pending.current) return
    pending.current = true
    setBusy(true)
    setError(null)
    try { await action() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Check Point migration request failed') }
    finally { pending.current = false; setBusy(false) }
  }

  async function prepareReview() {
    const request = ++requests.current
    setState((current) => ({ ...current, approval: null, artifact: null, preview: null }))
    const result = await api.prepare(source, options, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, requirements: result.requirements, review: result }))
    setSelected(result.report.items.filter(eligible).map((item) => item.key))
    setPage(1)
    onStageChange('review')
  }

  async function refreshPreview(currentArtifact = artifact) {
    if (!currentArtifact) return
    const request = ++requests.current
    const result = await api.preview(source, currentArtifact)
    if (request !== requests.current) return
    for (const [name, file] of Object.entries(result.files)) {
      const expected = currentArtifact.files[name]
      if (!expected || expected.content !== file.text || expected.sha256 !== file.sha256 || expected.byte_count !== file.byte_count) {
        throw new Error('Approved Check Point preview integrity check failed')
      }
    }
    setState((current) => ({ ...current, preview: result.files }))
  }

  async function approveAndBuild() {
    if (!review || !selected.length) return
    const request = ++requests.current
    const result = await api.approve(source, options, review.draft, selected, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, approval: result.approval, artifact: null, preview: null }))
    const built = await api.build(source, options, result.approval, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, artifact: built.artifact, preview: null }))
    onStageChange('export')
    await refreshPreview(built.artifact)
  }

  async function download(kind: 'management-operations' | 'gaia-config' | 'bindings' | 'bundle') {
    if (!artifact) return
    const blob = await api.download(source, artifact, kind)
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = fileName(kind)
    link.click()
    URL.revokeObjectURL(url)
  }

  async function exportProposal() {
    const result = await api.exportDecisions(source, options)
    const blob = new Blob([`${JSON.stringify(result.document, null, 2)}\n`], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'fortigate_to_checkpoint_mapping.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  async function importProposal(file: File | undefined) {
    if (!file) return
    const document = JSON.parse(await file.text()) as unknown
    const result = await api.importDecisions(source, document)
    changeOptions(result.options)
    setError(null)
  }

  function toggleItem(key: string) {
    setSelected((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key])
  }

  const items = review?.report.items ?? EMPTY_ITEMS
  const filteredItems = useMemo(() => items.filter((item) =>
    `${item.family} ${item.source_vdom} ${item.source_name} ${item.target_name} ${item.blockers.join(' ')}`.toLowerCase().includes(search.trim().toLowerCase())), [items, search])
  const pages = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE))
  const currentPage = Math.min(page, pages)
  const visibleItems = filteredItems.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)
  const eligibleCount = items.filter(eligible).length
  function textField(field: 'management_target' | 'management_domain' | 'policy_package' | 'access_layer' | 'insertion_anchor' | 'gaia_target', label: string, value: string) {
    return <label className="field" key={field}><span>{label}</span><input disabled={busy} value={value}
      onChange={(event) => changeOptions({ ...options, [field]: event.target.value })} /></label>
  }

  return <section className="panel" aria-labelledby="checkpoint-migration-title">
    <h2 id="checkpoint-migration-title">FortiGate to Check Point</h2>
    <p>Review a Check Point R81 Management API 1.8.1 request specification and a separate Gaia Clish file. Nothing is sent to a firewall.</p>
    {stage !== 'export' && <>
      <DestinationSnapshot vendor="checkpoint" families={['objects', 'services', 'packages', 'layers', 'gateways', 'policies', 'nat']} value={state.destination ?? null} disabled={busy} onChange={changeDestination} onPendingChange={setTargetLoading} />
      <div className="source-vendor-grid with-target">
        <label className="field"><span>Source FortiGate VDOM</span><select disabled={busy} value={options.source_vdom}
          onChange={(event) => changeOptions({ ...options, source_vdom: event.target.value })}>
          <option value="">Choose a VDOM</option>{sourceVdoms.map((value) => <option key={value} value={value}>{value}</option>)}
        </select></label>
        {textField('management_target', 'Management server label', options.management_target)}
        {textField('management_domain', 'Management Domain', options.management_domain)}
        <label className="field"><span>Management API version</span><select disabled value={options.management_api_version}>
          <option value="">Unsupported version</option><option value="1.8.1">R81 API 1.8.1</option>
        </select></label>
        {textField('policy_package', 'Policy package', options.policy_package)}
        {textField('access_layer', 'Access layer', options.access_layer)}
        <label className="field"><span>Install-on gateways or clusters (comma separated)</span><input disabled={busy} value={options.install_on.join(', ')}
          onChange={(event) => changeOptions({ ...options, install_on: [...new Set(event.target.value.split(',').map((value) => value.trim()).filter(Boolean))] })} /></label>
        {textField('insertion_anchor', 'Existing Drop cleanup rule name or UID', options.insertion_anchor)}
        <label className="field"><span>Insert imported rules</span><select disabled={busy} value={options.insertion_relation}
          onChange={(event) => changeOptions({ ...options, insertion_relation: event.target.value })}>
          <option value="">Choose placement</option><option value="above">Above the cleanup rule</option>
        </select></label>
        <label className="field"><span>Confirmed target cleanup action</span><select disabled={busy} value={options.target_cleanup_action}
          onChange={(event) => changeOptions({ ...options, target_cleanup_action: event.target.value })}>
          <option value="">Choose an action</option><option value="Drop">Drop</option>
        </select></label>
        {textField('gaia_target', 'Gaia gateway or cluster label', options.gaia_target)}
      </div>
      <p>Interface-bound rules, non-always schedules, NAT, inline layers and unsupported services stay manual. Verify the cleanup rule and destination names before applying the request specification.</p>
      <div className="report-actions">
        <button type="button" disabled={busy} onClick={() => void run(exportProposal)}>Export mapping proposal</button>
        <label className="field"><span>Import mapping proposal</span><input disabled={busy} type="file" accept="application/json,.json"
          onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ''; if (file) void run(() => importProposal(file)) }} /></label>
      </div>
      <button type="button" disabled={busy || targetLoading || !options.source_vdom} onClick={() => void run(prepareReview)}>Prepare review</button>
    </>}

    {error && <div className="error-banner" role="alert">{error}</div>}

    {stage === 'review' && review && <>
      <h3>Review generated operations</h3>
      <MigrationCoverage coverage={review.report.coverage} />
      <p>{review.report.plan_status}. {eligibleCount} items can be included; {items.length - eligibleCount} remain blocked or manual. Selecting a rule also approves its prior rule and object dependencies.</p>
      <label className="field"><span>Search plan items</span><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} /></label>
      <div className="migration-approval-list" aria-label="Check Point plan items">
        {visibleItems.map((item) => <label className="migration-approval-item" key={item.key}>
          <input type="checkbox" disabled={busy || !eligible(item)} checked={selected.includes(item.key)} onChange={() => toggleItem(item.key)} />
          <span><strong>{item.family}: {item.source_name}</strong><span>{item.render_disposition} · {item.target_name}</span>
            {item.blockers.length > 0 && <span>{item.blockers.join(', ')}</span>}</span>
        </label>)}
      </div>
      <div className="report-pagination"><button type="button" disabled={busy || currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous</button><span>Page {currentPage} of {pages}</span><button type="button" disabled={busy || currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next</button></div>
      {review.report.findings.map((finding, index) => <p key={`${String(finding.code)}-${index}`}>{String(finding.message)}</p>)}
      <button type="button" disabled={busy || selected.length === 0} onClick={() => void run(approveAndBuild)}>Approve selected items and build reviewed files</button>
    </>}

    {stage === 'export' && artifact && <>
      <h3>Reviewed offline files</h3>
      <p>Approval expires {new Date(artifact.expires_at * 1000).toLocaleString()}. Live device acceptance, policy publish, installation, and Gaia save remain manual.</p>
      <div className="migration-view-nav" aria-label="Reviewed Check Point files">
        {[MANAGEMENT_FILE, GAIA_FILE, BINDINGS_FILE].map((name) => <button type="button" key={name} aria-pressed={previewFile === name} onClick={() => setPreviewFile(name)}>{name}</button>)}
      </div>
      <p>SHA-256: {artifact.file_sha256[previewFile]}</p>
      <pre className="migration-command-preview">{preview?.[previewFile]?.text ?? 'Loading approved bytes…'}</pre>
      <div className="report-actions">
        <button type="button" disabled={busy} onClick={() => void run(() => download('management-operations'))}>Download Management requests</button>
        <button type="button" disabled={busy} onClick={() => void run(() => download('gaia-config'))}>Download Gaia config</button>
        <button type="button" disabled={busy} onClick={() => void run(() => download('bindings'))}>Download UID manifest</button>
        <button type="button" disabled={busy} onClick={() => void run(() => download('bundle'))}>Download reviewed bundle</button>
      </div>
      {!preview && <button type="button" disabled={busy} onClick={() => void run(() => refreshPreview())}>Reload exact approved preview</button>}
    </>}
  </section>
}
