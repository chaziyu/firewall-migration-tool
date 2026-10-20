import { MigrationCoverage } from '../components/MigrationCoverage'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import { Button } from '../../../components/common/Button'
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
const COMMANDS_FILE = 'checkpoint_management.sh'
const EMPTY_ITEMS: CheckPointPlanItem[] = []

const emptyCheckPointOptions = (): CheckPointOptions => ({
  target_mode: 'new',
  source_vdom: '', management_target: '', management_domain: '', management_api_version: '1.8.1',
  gaia_target: '', policy_package: '', access_layer: '', install_on: [], insertion_anchor: '',
  insertion_relation: '', target_cleanup_action: '',
})

function eligible(item: CheckPointPlanItem) { return ['CREATE', 'REUSE'].includes(item.render_disposition) }

const readableLabel = (value: string) => value.replaceAll('_', ' ').toLowerCase()

function expandSelection(items: CheckPointPlanItem[], keys: string[]) {
  const byKey = new Map(items.map((item) => [item.key, item]))
  const chosen = new Set<string>()
  const visiting = new Set<string>()
  function visit(key: string) {
    const item = byKey.get(key)
    if (!item || !eligible(item)) throw new Error('Selection contains an unknown or blocked dependency')
    if (visiting.has(key)) throw new Error('Selection contains a dependency cycle')
    if (chosen.has(key)) return
    visiting.add(key)
    item.dependencies.forEach(visit)
    visiting.delete(key)
    chosen.add(key)
  }
  keys.forEach(visit)
  return [...chosen].sort()
}

function fileName(kind: 'management-operations' | 'management-commands' | 'gaia-config' | 'bindings' | 'bundle') {
  if (kind === 'management-commands') return COMMANDS_FILE
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
  const [approvalPreview, setApprovalPreview] = useState<string[] | null>(null)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [findingPage, setFindingPage] = useState(1)
  const [memberPages, setMemberPages] = useState<Record<string, number>>({})
  const [approvalPage, setApprovalPage] = useState(1)
  const [previewFile, setPreviewFile] = useState(MANAGEMENT_FILE)
  const [sourceVdoms, setSourceVdoms] = useState<string[]>([])
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, review, approval, artifact, preview } = state
  const initialOptions = useRef(options)
  const newTarget = options.target_mode === 'new'

  useEffect(() => { void saveWorkspace({ newPairMigration: state }) }, [state])
  useEffect(() => () => { requests.current++ }, [])
  useEffect(() => {
    let active = true
    const requestedOptions = initialOptions.current
    api.requirements(source, requestedOptions).then((result) => {
      if (active) {
        setState((current) => ({ ...current, requirements: result.requirements,
          options: current.options === requestedOptions && !current.review && result.options
            ? result.options : current.options }))
        setSourceVdoms(result.source_vdoms ?? result.requirements.find((item) => item.key === 'checkpoint:source_vdom')?.choices ?? [])
      }
    }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : 'Could not load Check Point requirements') })
    return () => { active = false }
  }, [source, sourceKey, options.target_mode, options.source_vdom])

  function changeOptions(next: CheckPointOptions) {
    initialOptions.current = next
    requests.current++
    setState((current) => ({ ...current, options: next, review: null, approval: null, artifact: null, preview: null }))
    setSelected([])
    setApprovalPreview(null)
    setError(null)
  }

  function changeDestination(destination: DestinationEvidence | null) {
    requests.current++
    setState((current) => ({ ...current, destination, review: null, approval: null, artifact: null, preview: null }))
    setSelected([]); setApprovalPreview(null); setError(null)
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
    setSelected([])
    setApprovalPreview(null)
    const result = await api.prepare(source, options, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, options: result.options ?? current.options, requirements: result.requirements, review: result }))
    setPage(1)
    setFindingPage(1)
    setMemberPages({})
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

  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = ++requests.current
    const built = await api.build(source, options, currentApproval, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, artifact: built.artifact, preview: null }))
    setPreviewFile(built.artifact.files[COMMANDS_FILE] ? COMMANDS_FILE : MANAGEMENT_FILE)
    onStageChange('export')
    await refreshPreview(built.artifact)
  }

  async function confirmApproval() {
    if (!review || !approvalPreview?.length) return
    const request = ++requests.current
    const expanded = expandSelection(review.report.items, approvalPreview)
    const result = await api.approve(source, options, review.draft, expanded, state.destination)
    if (request !== requests.current) return
    const signedSelection = result.approval.selected_items
    if (!Array.isArray(signedSelection) || JSON.stringify([...signedSelection].sort()) !== JSON.stringify(expanded)) {
      throw new Error('Approved selection differs from the reviewed preview; prepare review again')
    }
    setState((current) => ({ ...current, approval: result.approval, artifact: null, preview: null }))
    setApprovalPreview(null)
    onStageChange('export')
    await generate(result.approval)
  }

  function openApprovalPreview() {
    if (review) {
      setApprovalPreview(expandSelection(review.report.items, selected))
      setApprovalPage(1)
    }
  }

  async function download(kind: 'management-operations' | 'management-commands' | 'gaia-config' | 'bindings' | 'bundle') {
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
    setApprovalPreview(null)
    setSelected((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key])
  }

  const items = review?.report.items ?? EMPTY_ITEMS
  const itemsByKey = new Map(items.map((item) => [item.key, item]))
  const filteredItems = useMemo(() => items.filter((item) =>
    `${item.family} ${item.source_vdom} ${item.source_name} ${item.target_name} ${item.blockers.join(' ')}`.toLowerCase().includes(search.trim().toLowerCase())), [items, search])
  const pages = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE))
  const currentPage = Math.min(page, pages)
  const visibleItems = filteredItems.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)
  const eligibleCount = items.filter(eligible).length
  const findingGroups = useMemo(() => {
    const groups = new Map<string, { key: string; message: string; findings: Record<string, unknown>[] }>()
    for (const finding of review?.report.findings ?? []) {
      const key = JSON.stringify([finding.code, finding.message, finding.blocking])
      const group = groups.get(key)
      if (group) group.findings.push(finding)
      else groups.set(key, { key, message: String(finding.message), findings: [finding] })
    }
    return [...groups.values()]
  }, [review])
  const findingPages = Math.max(1, Math.ceil(findingGroups.length / PAGE_SIZE))
  const currentFindingPage = Math.min(findingPage, findingPages)
  const approvalPages = Math.max(1, Math.ceil((approvalPreview?.length ?? 0) / PAGE_SIZE))
  const currentApprovalPage = Math.min(approvalPage, approvalPages)
  function textField(field: 'management_target' | 'management_domain' | 'policy_package' | 'access_layer' | 'insertion_anchor' | 'gaia_target', label: string, value: string) {
    return <label className="field" key={field}><span>{label}</span><input disabled={busy} value={value}
      onChange={(event) => changeOptions({ ...options, [field]: event.target.value })} /></label>
  }

  return <section className="panel checkpoint-workflow" aria-labelledby="checkpoint-migration-title">
    <h2 id="checkpoint-migration-title">FortiGate to Check Point</h2>
    <p>Convert the source into reviewed Check Point R81 API 1.8.1 operations and Gaia Clish commands for manual application.</p>
    {stage === 'place' && <>
      <label className="field"><span>Target setup</span><select disabled={busy} value={newTarget ? 'new' : 'existing'} onChange={(event) => {
        changeDestination(null)
        changeOptions({ ...emptyCheckPointOptions(), source_vdom: options.source_vdom,
          target_mode: event.target.value as 'new' | 'existing' })
      }}><option value="new">New target — create a policy package</option><option value="existing">Existing target — add to a policy</option></select></label>
      {newTarget && <p>No target configuration is needed. A new package, access layer and Drop cleanup rule are included. Review the proposed names, then generate the commands.</p>}
      <div className="source-vendor-grid with-target">
        <label className="field"><span>Source FortiGate VDOM</span><select disabled={busy} value={options.source_vdom}
          onChange={(event) => changeOptions({ ...options, source_vdom: event.target.value })}>
          <option value="">Choose a VDOM</option>{sourceVdoms.map((value) => <option key={value} value={value}>{value}</option>)}
        </select></label>
        {textField('policy_package', newTarget ? 'New policy package name (proposed)' : 'Policy package', options.policy_package)}
        {!newTarget && <>
        {textField('management_target', 'Management server label', options.management_target)}
        {textField('management_domain', 'Management Domain', options.management_domain)}
        <label className="field"><span>Management API version</span><select disabled value={options.management_api_version}>
          <option value="">Unsupported version</option><option value="1.8.1">R81 API 1.8.1</option>
        </select></label>
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
        </>}
      </div>
      {newTarget && <p>The gateway and Management Domain are selected when applying the files. No login, publish or policy installation is included. Requires mgmt_cli and jq to run the command file.</p>}
      {!newTarget && <details><summary>Optional: compare an existing target configuration</summary>
        <DestinationSnapshot vendor="checkpoint" families={['objects', 'services', 'packages', 'layers', 'gateways', 'policies', 'nat']} value={state.destination ?? null} disabled={busy} onChange={changeDestination} onPendingChange={setTargetLoading} />
      </details>}
      <p>Interface-bound rules, non-always schedules, NAT and unsupported source settings remain visible as manual work.</p>
      <details><summary>Advanced: mapping files</summary>
      <div className="action-row">
        <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(exportProposal)}>Export mapping proposal</Button>
        <label className="field"><span>Import mapping proposal</span><input disabled={busy} type="file" accept="application/json,.json"
          onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ''; if (file) void run(() => importProposal(file)) }} /></label>
      </div>
      </details>
      <Button variant="primary" type="button" disabled={busy || targetLoading || !options.source_vdom} onClick={() => void run(prepareReview)}>Prepare review</Button>
    </>}

    {error && <div className="error-banner" role="alert">{error}</div>}

    {stage === 'review' && review && <>
      <h3>Review generated operations</h3>
      <Button variant="secondary" type="button" disabled={busy} onClick={() => onStageChange('place')}>Edit target setup</Button>
      <MigrationCoverage coverage={review.report.coverage} />
      <p>{readableLabel(review.report.plan_status)}. {eligibleCount} items can be included; {items.length - eligibleCount} remain blocked or manual. Selecting a rule also approves its prior rule and object dependencies.</p>
      <label className="field"><span>Search plan items</span><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} /></label>
      <div className="checkpoint-plan-list" aria-label="Check Point plan items">
        {visibleItems.map((item) => <div className="checkpoint-plan-item" key={item.key}>
          <label className="checkpoint-item-heading"><input type="checkbox" disabled={busy || !eligible(item)} checked={selected.includes(item.key)} onChange={() => toggleItem(item.key)} />
            <strong>{readableLabel(item.family)}: {item.source_name}</strong></label>
          <p>Source VDOM: {item.source_vdom || 'Unspecified'}</p>
          <p>{readableLabel(item.render_disposition)} · Target: {item.target_name}</p>
          {item.blockers.length > 0 && <details><summary>{item.blockers.length} blocking reasons</summary>
            <ul>{item.blockers.map((reason, index) => <li key={index}>{readableLabel(reason)}</li>)}</ul>
            <details><summary>Technical blocker codes</summary><pre className="set-command-preview">{item.blockers.join('\n')}</pre></details>
          </details>}
        </div>)}
      </div>
      {!filteredItems.length && <p>No plan items match your search.</p>}
      <div className="action-row"><Button variant="secondary" type="button" disabled={busy || currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous</Button><span>Page {currentPage} of {pages}</span><Button variant="secondary" type="button" disabled={busy || currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next</Button></div>
      {findingGroups.length > 0 && <section className="checkpoint-findings" aria-label="Check Point findings">
        <h3>Findings ({review.report.findings.length})</h3>
        <p>{findingGroups.length} groups. Expand a group to review its source items and exact evidence.</p>
        {findingGroups.slice((currentFindingPage - 1) * PAGE_SIZE, currentFindingPage * PAGE_SIZE).map((group) => {
          const pages = Math.max(1, Math.ceil(group.findings.length / PAGE_SIZE))
          const current = Math.min(memberPages[group.key] ?? 1, pages)
          return <details className="checkpoint-plan-item" key={group.key}>
            <summary>{group.message} ({group.findings.length} {group.findings.length === 1 ? 'finding' : 'findings'})</summary>
            <ul>{group.findings.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE).map((finding, index) => <li key={(current - 1) * PAGE_SIZE + index}>
              {[finding.source_vdom, finding.source_kind, finding.source_name].filter((value) => value != null && value !== '').map(String).join(' / ') || 'Plan-wide finding'}
              <details><summary>Exact finding evidence</summary><pre className="set-command-preview">{JSON.stringify(finding, null, 2)}</pre></details>
            </li>)}</ul>
            {pages > 1 && <div className="action-row"><Button variant="secondary" disabled={busy || current === 1} onClick={() => setMemberPages((previous) => ({ ...previous, [group.key]: current - 1 }))}>Previous affected items</Button><span>Page {current} of {pages}</span><Button variant="secondary" disabled={busy || current === pages} onClick={() => setMemberPages((previous) => ({ ...previous, [group.key]: current + 1 }))}>Next affected items</Button></div>}
          </details>
        })}
        {findingPages > 1 && <div className="action-row"><Button variant="secondary" disabled={busy || currentFindingPage === 1} onClick={() => setFindingPage(currentFindingPage - 1)}>Previous finding groups</Button><span>Page {currentFindingPage} of {findingPages}</span><Button variant="secondary" disabled={busy || currentFindingPage === findingPages} onClick={() => setFindingPage(currentFindingPage + 1)}>Next finding groups</Button></div>}
      </section>}
      <div className="action-row"><Button variant="secondary" type="button" disabled={busy || eligibleCount === 0} onClick={() => { setSelected(items.filter(eligible).map((item) => item.key)); setApprovalPreview(null) }}>Select all supported operations</Button>
      <Button variant="primary" type="button" disabled={busy || selected.length === 0} onClick={() => void run(async () => openApprovalPreview())}>Review selected operations</Button></div>
      {approvalPreview && <section className="migration-approval-preview" aria-label="Check Point approval preview">
        <h3>Confirm operations and dependencies</h3>
        <p>{approvalPreview.length} operations, including {approvalPreview.filter((key) => !selected.includes(key)).length} required dependencies. Approval includes all pages.</p>
        {newTarget ? <p>Create package: {options.policy_package}. Create its access layer and Drop cleanup rule. Domain and gateways are selected during manual application. No existing policy is changed.</p>
          : <p>Management target: {options.management_target}. Domain: {options.management_domain}. Package: {options.policy_package}. Layer: {options.access_layer}. Install-on: {options.install_on.join(', ')}. Placement: {options.insertion_relation} {options.insertion_anchor}. Gaia target: {options.gaia_target}.</p>}
        {approvalPreview.slice((currentApprovalPage - 1) * PAGE_SIZE, currentApprovalPage * PAGE_SIZE).map((key) => {
          const item = itemsByKey.get(key)!
          return <details className="checkpoint-plan-item" key={key}><summary>{readableLabel(item.family)}: {item.source_name} ({selected.includes(key) ? 'Selected' : 'Required dependency'})</summary>
            <p>{readableLabel(item.render_disposition)} · Target: {item.target_name}</p>
            <p>Source VDOM: {item.source_vdom || 'Unspecified'}. Dependencies: {item.dependencies.length}.</p>
            <details><summary>Exact settings and dependency keys</summary><pre className="set-command-preview">{JSON.stringify({ settings: item.settings, dependencies: item.dependencies }, null, 2)}</pre></details>
          </details>
        })}
        {approvalPages > 1 && <div className="action-row"><Button variant="secondary" disabled={busy || currentApprovalPage === 1} onClick={() => setApprovalPage(currentApprovalPage - 1)}>Previous approval details</Button><span>Page {currentApprovalPage} of {approvalPages}</span><Button variant="secondary" disabled={busy || currentApprovalPage === approvalPages} onClick={() => setApprovalPage(currentApprovalPage + 1)}>Next approval details</Button></div>}
        <div className="action-row"><Button variant="primary" type="button" disabled={busy} onClick={() => void run(confirmApproval)}>Approve these operations and generate files</Button>
        <Button variant="secondary" type="button" disabled={busy} onClick={() => setApprovalPreview(null)}>Cancel approval preview</Button></div>
      </section>}
    </>}

    {stage === 'export' && approval && !artifact && <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => generate())}>Retry with current approval</Button>}
    {stage === 'export' && artifact && <>
      <h3>Reviewed offline files</h3>
      <p>Approval expires {new Date(artifact.expires_at * 1000).toLocaleString()}. Live device acceptance, policy publish, installation, and Gaia save remain manual.</p>
      <div className="migration-view-nav" aria-label="Reviewed Check Point files">
        {Object.keys(artifact.files).map((name) => <Button variant="secondary" type="button" key={name} aria-pressed={previewFile === name} onClick={() => setPreviewFile(name)}>{name}</Button>)}
      </div>
      <p>SHA-256: {artifact.file_sha256[previewFile]}</p>
      <pre className="set-command-preview">{preview?.[previewFile]?.text ?? 'Loading approved bytes…'}</pre>
      <div className="action-row">
        {artifact.files[COMMANDS_FILE] && <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => download('management-commands'))}>Download Management commands</Button>}
        <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => download('management-operations'))}>Download Management requests</Button>
        <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => download('gaia-config'))}>Download Gaia config</Button>
        <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => download('bindings'))}>Download UID manifest</Button>
        <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => download('bundle'))}>Download reviewed bundle</Button>
      </div>
      {!preview && <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => refreshPreview())}>Reload exact approved preview</Button>}
    </>}
  </section>
}
