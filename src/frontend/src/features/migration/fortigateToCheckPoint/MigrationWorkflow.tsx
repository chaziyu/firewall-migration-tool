import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { MigrationCoverage } from '../components/MigrationCoverage'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import { Button } from '../../../components/common/Button'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { useEffect, useRef, useState } from 'react'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { MigrationStage } from '../types'
import * as api from './migrationApi'
import type { CheckPointOptions, CheckPointPlanItem, CheckPointWorkspace } from './types'

const MANAGEMENT_FILE = 'checkpoint_management_operations.json'
const GAIA_FILE = 'gaia_config.clish'
const BINDINGS_FILE = 'checkpoint_bindings.json'
const COMMANDS_FILE = 'checkpoint_management.sh'

const emptyCheckPointOptions = (): CheckPointOptions => ({
  target_mode: 'new',
  source_vdom: '', management_target: '', management_domain: '', management_api_version: '1.8.1',
  gaia_target: '', policy_package: '', access_layer: '', install_on: [], insertion_anchor: '',
  insertion_relation: '', target_cleanup_action: '',
})

function eligible(item: CheckPointPlanItem) { return ['CREATE', 'REUSE'].includes(item.render_disposition) }


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
    const saved = workspace().panosMigration
    return saved?.pairId === 'fortigate_to_checkpoint' && saved.sourceKey === sourceKey
      ? saved
      : { pairId: 'fortigate_to_checkpoint', sourceKey, options: emptyCheckPointOptions(), requirements: [], review: null, approval: null, artifact: null, preview: null }
  })
  const [targetLoading, setTargetLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [preparing, setPreparing] = useState(false)
  const [reviewTab, setReviewTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const [selected, setSelected] = useState<string[]>([])
  const [approvalPreview, setApprovalPreview] = useState<string[] | null>(null)
  const [sourceVdoms, setSourceVdoms] = useState<string[]>([])
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, review, approval, artifact } = state
  const newTarget = options.target_mode === 'new'

  useEffect(() => { void saveWorkspace({ panosMigration: { ...state, stage } }) }, [state, stage])
  useEffect(() => () => { requests.current++ }, [])
  useEffect(() => {
    let active = true
    const request = ++requests.current

    const timer = setTimeout(() => { setPreparing(true); void api.prepare(source, options, state.destination).then((result) => {
      if (!active || request !== requests.current) return
      const nextOptions = result.options ?? options
      setSourceVdoms(result.source_vdoms ?? result.requirements.find((item) => item.key === 'checkpoint:source_vdom')?.choices ?? [])
      setState((current) => ({ ...current, requirements: result.requirements, review: JSON.stringify(nextOptions) === JSON.stringify(options) ? result : null,
        options: JSON.stringify(nextOptions) === JSON.stringify(options) ? options : nextOptions,
        ...(JSON.stringify(nextOptions) === JSON.stringify(options) ? {} : { approval: null, artifact: null }) }))
    }).catch((cause) => { if (active && request === requests.current) setError(cause instanceof Error ? cause.message : 'Could not prepare conversion') })
      .finally(() => { if (active) setPreparing(false) }) }, 250)
    return () => { active = false; clearTimeout(timer) }
  }, [source, options, state.destination])

  function changeOptions(next: CheckPointOptions) {
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

  async function download(kind: 'management-operations' | 'management-commands' | 'gaia-config' | 'bindings' | 'bundle') {
    if (!artifact) return
    const request = requests.current
    const blob = await api.download(source, artifact, kind)
    if (request !== requests.current) return
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

  function textField(field: 'management_target' | 'management_domain' | 'policy_package' | 'access_layer' | 'insertion_anchor' | 'gaia_target', label: string, value: string) {
    return <label className="field" key={field}><span>{label}</span><input disabled={busy} value={value}
      onChange={(event) => changeOptions({ ...options, [field]: event.target.value })} /></label>
  }

  const unresolvedInputs = state.requirements.filter((item) => (item.value == null || item.value === '' || item.value === false))
  return <section className="panel checkpoint-workflow" aria-labelledby="checkpoint-migration-title">
    <h2 id="checkpoint-migration-title">FortiGate to Check Point</h2>
    <p>Convert the source into reviewed Check Point R81 API 1.8.1 operations and Gaia Clish commands for manual application.</p>
    {(stage === 'place' || stage === 'review') && <details open={stage === 'place'}><summary>Target setup and choices</summary>
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
    </details>}

    {error && <div className="error-banner" role="alert">{error}</div>}

    {(stage === 'review' || stage === 'place') && review && <>
      <MigrationCoverage coverage={review.report.coverage} />
      <OfflineMigrationReview id="fg-cp" title="Check Point" rows={review.report.items.map((item) => ({
        key: item.key, family: item.family, sourceScope: item.source_vdom, sourceName: item.source_name,
        target: item.target_name, operation: item.render_disposition, settings: item.settings,
        dependencies: item.dependencies, reasons: item.blockers, ready: ['CREATE', 'REUSE'].includes(item.render_disposition) && !item.blockers.length,
      }))} busy={busy || preparing || targetLoading} tab={reviewTab} onTabChange={setReviewTab}
        inputCount={unresolvedInputs.length}
        manualCount={review.report.items.filter((item) => item.blockers.length).length}
        issueContent={reviewTab === 'decisions' ? <><p>Complete these target choices in the setup details above.</p>
          <ul>{unresolvedInputs.map((item) => <li key={item.key}>{item.label} {item.source_name}</li>)}</ul></>
          : <><p>Blocked configuration and separate work retain their source reasons. Target choices may resolve some blockers; unsupported semantics remain manual.</p>
          <ul>{[...new Set(review.report.items.flatMap((item) => item.blockers))].map((reason) => <li key={reason}>{reason.replaceAll('_', ' ')}</li>)}</ul></>}

        selected={selected} onSelect={(keys) => { setSelected(keys); setApprovalPreview(null); setState((current) => ({ ...current, approval: null, artifact: null })) }}
        approvalKeys={approvalPreview} onPreview={(keys) => { try { setApprovalPreview(expandSelection(review.report.items, keys)) } catch (cause) { setError(String(cause)) } }}
        onApprove={() => void run(confirmApproval)} onCancel={() => setApprovalPreview(null)}
        approvalContext={<><p>Proposed offline placement; hardware availability is unverified. Approval binds these target choices and exact configuration.</p><pre className="set-command-preview">{JSON.stringify(options, null, 2)}</pre></>}
        onSetup={() => onStageChange('place')} findings={review.report.findings} approveLabel="Approve and generate" />
    </>}
    {preparing && <p role="status">Preparing conversion review…</p>}

    {stage === 'export' && approval && !artifact && <Button variant="secondary" type="button" disabled={busy} onClick={() => void run(() => generate())}>Retry with current approval</Button>}
    {stage === 'export' && artifact && <OfflineMigrationExport dispositions={artifact.report.items.map((row) => row.render_disposition)} artifactId={artifact.artifact_id}
      partial={Object.entries(artifact.report.coverage?.status_counts ?? {}).some(([status, count]) => count > 0 && !['RENDERED', 'REUSED'].includes(status)) || artifact.report.items.some((item) => !['CREATE', 'REUSE'].includes(item.render_disposition))}
      noChanges={artifact.report.items.length > 0 && artifact.report.items.every((item) => item.render_disposition === 'REUSE')}
      verification="Offline files only. Publish, policy installation, Gaia save and device acceptance remain manual."
      busy={busy || targetLoading} files={[
        { key: 'management-operations', name: MANAGEMENT_FILE, label: 'Management requests' },
        { key: 'management-commands', name: COMMANDS_FILE, label: 'Management commands' },
        { key: 'gaia-config', name: GAIA_FILE, label: 'Gaia config' },
        { key: 'bindings', name: BINDINGS_FILE, label: 'UID manifest' },
      ].filter((spec) => artifact.files[spec.name]).map((spec) => ({ key: spec.key, label: spec.label, previewLabel: spec.label,
        text: artifact.files[spec.name].content, sha256: artifact.files[spec.name].sha256,
        count: `${artifact.files[spec.name].byte_count} bytes`, downloadLabel: `Download ${spec.label}`, downloadable: true }))}
      onDownload={(kind) => void run(() => download(kind as 'management-operations' | 'management-commands' | 'gaia-config' | 'bindings'))}
      onBundle={() => void run(() => download('bundle'))}>
      <MigrationCoverage coverage={artifact.report.coverage} />
    </OfflineMigrationExport>}

  </section>
}
