import { useEffect, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { useMigrationReviewActivity } from '../hooks/useMigrationReviewActivity'
import { downloadFile } from '../migrationApi'
import type { MigrationStage } from '../types'
import type { CPOptions, CPWorkspace } from './types'
import * as api from './migrationApi'
import { approvalSelection } from './reviewSelection'

const emptyOptions = (): CPOptions => ({ source_scope: '', target_mode: 'new', management_target: '', management_domain: '',
  management_api_version: '1.8.1', gaia_target: '', policy_package: '', access_layer: '', install_on: [],
  insertion_anchor: '', insertion_relation: '', target_cleanup_action: '' })
const fileSpecs = [
  { key: 'management-operations', name: 'checkpoint_management_operations.json', label: 'Management API requests' },
  { key: 'management-commands', name: 'checkpoint_management.sh', label: 'Fresh-package Management commands' },
  { key: 'bindings', name: 'checkpoint_bindings.json', label: 'UID bindings and file manifest' },
  { key: 'gaia-config', name: 'gaia_config.clish', label: 'Gaia configuration' },
]

export function PaloAltoToCheckPointWorkflow({ source, sourceKey, stage: controlledStage, onStageChange }: {
  source: SourceEvidence; sourceKey: string; stage?: MigrationStage; onStageChange?: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<CPWorkspace>(() => {
    const saved = workspace().panosMigration
    return saved?.pairId === 'palo_alto_to_checkpoint' && saved.sourceKey === sourceKey ? saved
      : { pairId: 'palo_alto_to_checkpoint', sourceKey, options: emptyOptions(), review: null, approval: null, artifact: null, stage: 'place' }
  })
  const [selected, setSelected] = useState<string[]>([])
  const [approvalKeys, setApprovalKeys] = useState<string[] | null>(null)
  const [tab, setTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const [targetPending, setTargetPending] = useState(false)
  const activity = useMigrationReviewActivity({ source, targetSource: state.targetSource?.source ?? null,
    targetDevice: '', workflowMode: 'offline', pairId: 'palo_alto_to_checkpoint' })
  // These helpers close over stable refs and setters, not source or target payloads.
  const [requests] = useState(() => ({ begin: activity.beginReviewRequest, finish: activity.finishReviewRequest,
    current: activity.currentReviewVersion, isCurrent: activity.reviewRequestIsCurrent, invalidate: activity.invalidateReviewRequests, run: activity.run }))
  const { setError } = activity
  const { options, review, approval, artifact, targetSource } = state
  const [installOnText, setInstallOnText] = useState(options.install_on.join(', '))
  const [scopes, setScopes] = useState(state.review?.source_scopes ?? [])
  const stage = controlledStage ?? state.stage
  const rows = review?.report.items ?? []
  const busy = activity.busy || targetPending
  useEffect(() => { void saveWorkspace({ panosMigration: { ...state, stage } }) }, [state, stage])
  useEffect(() => {
    const request = requests.begin()
    let active = true
    const timer = setTimeout(() => { void api.prepare(source, options, targetSource).then((result) => {
      if (!active || !requests.isCurrent(request)) return
      setScopes(result.source_scopes)
      setState((current) => ({ ...current, review: result, options: JSON.stringify(options) === JSON.stringify(result.options) ? options : result.options }))
    }).catch((cause) => { if (active && requests.isCurrent(request)) setError(cause instanceof Error ? cause.message : 'Check Point proposal failed') })
      .finally(() => { if (active) requests.finish(request) }) }, 250)
    return () => { active = false; clearTimeout(timer); requests.invalidate() }
  }, [source, options, targetSource, requests, setError])
  useEffect(() => () => requests.invalidate(), [requests])
  function setStage(next: MigrationStage) { setState((current) => ({ ...current, stage: next })); onStageChange?.(next) }
  function update(next: Partial<CPWorkspace>) {
    requests.invalidate(); setSelected([]); setApprovalKeys(null); setError('')
    setState((current) => ({ ...current, ...next, review: null, approval: null, artifact: null }))
  }
  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = requests.current()
    const built = await api.build(source, options, currentApproval, targetSource)
    if (requests.isCurrent(request)) { setState((current) => ({ ...current, artifact: built.artifact })); setStage('export') }
  }
  async function approve() {
    if (!review || !approvalKeys) return
    const request = requests.current()
    const result = await api.approve(source, options, review.draft, approvalKeys, targetSource)
    if (!requests.isCurrent(request)) return
    const signed = result.approval.selected_items
    if (!Array.isArray(signed) || JSON.stringify([...signed].sort()) !== JSON.stringify([...approvalKeys].sort())) throw new Error('Approved operations differ from the reviewed selection')
    setState((current) => ({ ...current, approval: result.approval, artifact: null })); setApprovalKeys(null); setStage('export')
    await generate(result.approval)
  }
  function download(kind: string) {
    if (!artifact) return
    const spec = fileSpecs.find((file) => file.key === kind)
    if (kind !== 'bundle' && !spec) return
    const request = requests.current()
    void requests.run(async () => {
      const blob = await api.download(source, artifact, kind)
      if (requests.isCurrent(request)) downloadFile(blob, spec?.name ?? 'migration_palo_alto_to_checkpoint.zip')
    })
  }
  const manual = rows.filter((row) => row.render_disposition === 'BLOCK')
  const inputCount = review?.requirements.length ?? 0
  return <section className="panel" aria-label="PAN-OS to Check Point">
    <h2>PAN-OS → Check Point</h2><p>Management API 1.8.1. Offline files only. Gaia and live policy activation require separate work.</p>
    {activity.error && <ErrorBanner message={activity.error} />}
    {busy && <p role="status">Preparing reviewed migration…</p>}
    {stage === 'load' && <Button disabled={busy || !review} onClick={() => setStage('place')}>Continue to target setup</Button>}
    {stage === 'place' && <>
      <h3>Target setup</h3>
      <label className="field">Target mode<select disabled={activity.actionBusy || targetPending} value={options.target_mode} onChange={(event) => update({ options: { ...options, target_mode: event.target.value as CPOptions['target_mode'] }, targetSource: null })}>
        <option value="new">New policy package</option><option value="existing">Existing Management snapshot</option></select></label>
      <label className="field">PAN-OS source scope<select value={options.source_scope} disabled={activity.actionBusy || targetPending} onChange={(event) => update({ options: { ...options, source_scope: event.target.value, policy_package: '' } })}>
        <option value="">Choose one device / VSYS</option>{scopes.map((scope) => <option key={scope}>{scope}</option>)}</select></label>
      {(['management_target', 'management_domain', ...(options.target_mode === 'new' ? ['policy_package'] : [])] as const).map((field) => <label className="field" key={field}>
        {field === 'management_target' ? 'Management server' : field === 'management_domain' ? 'Management Domain' : 'New policy package'}
        <input disabled={activity.actionBusy || targetPending} value={String(options[field as keyof CPOptions])} onChange={(event) => update({ options: { ...options, [field]: event.target.value } })} /></label>)}
      {options.target_mode === 'new' ? <>
        <p>The package name and API version are proposals. Returned layer and object UIDs bind later requests. Unspecified server, Domain and gateway selection remain explicit application steps before publishing or installing policy.</p>
        <label className="field">Install-on gateways or clusters (comma separated)<input disabled={activity.actionBusy} value={installOnText} onChange={(event) => {
          setInstallOnText(event.target.value)
          update({ options: { ...options, install_on: event.target.value.split(',').map((value) => value.trim()).filter(Boolean) } })
        }} /></label>
      </> : <>
        <p>Declare the selected Management server and Domain. Complete snapshots can prove address/group reuse or object-name absence. Existing rule placement and service reuse remain blocked.</p>
        <DestinationSnapshot vendor="checkpoint" families={['objects', 'services', 'packages', 'layers', 'gateways', 'policies', 'nat']} value={targetSource ?? null}
          disabled={busy} onPendingChange={setTargetPending} onChange={(next: DestinationEvidence | null) => update({ targetSource: next })} />
      </>}
      <p>Zone-constrained rules, active NAT, App-ID, named schedules and Gaia topology remain manual. Supported policies must explicitly match unrestricted source and destination zones.</p>
      <Button disabled={busy || !review} onClick={() => setStage('review')}>Review migration</Button>
    </>}
    {stage === 'review' && review && <OfflineMigrationReview id="panos-cp" title="Check Point" rows={rows.map((row) => ({ key: row.key, family: row.family,
      sourceScope: row.source_scope, sourceName: row.source_name, target: row.target_name, operation: row.render_disposition, settings: row.settings,
      dependencies: row.dependencies, reasons: row.blockers, ready: ['CREATE', 'REUSE'].includes(row.render_disposition) && !row.blockers.length }))}
      busy={busy} tab={tab} onTabChange={setTab} inputCount={inputCount} manualCount={manual.length}
      issueContent={<><h3>Remaining choices and manual work</h3><p>{inputCount} target choices; {manual.length} blocked items.</p><ul>{[...new Set(manual.flatMap((row) => row.blockers))].map((reason) => <li key={reason}>{reason.replaceAll('_', ' ')}</li>)}</ul></>}
      selected={selected} onSelect={(keys) => { setSelected(keys); setApprovalKeys(null) }} approvalKeys={approvalKeys}
      onPreview={(keys) => { try { setApprovalKeys(approvalSelection(rows, keys)) } catch (cause) { setError(String(cause)) } }}
      onApprove={() => void requests.run(approve)} onCancel={() => setApprovalKeys(null)}
      approvalContext={<><p>Approve these exact request bodies, returned UID dependencies and target choices. No login, publish or policy installation is included.</p><pre className="set-command-preview">{JSON.stringify(options, null, 2)}</pre></>}
      onSetup={() => setStage('place')} approveLabel="Approve and build offline export" />}
    {stage === 'export' && !artifact && <p>Review and approve current changes before download.</p>}
    {stage === 'export' && approval && !artifact && <Button disabled={busy} onClick={() => void requests.run(() => generate())}>Retry generation with current approval</Button>}
    {stage === 'export' && artifact && <OfflineMigrationExport artifactId={artifact.artifact_id} partial={manual.length > 0 || rows.some((row) => !approval || !(approval.selected_items as string[] | undefined)?.includes(row.key))}
      noChanges={!Number(artifact.report.management_operation_count)} verification={artifact.report.verification} busy={busy}
      files={fileSpecs.filter((spec) => artifact.files[spec.name]).map((spec) => ({ key: spec.key, label: spec.label, previewLabel: spec.label,
        text: artifact.files[spec.name].content, sha256: artifact.files[spec.name].sha256, count: `${artifact.files[spec.name].byte_count} bytes`,
        downloadLabel: `Download ${spec.label}`, downloadable: artifact.files[spec.name].byte_count > 0 }))}
      onDownload={download} onBundle={() => download('bundle')} />}
  </section>
}
