import { useEffect, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { MigrationStage } from '../types'
import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { useMigrationReviewActivity } from '../hooks/useMigrationReviewActivity'
import { downloadFile } from '../migrationApi'
import * as api from './migrationApi'
import type { ASAOptions, ASAWorkspace } from './types'
import { approvalSelection } from './reviewSelection'

const emptyOptions = (): ASAOptions => ({ source_scope: null, target_context: 'single', target_version: '9.20', target_mode: 'routed',
  interfaces: {}, new_target_confirmed: false, routing_complete: false, permit_inter_interface: false, permit_intra_interface: false, ace_limit: 256 })

export function PaloAltoToCiscoAsaWorkflow({ source, sourceKey, stage: controlledStage, onStageChange }: {
  source: SourceEvidence; sourceKey: string; stage?: MigrationStage; onStageChange?: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<ASAWorkspace>(() => {
    const saved = workspace().panosMigration
    return saved?.pairId === 'palo_alto_to_cisco_asa' && saved.sourceKey === sourceKey ? saved
      : { pairId: 'palo_alto_to_cisco_asa', sourceKey, options: emptyOptions(), review: null, approval: null, artifact: null, stage: 'place' }
  })
  const [selected, setSelected] = useState<string[]>([])
  const [approvalKeys, setApprovalKeys] = useState<string[] | null>(null)
  const [tab, setTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const [targetPending, setTargetPending] = useState(false)
  const activity = useMigrationReviewActivity({ source, targetSource: state.targetSource?.source ?? null,
    targetDevice: '', workflowMode: 'offline', pairId: 'palo_alto_to_cisco_asa' })
  // These request helpers close over stable refs/setters, not source or target payloads.
  const [requests] = useState(() => ({ begin: activity.beginReviewRequest, finish: activity.finishReviewRequest,
    current: activity.currentReviewVersion, isCurrent: activity.reviewRequestIsCurrent, invalidate: activity.invalidateReviewRequests, run: activity.run }))
  const { setError } = activity
  const { options, review, approval, artifact, targetSource } = state
  const [requirements, setRequirements] = useState(state.review?.requirements)
  const stage = controlledStage ?? state.stage
  const rows = review?.report.items ?? []
  const busy = activity.busy || targetPending
  useEffect(() => { void saveWorkspace({ panosMigration: { ...state, stage } }) }, [state, stage])
  useEffect(() => {
    const request = requests.begin()
    let active = true
    const timer = setTimeout(() => { void api.prepare(source, options, targetSource).then((result) => {
      if (!active || !requests.isCurrent(request)) return
      setRequirements(result.requirements)
      if (!options.source_scope && result.requirements.source_scopes.length === 1) {
        setState((current) => ({ ...current, options: { ...options, source_scope: result.requirements.source_scopes[0] }, review: null }))
      } else setState((current) => ({ ...current, review: result }))
    }).catch((cause) => { if (active && requests.isCurrent(request)) setError(cause instanceof Error ? cause.message : 'ASA proposal failed') })
      .finally(() => { if (active) requests.finish(request) }) }, 250)
    return () => { active = false; clearTimeout(timer); requests.invalidate() }
  }, [source, options, targetSource, requests, setError])
  useEffect(() => () => requests.invalidate(), [requests])

  function setStage(next: MigrationStage) {
    setState((current) => ({ ...current, stage: next }))
    onStageChange?.(next)
  }
  function update(next: Partial<ASAWorkspace>) {
    requests.invalidate()
    setSelected([]); setApprovalKeys(null); setError('')
    setState((current) => ({ ...current, ...next, review: null, approval: null, artifact: null }))
  }
  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = requests.current()
    const result = await api.build(source, options, currentApproval, targetSource)
    if (requests.isCurrent(request)) { setState((current) => ({ ...current, artifact: result.artifact })); setStage('export') }
  }
  async function approve() {
    if (!review || !approvalKeys) return
    const request = requests.current()
    const result = await api.approve(source, options, review.draft, approvalKeys, targetSource)
    if (!requests.isCurrent(request)) return
    setState((current) => ({ ...current, approval: result.approval, artifact: null }))
    setApprovalKeys(null); setStage('export')
    await generate(result.approval)
  }
  function download(kind: 'commands' | 'bundle') {
    if (!artifact) return
    const request = requests.current()
    void requests.run(async () => {
      const blob = await api.download(source, artifact, kind)
      if (requests.isCurrent(request)) downloadFile(blob, kind === 'bundle' ? 'migration_palo_alto_to_cisco_asa.zip' : 'asa_config.cfg')
    })
  }
  const manual = rows.filter((row) => row.blockers.length)
  const inputCount = review?.requirements.decisions.filter((row) => row.mode === 'REQUIRED' && !row.value).length ?? 0
  return <section className="panel" aria-label="PAN-OS to Cisco ASA">
    <h2>PAN-OS → Cisco ASA</h2><p>ASA 9.20 routed single context. Offline export only. Review hardware, cabling and capacity separately.</p>
    {activity.error && <ErrorBanner message={activity.error} />}
    {activity.busy && <p role="status">Preparing reviewed migration…</p>}
    {stage === 'load' && <Button disabled={busy || !review} onClick={() => setStage('place')}>Continue to target setup</Button>}
    {stage === 'place' && <>
      <h3>Target setup</h3><p>The target profile is proposed. Enter the actual ports, nameifs and security levels. No choice grants approval.</p>
      <label className="field">PAN-OS source scope<select disabled={activity.actionBusy || targetPending} value={options.source_scope ?? ''} onChange={(event) => update({ options: { ...options, source_scope: event.target.value || null, interfaces: {} } })}>
        <option value="">Choose a device VSYS</option>{requirements?.source_scopes.map((scope) => <option key={scope}>{scope}</option>)}</select></label>
      {requirements?.decisions.filter((row) => row.family === 'interface').map((row) => {
        const mapping = options.interfaces[row.source_name]
        return <fieldset key={row.key} disabled={activity.actionBusy || targetPending}><legend>{row.source_name}</legend>
          <label className="field">Target port for {row.source_name}<input placeholder="GigabitEthernet0/0" value={mapping?.target_interface ?? ''} onChange={(event) => update({ options: { ...options, interfaces: { ...options.interfaces,
            [row.source_name]: { target_interface: event.target.value, nameif: mapping?.nameif ?? '', security_level: mapping?.security_level ?? 0 } } } })} /></label>
          <label className="field">Nameif for {row.source_name}<input value={mapping?.nameif ?? ''} onChange={(event) => update({ options: { ...options, interfaces: { ...options.interfaces,
            [row.source_name]: { target_interface: mapping?.target_interface ?? '', nameif: event.target.value, security_level: mapping?.security_level ?? 0 } } } })} /></label>
          <label className="field">Security level for {row.source_name}<input type="number" min={0} max={100} value={mapping?.security_level ?? 0} onChange={(event) => update({ options: { ...options, interfaces: { ...options.interfaces,
            [row.source_name]: { target_interface: mapping?.target_interface ?? '', nameif: mapping?.nameif ?? '', security_level: Number(event.target.value) } } } })} /></label>
        </fieldset>
      })}
      {([['new_target_confirmed', 'Confirm a new empty routed single-context target with no existing ACLs, bindings, NAT, inspection or policy routing'],
        ['routing_complete', 'Confirm source connected/static routing evidence is complete; no dynamic or policy-based forwarding'],
        ['permit_inter_interface', 'Approve same-security inter-interface permission, guarded by all reviewed ACL bindings'],
        ['permit_intra_interface', 'Approve intra-interface permission, guarded by all reviewed ACL bindings']] as const).map(([key, label]) => <label className="field" key={key}>
          <span><input type="checkbox" disabled={busy} checked={options[key]} onChange={(event) => update({ options: { ...options, [key]: event.target.checked } })} /> {label}</span></label>)}
      <DestinationSnapshot vendor="cisco_asa" families={['addresses', 'services', 'interfaces', 'static_routes', 'policies', 'nat', 'acl_bindings']} value={targetSource ?? null}
        disabled={busy} onPendingChange={setTargetPending} onChange={(next: DestinationEvidence | null) => update({ targetSource: next })} />
      <p>Optional snapshots support exact object comparison. Existing-target traffic placement stays blocked.</p>
      <Button disabled={busy || !review} onClick={() => setStage('review')}>Review migration</Button>
    </>}
    {stage === 'review' && review && <OfflineMigrationReview id="panos-asa" title="Cisco ASA" rows={rows.map((row) => ({ key: row.key, family: row.family,
      sourceScope: row.source_scope, sourceName: row.source_name, target: row.target_name, operation: row.render_disposition,
      settings: row.settings, dependencies: row.dependencies, reasons: row.blockers, ready: ['CREATE', 'REUSE'].includes(row.render_disposition) && !row.blockers.length }))}
      busy={busy} tab={tab} onTabChange={setTab} inputCount={inputCount} manualCount={manual.length}
      issueContent={<><h3>Remaining choices and manual work</h3><p>{inputCount} setup choices; {manual.length} blocked or manual items.</p><ul>{[...new Set(manual.flatMap((row) => row.blockers))].map((reason) => <li key={reason}>{reason.replaceAll('_', ' ')}</li>)}</ul></>}
      selected={selected} onSelect={(keys) => { setSelected(keys); setApprovalKeys(null) }} approvalKeys={approvalKeys}
      onPreview={(keys) => { try { setApprovalKeys(approvalSelection(rows, keys)) } catch (cause) { setError(String(cause)) } }}
      onApprove={() => void requests.run(approve)} onCancel={() => setApprovalKeys(null)}
      approvalContext={<><p>Traffic is one approval unit: interfaces remain shut down until all ACLs and bindings are installed. Approval binds exact commands and these target choices.</p><pre className="set-command-preview">{JSON.stringify(options, null, 2)}</pre></>}
      onSetup={() => setStage('place')} approveLabel="Approve and build offline export" />}
    {stage === 'export' && !artifact && <p>Review and approve current changes before download.</p>}
    {stage === 'export' && approval && !artifact && <Button disabled={busy} onClick={() => void requests.run(() => generate())}>Retry generation with current approval</Button>}
    {stage === 'export' && artifact && <OfflineMigrationExport artifactId={artifact.artifact_id} partial={manual.length > 0 || rows.some((row) => !approval || !(approval.selected_items as string[] | undefined)?.includes(row.key))}
      noChanges={!artifact.command_count} verification={artifact.report.verification} busy={busy}
      files={[{ key: 'cli', label: 'Approved ASA CLI configuration', previewLabel: 'Cisco ASA command preview', text: artifact.command_text, sha256: artifact.command_sha256,
        count: `${artifact.command_count} CLI lines`, downloadLabel: 'Download ASA .cfg', downloadable: artifact.command_count > 0 }]}
      onDownload={() => download('commands')} onBundle={() => download('bundle')} />}
  </section>
}
