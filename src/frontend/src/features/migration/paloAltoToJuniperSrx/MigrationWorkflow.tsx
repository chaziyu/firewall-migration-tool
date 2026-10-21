import { useEffect, useRef, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { MigrationStage } from '../types'
import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { downloadFile } from '../migrationApi'
import * as api from './migrationApi'
import type { SRXOptions, SRXReview, SRXWorkspace } from './types'

const emptyOptions = (): SRXOptions => ({ source_scope: null, target_context: 'root', target_version: '25.2R1',
  target_mode: 'standalone', interfaces: {}, zones: {}, interface_zones: {}, routing_table: 'inet.0', vlan_interfaces_available: false })

export function PaloAltoToJuniperSrxWorkflow({ source, sourceKey, stage: controlledStage, onStageChange }: {
  source: SourceEvidence; sourceKey: string; stage?: MigrationStage; onStageChange?: (stage: MigrationStage) => void
}) {
  const saved = workspace().panosMigration
  const [state, setState] = useState<SRXWorkspace>(() => saved?.pairId === 'palo_alto_to_juniper_srx' && saved.sourceKey === sourceKey
    ? saved as SRXWorkspace
    : { pairId: 'palo_alto_to_juniper_srx', sourceKey, options: emptyOptions(), review: null, approval: null, artifact: null, stage: 'load' })
  const [proposal, setProposal] = useState<SRXReview | null>(state.review)
  const [selected, setSelected] = useState<string[]>([])
  const [approvalKeys, setApprovalKeys] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [targetPending, setTargetPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reviewTab, setReviewTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const requestId = useRef(0)
  const { options, review, approval, artifact } = state
  const stage = controlledStage ?? state.stage
  const working = busy || !review

  useEffect(() => { void saveWorkspace({ panosMigration: { ...state, stage } }) }, [state, stage])
  useEffect(() => {
    let active = true
    const request = ++requestId.current
    api.prepare(source, options, state.targetSource).then((result) => {
      if (!active || request !== requestId.current) return
      setProposal(result)
      setState((current) => ({ ...current, review: result }))
      if (!options.source_scope && result.requirements.source_scopes.length === 1) {
        updateOptions({ ...options, source_scope: result.requirements.source_scopes[0] })
      }
    }).catch((cause) => {
      if (active && request === requestId.current) setError(cause instanceof Error ? cause.message : 'Could not prepare the SRX proposal')
    })
    return () => { active = false }
  }, [source, options, state.targetSource])

  function setStage(next: SRXWorkspace['stage']) {
    setState((current) => ({ ...current, stage: next }))
    onStageChange?.(next)
  }
  function updateOptions(next: SRXOptions) {
    requestId.current++
    setState((current) => ({ ...current, options: next, review: null, approval: null, artifact: null }))
    setProposal(null); setSelected([]); setApprovalKeys(null); setError(null)
  }
  function updateTarget(next: DestinationEvidence | null) {
    requestId.current++
    setState((current) => ({ ...current, targetSource: next, review: null, approval: null, artifact: null }))
    setProposal(null); setSelected([]); setApprovalKeys(null); setError(null)
  }
  async function run(action: () => Promise<void>) {
    if (busy) return
    setBusy(true); setError(null)
    try { await action() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'SRX migration request failed') }
    finally { setBusy(false) }
  }
  const currentRows = proposal?.report.items ?? []
  const rowMap = new Map(currentRows.map((row) => [row.key, row]))
  const displayRows = currentRows.map((row) => ({
    key: row.key, family: row.family, sourceScope: row.source_scope, sourceName: row.source_name,
    target: row.target_name, operation: row.render_disposition, settings: row.settings,
    dependencies: row.dependencies, reasons: row.blockers, ready: ['CREATE', 'REUSE'].includes(row.render_disposition) && !row.blockers.length,
  }))
  function expand(keys: string[]) {
    const result = new Set<string>()
    const pending = [...keys]
    while (pending.length) {
      const key = pending.pop()!
      if (result.has(key)) continue
      const row = rowMap.get(key)
      if (!row || row.blockers.length || row.render_disposition === 'BLOCK') throw new Error('Selected configuration has blocked prerequisites')
      result.add(key); pending.push(...row.dependencies)
    }
    return [...result]
  }
  async function confirmApproval() {
    if (!review || !approvalKeys?.length) return
    await run(async () => {
      const result = await api.approve(source, options, review.draft, approvalKeys, state.targetSource)
      setState((current) => ({ ...current, approval: result.approval, artifact: null }))
      setApprovalKeys(null); setStage('export')
      const built = await api.build(source, options, result.approval, state.targetSource)
      setState((current) => ({ ...current, artifact: built.artifact }))
    })
  }
  async function generate() {
    if (!approval) return
    await run(async () => {
      const result = await api.build(source, options, approval, state.targetSource)
      setState((current) => ({ ...current, artifact: result.artifact }))
      setStage('export')
    })
  }
  function download(kind: 'commands' | 'bundle') {
    if (!artifact) return
    void run(async () => {
      const blob = await api.download(source, artifact, kind)
      downloadFile(blob, kind === 'bundle' ? 'migration_palo_alto_to_juniper_srx.zip' : 'juniper_config.set')
    })
  }
  const inputCount = proposal?.requirements.decisions.filter((row) => row.mode === 'REQUIRED' && !row.value).length ?? 0
  const manualCount = currentRows.filter((row) => row.blockers.length).length
  const issueContent = <div><h3>Setup choices and manual work</h3><p>{inputCount} target choices remain. {manualCount} planned items are blocked or manual.</p>
    <ul>{[...new Set(currentRows.flatMap((row) => row.blockers))].map((reason) => <li key={reason}>{reason.replaceAll('_', ' ')}</li>)}</ul>
    {proposal?.report.findings.map((finding) => <p key={finding}>{finding}</p>)}</div>
  return <div className="migration-workflow">
    {error && <ErrorBanner message={error} />}
    {stage === 'load' && <section className="panel"><h2>PAN-OS to Juniper SRX</h2><p>Source analysis is ready. Review source scope and target placement.</p><Button disabled={working} onClick={() => setStage('place')}>Review target setup</Button></section>}
    {stage === 'place' && <section className="panel"><h2>Target setup</h2><p>Standalone Junos 25.2R1. Placement choices are engineer supplied and remain separate from approval.</p>
      <label className="field">PAN-OS source scope<select disabled={busy} value={options.source_scope ?? ''} onChange={(event) => updateOptions({ ...options, source_scope: event.target.value || null, interfaces: {}, zones: {} })}><option value="">Choose a device VSYS</option>{proposal?.requirements.source_scopes.map((scope) => <option key={scope}>{scope}</option>)}</select></label>
      <h3>Interface placement</h3>{proposal?.requirements.decisions.filter((row) => row.family === 'interface').map((row) => <label className="field" key={row.key}>{row.source_name}<input disabled={busy} value={options.interfaces[row.source_name]?.target_interface ?? ''} placeholder="ge-0/0/0" onChange={(event) => {
        const interfaces = { ...options.interfaces }
        if (event.target.value) interfaces[row.source_name] = { target_interface: event.target.value, unit: 0 }
        else delete interfaces[row.source_name]
        updateOptions({ ...options, interfaces })
      }} /></label>)}
      <h3>Security zones</h3>{proposal?.requirements.decisions.filter((row) => row.family === 'zone').map((row) => <label className="field" key={row.key}>{row.source_name}<input disabled={busy} value={options.zones[row.source_name] ?? ''} placeholder={row.source_name} onChange={(event) => {
        const zones = { ...options.zones }
        if (event.target.value) zones[row.source_name] = event.target.value
        else delete zones[row.source_name]
        updateOptions({ ...options, zones })
      }} /></label>)}
      <label className="field"><span><input type="checkbox" checked={options.vlan_interfaces_available} disabled={busy} onChange={(event) => updateOptions({ ...options, vlan_interfaces_available: event.target.checked })} /> Confirm target platform and VLAN logical interfaces are available</span></label>
      <DestinationSnapshot vendor="juniper_srx" families={['addresses', 'applications', 'interfaces', 'zones', 'static_routes', 'policies', 'nat']}
        value={state.targetSource ?? null} disabled={busy || targetPending} onPendingChange={setTargetPending} onChange={updateTarget} />
      <p>Snapshot comparison requires explicit context, version, mode and completeness declarations. It does not verify a live device.</p>
      <Button disabled={working || targetPending || !options.source_scope} onClick={() => { if (review) setState((current) => ({ ...current, review })); setStage('review') }}>Review migration</Button>
    </section>}
    {stage === 'review' && review && <OfflineMigrationReview id="panos-srx" title="Juniper SRX" rows={displayRows} busy={busy || working}
      tab={reviewTab} onTabChange={setReviewTab} inputCount={inputCount} manualCount={manualCount} issueContent={issueContent}
      selected={selected} onSelect={setSelected} approvalKeys={approvalKeys} onPreview={(keys) => {
        try { setApprovalKeys(expand(keys)) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Selection is blocked') }
      }} onApprove={() => void confirmApproval()} onCancel={() => setApprovalKeys(null)} approvalContext={<p>Approval binds this PAN-OS source digest, chosen VSYS, target mappings and exact Junos command bytes.</p>}
      onSetup={() => setStage('place')} approveLabel="Approve and build offline export" />}
    {stage === 'export' && approval && !artifact && <section className="panel" role="status"><h2>Approval is current</h2><p>Artifact generation failed. Retry with this approval.</p><Button disabled={busy} onClick={() => void generate()}>Retry artifact generation</Button></section>}
    {stage === 'export' && artifact && <OfflineMigrationExport artifactId={artifact.artifact_id} partial={manualCount > 0} noChanges={!artifact.command_count}
      verification={artifact.report.verification} busy={busy} files={[{ key: 'set', label: 'Junos set configuration', previewLabel: 'Juniper SRX set commands', text: artifact.command_text,
        sha256: artifact.command_sha256, count: `${artifact.command_count} commands`, downloadLabel: 'Download Junos set file', downloadable: true }]}
      onDownload={(key) => key === 'set' && download('commands')} onBundle={() => download('bundle')}>
      <Button disabled={busy || !approval} onClick={() => void generate()}>Retry artifact generation</Button></OfflineMigrationExport>}
  </div>
}
