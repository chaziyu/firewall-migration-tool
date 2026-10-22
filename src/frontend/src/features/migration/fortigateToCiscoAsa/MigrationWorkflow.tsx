import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { MigrationCoverage } from '../components/MigrationCoverage'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { useEffect, useRef, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { LoadingState } from '../../../components/common/LoadingState'
import { workspace, saveWorkspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { MigrationStage } from '../types'
import { downloadFile } from '../migrationApi'
import * as api from './migrationApi'
import type { AsaOptions, AsaPlanItem, CiscoAsaWorkspace } from './types'

const PAIR_ID = 'fortigate_to_cisco_asa' as const
const emptyOptions = (): AsaOptions => ({
  source_vdom: '', target_context: '', target_version: '', target_mode: '', interfaces: {},
  source_timezone: '', target_timezone: '', nat_evidence: {},
})

function payloadOptions(options: AsaOptions): AsaOptions {
  const interfaces = Object.fromEntries(Object.entries(options.interfaces).flatMap(([vdom, mappings]) => {
    const complete = Object.fromEntries(Object.entries(mappings).filter(([, mapping]) =>
      Boolean(mapping.interface?.trim()) && Boolean(mapping.nameif?.trim()) && Number.isInteger(mapping.security_level)
      && mapping.security_level! >= 0 && mapping.security_level! <= 100,
    ).map(([name, mapping]) => [name, { interface: mapping.interface!.trim(), nameif: mapping.nameif!.trim(), security_level: mapping.security_level! }]))
    return Object.keys(complete).length ? [[vdom, complete]] : []
  }))
  return { ...options, interfaces }
}

function expandSelection(items: AsaPlanItem[], selected: string[]): string[] {
  const byKey = new Map(items.map((item) => [item.key, item]))
  const groups = new Map<string, string[]>()
  for (const item of items) {
    if (item.approval_group) groups.set(item.approval_group, [...(groups.get(item.approval_group) ?? []), item.key])
  }
  const expandedGroups = new Set<string>()
  const expanded = new Set<string>()
  const visiting = new Set<string>()
  const add = (key: string) => {
    if (visiting.has(key)) throw new Error('A dependency cycle blocks this selection')
    if (expanded.has(key)) return
    const item = byKey.get(key)
    if (!item || !['CREATE', 'REUSE'].includes(item.render_disposition) || item.blockers.length) throw new Error('A selected item or required dependency is blocked')
    visiting.add(key)
    item.dependencies.forEach(add)
    visiting.delete(key)
    expanded.add(key)
  }
  selected.forEach(add)
  for (const key of expanded) {
    const group = byKey.get(key)?.approval_group
    if (group && !expandedGroups.has(group)) {
      expandedGroups.add(group)
      for (const member of groups.get(group) ?? []) add(member)
    }
  }
  return items.filter((item) => expanded.has(item.key)).map((item) => item.key)
}

export function CiscoAsaMigrationWorkflow({ source, sourceKey, stage, onStageChange }: {
  source: SourceEvidence
  sourceKey: string
  stage: MigrationStage
  onStageChange: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<CiscoAsaWorkspace>(() => {
    const saved = workspace().panosMigration
    return saved?.pairId === PAIR_ID && saved.sourceKey === sourceKey
      ? saved
      : { pairId: PAIR_ID, sourceKey, options: emptyOptions(), requirements: [], review: null, approval: null, artifact: null, previewText: null }
  })
  const [hasSchedules, setHasSchedules] = useState(Boolean(state.review?.report.items.some((item) => item.family === 'schedule')))
  const [targetLoading, setTargetLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [preparing, setPreparing] = useState(false)
  const [reviewTab, setReviewTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const [selected, setSelected] = useState<string[]>([])
  const [approvalPreview, setApprovalPreview] = useState<string[] | null>(null)
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, requirements, review, approval, artifact } = state

  useEffect(() => { void saveWorkspace({ panosMigration: { ...state, stage } }) }, [state, stage])
  useEffect(() => () => { requests.current++ }, [])
  useEffect(() => {
    let active = true
    const request = ++requests.current

    const timer = setTimeout(() => { setPreparing(true); void api.prepare(source, payloadOptions(options), state.destination).then((result) => {
      if (!active || request !== requests.current) return
      const nextOptions = { ...options, ...result.options, interfaces: { ...options.interfaces } }
      for (const proposal of result.report.proposals ?? []) {
        const scope = proposal.source_vdom
        nextOptions.interfaces[scope] = { ...nextOptions.interfaces[scope],
          [proposal.source_name]: { ...proposal.value, ...options.interfaces[scope]?.[proposal.source_name] } }
      }
      setState((current) => ({ ...current, requirements: result.requirements, review: JSON.stringify(nextOptions) === JSON.stringify(options) ? result : null,
        options: JSON.stringify(nextOptions) === JSON.stringify(options) ? options : nextOptions,
        ...(JSON.stringify(nextOptions) === JSON.stringify(options) ? {} : { approval: null, artifact: null }) }))
      setHasSchedules(result.report.items.some((item) => item.family === 'schedule'))
    }).catch((cause) => { if (active && request === requests.current) setError(cause instanceof Error ? cause.message : 'Could not prepare conversion') })
      .finally(() => { if (active) setPreparing(false) }) }, 250)
    return () => { active = false; clearTimeout(timer) }
  }, [source, options, state.destination])

  function changeOptions(next: AsaOptions) {
    requests.current++
    setState((current) => ({ ...current, options: next, review: null, approval: null, artifact: null, previewText: null }))
    setApprovalPreview(null); setSelected([]); setError(null)
  }

  function changeDestination(destination: DestinationEvidence | null) {
    requests.current++
    setState((current) => ({ ...current, destination, review: null, approval: null, artifact: null, previewText: null }))
    setApprovalPreview(null); setSelected([]); setError(null)
  }

  async function run(action: () => Promise<void>) {
    if (pending.current) return
    pending.current = true; setBusy(true); setError(null)
    try { await action() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'ASA migration request failed') }
    finally { pending.current = false; setBusy(false) }
  }

  async function prepareReview() {
    const request = ++requests.current
    setState((current) => ({ ...current, approval: null, artifact: null, previewText: null }))
    const result = await api.prepare(source, payloadOptions(options), state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, requirements: result.requirements, review: result }))
    setHasSchedules(result.report.items.some((item) => item.family === 'schedule'))
    setSelected([]); setApprovalPreview(null); onStageChange('review')
  }

  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = ++requests.current
    const result = await api.build(source, payloadOptions(options), currentApproval, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, artifact: result.artifact, previewText: null }))
    onStageChange('export')
    const preview = await api.commandPreview(result.artifact)
    if (request !== requests.current) return
    if (preview.command_sha256 !== result.artifact.command_sha256
      || (result.artifact.command_text !== undefined && preview.text !== result.artifact.command_text)) {
      throw new Error('Command preview integrity check failed')
    }
    setState((current) => ({ ...current, previewText: preview.text }))
  }

  async function confirmApproval() {
    if (!review || !approvalPreview?.length) return
    const request = ++requests.current
    const result = await api.approve(source, payloadOptions(options), review.draft, approvalPreview, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, approval: result.approval, artifact: null, previewText: null }))
    setApprovalPreview(null); onStageChange('export')
    await generate(result.approval)
  }

  function setGlobal(field: 'source_vdom' | 'target_context' | 'target_version' | 'target_mode', value: string) {
    changeOptions({ ...options, [field]: value })
  }

  function setInterface(vdom: string, name: string, field: 'interface' | 'nameif' | 'security_level', value: string) {
    const mapping = { ...options.interfaces[vdom]?.[name] }
    if (field === 'security_level') {
      if (value === '') delete mapping.security_level
      else mapping.security_level = Number(value)
    } else if (value) mapping[field] = value
    else delete mapping[field]
    const vdomMappings = { ...options.interfaces[vdom] }
    if (Object.keys(mapping).length) vdomMappings[name] = mapping
    else delete vdomMappings[name]
    const interfaces = { ...options.interfaces }
    if (Object.keys(vdomMappings).length) interfaces[vdom] = vdomMappings
    else delete interfaces[vdom]
    changeOptions({ ...options, interfaces })
  }

  function setTimezone(field: 'source_timezone' | 'target_timezone', value: string) {
    changeOptions({ ...options, [field]: value })
  }

  const sourceScope = requirements.find((item) => item.target_field === 'source_vdom')
  const scoped = requirements.filter((item) => item.source_vdom === options.source_vdom)
  const interfaceRequirements = scoped.filter((item) => item.target_field === 'asa_interface')
  const targetChoice = (field: string) => requirements.find((item) => item.target_field === field)

  const unresolvedInputs = requirements.filter((item) => (item.value == null || item.value === '' || item.value === false))
  return <section className="panel" aria-labelledby="cisco-asa-migration-title">
    <h2 id="cisco-asa-migration-title">FortiGate → Cisco ASA</h2>
    <p>Review and export a Cisco ASA 9.20 routed configuration. Export is offline; device execution is unavailable.</p>
    {stage === 'load' && <>
      <p>Source: {source.source_name || 'Loaded FortiGate configuration'}</p>
      <p>The source stays unchanged. Unsupported and unmapped items remain visible as manual work.</p>
      <Button disabled={busy} onClick={() => onStageChange('place')}>Set up ASA target</Button>
    </>}
    {(stage === 'place' || stage === 'review') && <details open={stage === 'place'}><summary>Target setup and choices</summary>
      <DestinationSnapshot vendor="cisco_asa" families={['interfaces', 'objects', 'schedules', 'routes', 'access_rules', 'acl_bindings', 'nat']} value={state.destination ?? null} disabled={busy} onChange={changeDestination} onPendingChange={setTargetLoading} />
      <h3>Target context</h3>
      <label className="field">Target VLAN platform<select disabled={busy} value={options.target_platform ?? ''} onChange={(event) => changeOptions({ ...options, target_platform: event.target.value })}><option value="">VLAN export unavailable</option><option value="asav">ASAv 9.20</option></select></label>
      <label className="field"><span><input disabled={busy} type="checkbox" checked={options.vlan_interfaces_available ?? false} onChange={(event) => changeOptions({ ...options, vlan_interfaces_available: event.target.checked })} /> I verified VLAN capacity and mapped parent/subinterface availability</span></label>
      {requirements.filter((item) => item.target_field === 'nat_return_routing').map((item) => <label className="field" key={item.key}><span><input disabled={busy} type="checkbox" checked={options.nat_evidence?.[item.key]?.return_routing_confirmed ?? false} onChange={(event) => changeOptions({ ...options, nat_evidence: { ...options.nat_evidence, [item.key]: { ...options.nat_evidence?.[item.key], return_routing_confirmed: event.target.checked } } })} /> {item.label} ({item.source_vdom} / {item.source_name})</span></label>)}
      <label className="field">FortiGate VDOM<select disabled={busy} value={options.source_vdom} onChange={(event) => setGlobal('source_vdom', event.target.value)}><option value="">Choose source VDOM</option>{sourceScope?.choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>
      {(['target_context', 'target_version', 'target_mode'] as const).map((field) => {
        const requirement = targetChoice(field)
        return <label className="field" key={field}>{requirement?.label ?? field}<select disabled={busy} value={options[field]} onChange={(event) => setGlobal(field, event.target.value)}><option value="">Choose explicitly</option>{requirement?.choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>
      })}
      {options.source_vdom && <>
        <h3>Interface placement</h3>
        {interfaceRequirements.map((item) => {
          const mapping = options.interfaces[options.source_vdom]?.[item.source_name] ?? {}
          return <div className="connection-grid" key={item.key}>
            <strong>{item.source_name}</strong>
            <label className="field">ASA interface<input disabled={busy} value={mapping.interface ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'interface', event.target.value)} placeholder="GigabitEthernet0/1" /></label>
            <label className="field">ASA nameif<input disabled={busy} value={mapping.nameif ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'nameif', event.target.value)} /></label>
            <label className="field">ASA security level<input disabled={busy} type="number" min="0" max="100" step="1" value={mapping.security_level ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'security_level', event.target.value)} /></label>
          </div>
        })}
      </>}
      {hasSchedules && <>
        <h3>Schedule time zone</h3>
        <label className="field">Confirmed FortiGate time zone<input disabled={busy} value={options.source_timezone} onChange={(event) => setTimezone('source_timezone', event.target.value)} placeholder="Asia/Kuala_Lumpur" /></label>
        <label className="field">Confirmed ASA time zone<input disabled={busy} value={options.target_timezone} onChange={(event) => setTimezone('target_timezone', event.target.value)} placeholder="Asia/Kuala_Lumpur" /></label>
      </>}
      <details>
        <summary>Mapping proposals</summary>
        <p>Imported values are proposals. They do not restore or create engineer approval.</p>
        <Button disabled={busy} onClick={() => void run(async () => {
          const result = await api.exportDecisions(source, payloadOptions(options))
          downloadFile(new Blob([JSON.stringify(result.document, null, 2)], { type: 'application/json' }), 'fortigate_to_cisco_asa_decisions.json')
        })}>Download mapping proposals</Button>
        <label className="field">Import mapping proposals<input disabled={busy} type="file" accept=".json,application/json" onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) void run(async () => {
            const result = await api.importDecisions(source, JSON.parse(await file.text()))
            changeOptions({ ...emptyOptions(), ...result.options })
          })
          event.target.value = ''
        }} /></label>
      </details>
      <Button disabled={busy || targetLoading} onClick={() => void run(prepareReview)}>Prepare migration review</Button>
    </details>}
    {(stage === 'review' || stage === 'place') && review && <>
      <MigrationCoverage coverage={review.report.coverage} />
      <OfflineMigrationReview id="fg-asa" title="Cisco ASA" rows={review.report.items.map((item) => ({
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

    {stage === 'export' && <>
      {approval && !artifact && <Button disabled={busy} onClick={() => void run(() => generate())}>Retry with current approval</Button>}
      {!approval && <p>Review and approve the current plan before exporting.</p>}
      {artifact && <OfflineMigrationExport dispositions={artifact.report.items.map((row) => row.render_disposition)} artifactId={artifact.artifact_id}
        partial={Object.entries(artifact.report.coverage?.status_counts ?? {}).some(([status, count]) => count > 0 && !['RENDERED', 'REUSED'].includes(status)) || artifact.report.items.some((item) => !['CREATE', 'REUSE'].includes(item.render_disposition))}
        noChanges={!artifact.command_count && artifact.report.items.length > 0 && artifact.report.items.every((item) => item.render_disposition === 'REUSE')}
        verification={String(artifact.report.verification ?? 'Offline export; device acceptance remains unverified.')}
        busy={busy || targetLoading} files={[{ key: 'commands', label: 'ASA CLI configuration', previewLabel: 'Cisco ASA command preview', text: artifact.command_text ?? '',
          sha256: artifact.command_sha256, count: `${artifact.command_count} commands`, downloadLabel: 'Download ASA', downloadable: true }]}
        onDownload={() => void run(async () => { const request = requests.current; const blob = await api.download(source, artifact, 'commands'); if (request === requests.current) downloadFile(blob, 'asa_config.cfg') })}
        onBundle={() => void run(async () => { const request = requests.current; const blob = await api.download(source, artifact, 'bundle'); if (request === requests.current) downloadFile(blob, 'migration_fortigate_to_cisco_asa.zip') })}>
        <MigrationCoverage coverage={artifact.report.coverage} />
      </OfflineMigrationExport>}
    </>}
    {busy && <LoadingState label="Preparing reviewed ASA migration…" />}
    {error && <ErrorBanner message={error} />}
  </section>
}
