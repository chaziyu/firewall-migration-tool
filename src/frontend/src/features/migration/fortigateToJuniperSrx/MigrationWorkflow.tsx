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
import type { JuniperSrxWorkspace, SrxOptions, SrxPlanItem } from './types'

const PAIR_ID = 'fortigate_to_juniper_srx' as const
const emptyOptions = (): SrxOptions => ({
  source_vdom: '', target_context: '', target_version: '', target_mode: '', routing_table: '', timezone: '',
  interfaces: {}, zones: {},
})

function payloadOptions(options: SrxOptions): SrxOptions {
  const interfaces = Object.fromEntries(Object.entries(options.interfaces).flatMap(([vdom, mappings]) => {
    const complete = Object.fromEntries(Object.entries(mappings).filter(([, mapping]) =>
      Boolean(mapping.target_interface?.trim()) && Number.isInteger(mapping.unit) && (mapping.unit ?? -1) >= 0,
    ).map(([name, mapping]) => [name, { target_interface: mapping.target_interface!.trim(), unit: mapping.unit! }]))
    return Object.keys(complete).length ? [[vdom, complete]] : []
  }))
  const zones = Object.fromEntries(Object.entries(options.zones).flatMap(([vdom, mappings]) => {
    const complete = Object.fromEntries(Object.entries(mappings).filter(([, target]) => Boolean(target.trim())))
    return Object.keys(complete).length ? [[vdom, complete]] : []
  }))
  return { ...options, interfaces, zones }
}

function expandSelection(items: SrxPlanItem[], selected: string[]): string[] {
  const byKey = new Map(items.map((item) => [item.key, item]))
  const groups = new Map<string, string[]>()
  for (const item of items) {
    if (item.approval_group) groups.set(item.approval_group, [...(groups.get(item.approval_group) ?? []), item.key])
  }
  const expanded = new Set<string>()
  const visiting = new Set<string>()
  const expandedGroups = new Set<string>()
  const add = (key: string) => {
    if (visiting.has(key)) throw new Error('A dependency cycle blocks this selection')
    if (expanded.has(key)) return
    const item = byKey.get(key)
    if (!item || !['CREATE', 'REUSE'].includes(item.render_disposition) || item.blockers.length) throw new Error('A selected item or required group is blocked')
    visiting.add(key)
    for (const dependency of item.dependencies) add(dependency)
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

export function JuniperSRXMigrationWorkflow({ source, sourceKey, stage, onStageChange }: {
  source: SourceEvidence
  sourceKey: string
  stage: MigrationStage
  onStageChange: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<JuniperSrxWorkspace>(() => {
    const saved = workspace().newPairMigration
    return saved?.pairId === PAIR_ID && saved.sourceKey === sourceKey
      ? saved
      : { pairId: PAIR_ID, sourceKey, options: emptyOptions(), requirements: [], review: null, approval: null, artifact: null, previewText: null }
  })
  const [hasSchedules, setHasSchedules] = useState(Boolean(state.review?.report.items.some((item) => item.family === 'schedule')))
  const [targetLoading, setTargetLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [approvalPreview, setApprovalPreview] = useState<string[] | null>(null)
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, requirements, review, approval, artifact } = state
  const initialOptions = useRef(payloadOptions(options))

  useEffect(() => { void saveWorkspace({ newPairMigration: state }) }, [state])
  useEffect(() => () => { requests.current++ }, [])
  useEffect(() => {
    let active = true
    api.requirements(source, { ...initialOptions.current, source_vdom: options.source_vdom }).then((result) => {
      if (active) {
        setState((current) => ({ ...current, requirements: result.requirements }))
        setHasSchedules(Boolean(result.report?.items.some((item) => item.family === 'schedule')))
      }
    }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : 'Could not load SRX placement requirements') })
    return () => { active = false }
  }, [source, sourceKey, options.source_vdom])

  function changeOptions(next: SrxOptions) {
    requests.current++
    setState((current) => ({ ...current, options: next, review: null, approval: null, artifact: null, previewText: null }))
    setApprovalPreview(null)
    setSelected([])
    setError(null)
  }

  function changeDestination(destination: DestinationEvidence | null) {
    requests.current++
    setState((current) => ({ ...current, destination, review: null, approval: null, artifact: null, previewText: null }))
    setApprovalPreview(null); setSelected([]); setError(null)
  }

  async function run(action: () => Promise<void>) {
    if (pending.current) return
    pending.current = true
    setBusy(true)
    setError(null)
    try { await action() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'SRX migration request failed') }
    finally { pending.current = false; setBusy(false) }
  }

  async function prepareReview() {
    const request = ++requests.current
    const normalized = payloadOptions(options)
    setState((current) => ({ ...current, approval: null, artifact: null, previewText: null }))
    const result = await api.prepare(source, normalized, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, options: normalized, requirements: result.requirements, review: result }))
    setHasSchedules(result.report.items.some((item) => item.family === 'schedule'))
    setSelected([])
    setApprovalPreview(null)
    onStageChange('review')
  }

  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = ++requests.current
    const result = await api.build(source, payloadOptions(options), currentApproval, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, artifact: result.artifact, previewText: null }))
    onStageChange('export')
    const preview = await api.commandPreview(result.artifact)
    if (request === requests.current && preview.command_sha256 === result.artifact.command_sha256) {
      setState((current) => ({ ...current, previewText: preview.text }))
    }
  }

  async function confirmApproval() {
    if (!review || !approvalPreview?.length) return
    const request = ++requests.current
    const result = await api.approve(source, payloadOptions(options), review.draft, approvalPreview, state.destination)
    if (request !== requests.current) return
    setState((current) => ({ ...current, approval: result.approval, artifact: null, previewText: null }))
    setApprovalPreview(null)
    onStageChange('export')
    await generate(result.approval)
  }

  function setGlobal(field: 'source_vdom' | 'target_context' | 'target_version' | 'target_mode' | 'routing_table' | 'timezone', value: string) {
    changeOptions({ ...options, [field]: value })
  }

  function setInterface(vdom: string, name: string, field: 'target_interface' | 'unit', value: string) {
    const mapping = { ...options.interfaces[vdom]?.[name] }
    if (field === 'target_interface') {
      if (value) mapping.target_interface = value
      else delete mapping.target_interface
    } else if (value === '') delete mapping.unit
    else mapping.unit = Number(value)
    const vdomMappings = { ...options.interfaces[vdom] }
    if (Object.keys(mapping).length) vdomMappings[name] = mapping
    else delete vdomMappings[name]
    const interfaces = { ...options.interfaces }
    if (Object.keys(vdomMappings).length) interfaces[vdom] = vdomMappings
    else delete interfaces[vdom]
    changeOptions({ ...options, interfaces })
  }

  function setZone(vdom: string, name: string, value: string) {
    const vdomMappings = { ...options.zones[vdom] }
    if (value) vdomMappings[name] = value
    else delete vdomMappings[name]
    const zones = { ...options.zones }
    if (Object.keys(vdomMappings).length) zones[vdom] = vdomMappings
    else delete zones[vdom]
    changeOptions({ ...options, zones })
  }

  function openApprovalPreview(keys: string[]) {
    if (!review) return
    setApprovalPreview(expandSelection(review.report.items, keys))
  }

  const sourceScope = requirements.find((item) => item.target_field === 'source_vdom')
  const scopeRequirements = requirements.filter((item) => item.source_vdom === options.source_vdom)
  const interfaceRequirements = scopeRequirements.filter((item) => item.source_kind === 'interface' && item.target_field === 'target_interface')
  const zoneRequirements = scopeRequirements.filter((item) => item.source_kind === 'zone' && item.target_field === 'target_zone')
  const targetChoice = (field: string) => requirements.find((item) => item.target_field === field)
  const createItems = review?.report.items.filter((item) => ['CREATE', 'REUSE'].includes(item.render_disposition)) ?? []
  const approvalItems = review?.report.items.filter((item) => approvalPreview?.includes(item.key)) ?? []

  return <section className="panel" aria-labelledby="juniper-srx-migration-title">
    <h2 id="juniper-srx-migration-title">FortiGate → Juniper SRX</h2>
    <p>Review and export a Junos 25.2R1 set file with optional destination snapshot comparison. Device execution is unavailable.</p>
    {stage === 'load' && <>
      <p>Source: {source.source_name || 'Loaded FortiGate configuration'}</p>
      <p>The source stays unchanged. Unmapped and unsupported items remain visible as manual work.</p>
      <Button disabled={busy} onClick={() => onStageChange('place')}>Set up SRX target</Button>
    </>}

    {stage === 'place' && <>
      <DestinationSnapshot vendor="juniper_srx" families={['addresses', 'applications', 'interfaces', 'zones', 'static_routes', 'schedules', 'policies', 'nat']} value={state.destination ?? null} disabled={busy} onChange={changeDestination} onPendingChange={setTargetLoading} />
      <h3>Target context</h3>
      <label className="field">Target VLAN platform<select disabled={busy} value={options.target_platform ?? ''} onChange={(event) => changeOptions({ ...options, target_platform: event.target.value })}><option value="">VLAN export unavailable</option><option value="vsrx">vSRX 25.2R1 (tagged-only parent)</option></select></label>
      <label className="field"><span><input disabled={busy} type="checkbox" checked={options.vlan_interfaces_available ?? false} onChange={(event) => changeOptions({ ...options, vlan_interfaces_available: event.target.checked })} /> I verified VLAN capacity and mapped parent/unit availability</span></label>
      <label className="field"><span><input disabled={busy} type="checkbox" checked={options.nat_return_routing_confirmed ?? false} onChange={(event) => changeOptions({ ...options, nat_return_routing_confirmed: event.target.checked })} /> I confirmed return routing for the source NAT pool</span></label>
      <label className="field">FortiGate VDOM<select disabled={busy} value={options.source_vdom} onChange={(event) => setGlobal('source_vdom', event.target.value)}><option value="">Choose source VDOM</option>{sourceScope?.choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>
      {(['target_context', 'target_version', 'target_mode', 'routing_table'] as const).map((field) => {
        const requirement = targetChoice(field)
        const label = requirement?.label ?? field
        return <label className="field" key={field}>{label}<select disabled={busy} value={options[field]} onChange={(event) => setGlobal(field, event.target.value)}><option value="">Choose explicitly</option>{requirement?.choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>
      })}
      {hasSchedules && <label className="field">Confirmed FortiGate and SRX system timezone<input disabled={busy} value={options.timezone} onChange={(event) => setGlobal('timezone', event.target.value)} placeholder="Asia/Kuala_Lumpur" /></label>}

      {options.source_vdom && <>
        <h3>Interface placement</h3>
        {interfaceRequirements.map((item) => <div className="connection-grid" key={item.key}>
          <strong>{item.label}</strong>
          <label className="field">Target physical interface<input disabled={busy} value={options.interfaces[options.source_vdom]?.[item.source_name]?.target_interface ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'target_interface', event.target.value)} placeholder="ge-0/0/0" /></label>
          <label className="field">Logical unit<input disabled={busy} type="number" min="0" max="16385" step="1" value={options.interfaces[options.source_vdom]?.[item.source_name]?.unit ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'unit', event.target.value)} /></label>
        </div>)}
        <h3>Security zone placement</h3>
        {zoneRequirements.map((item) => <label className="field" key={item.key}>{item.label}<input disabled={busy} value={options.zones[options.source_vdom]?.[item.source_name] ?? ''} onChange={(event) => setZone(options.source_vdom, item.source_name, event.target.value)} placeholder="inside-zone" /></label>)}
      </>}

      <details>
        <summary>Mapping proposals</summary>
        <p>Imported values are proposals. They do not restore or create engineer approval.</p>
        <Button disabled={busy} onClick={() => void run(async () => {
          const result = await api.exportDecisions(source, payloadOptions(options))
          downloadFile(new Blob([JSON.stringify(result.document, null, 2)], { type: 'application/json' }), 'fortigate_to_juniper_srx_decisions.json')
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
    </>}

    {stage === 'review' && <>
      {!review ? <><p>Prepare the current target choices before review.</p><Button disabled={busy || targetLoading} onClick={() => void run(prepareReview)}>Prepare migration review</Button></> : <>
        <MigrationCoverage coverage={review.report.coverage} />
        <p>{createItems.length} items ready for review · {review.report.items.length - createItems.length} blocked or manual.</p>
        {review.report.findings.map((finding, index) => <p role="status" key={`${String(finding.code)}-${index}`}>{String(finding.message ?? finding.code)}</p>)}
        <Button disabled={busy || !createItems.length} onClick={() => openApprovalPreview(createItems.map((item) => item.key))}>Review all ready changes</Button>
        <Button disabled={busy || !selected.length} onClick={() => void run(async () => openApprovalPreview(selected))}>Review selected changes</Button>
        <div className="report-table-wrap"><table className="report-table"><caption>Planned Juniper SRX configuration</caption><thead><tr><th>Select</th><th>Source</th><th>Target</th><th>Operation</th><th>Blockers</th><th>Review details</th></tr></thead><tbody>{review.report.items.map((item) => <tr key={item.key}>
          <td><input aria-label={`Select ${item.source_vdom} ${item.source_name}`} type="checkbox" disabled={busy || !['CREATE', 'REUSE'].includes(item.render_disposition)} checked={selected.includes(item.key)} onChange={(event) => setSelected(event.target.checked ? [...selected, item.key] : selected.filter((key) => key !== item.key))} /></td>
          <td>{item.source_vdom} / {item.source_name}<small>{item.family}</small></td><td>{item.target_name}</td><td>{item.render_disposition}</td><td>{item.blockers.join(', ')}</td>
          <td><details><summary>Settings and dependencies</summary><pre>{JSON.stringify({ settings: item.settings, dependencies: item.dependencies, approval_group: item.approval_group, guidance: item.guidance }, null, 2)}</pre></details></td>
        </tr>)}</tbody></table></div>
        {approvalPreview && <section className="review-work-card" aria-label="SRX approval preview">
          <h3>Approve these exact changes</h3><p>{approvalItems.length} items, including required dependencies and atomic groups.</p>
          {approvalItems.map((item) => <details key={item.key}><summary>{item.render_disposition}: {item.source_vdom} / {item.source_name} → {item.target_name}</summary><pre>{JSON.stringify({ settings: item.settings, dependencies: item.dependencies, approval_group: item.approval_group }, null, 2)}</pre></details>)}
          <Button disabled={busy || !approvalPreview.length} onClick={() => void run(confirmApproval)}>Approve these changes and build export</Button>
          <Button disabled={busy} onClick={() => setApprovalPreview(null)}>Cancel approval preview</Button>
        </section>}
        <Button disabled={busy} onClick={() => onStageChange('place')}>Change target choices</Button>
      </>}
    </>}

    {stage === 'export' && <>
      {approval && !artifact && <Button disabled={busy} onClick={() => void run(() => generate())}>Retry with current approval</Button>}
      {!approval && <p>Review and approve the current plan before exporting.</p>}
      {artifact && <>
        <h3>{artifact.report.plan_status === 'READY_WITH_MANUAL_WORK' ? 'Partial offline export' : artifact.report.plan_status === 'BLOCKED' ? 'No approved commands' : 'Offline export ready'}</h3>
        <p>{artifact.command_count} set lines · SHA-256: {artifact.command_sha256}</p>
        <p>{String(artifact.report.verification ?? 'Destination compatibility and device acceptance are unverified.')}</p>
        {artifact.report.plan_status === 'READY_WITH_MANUAL_WORK' && <p role="status">Blocked, unsupported and unapproved work is excluded from this export.</p>}
        {!state.previewText ? <Button disabled={busy} onClick={() => void run(async () => {
          const result = await api.commandPreview(artifact)
          if (result.command_sha256 !== artifact.command_sha256) throw new Error('Command preview integrity check failed')
          setState((current) => ({ ...current, previewText: result.text }))
        })}>Load command preview</Button> : <details open><summary>Command preview</summary><textarea aria-label="Juniper SRX command preview" readOnly value={state.previewText} rows={14} /></details>}
        <Button disabled={busy || !artifact.command_count} onClick={() => void run(async () => downloadFile(await api.download(source, artifact, 'commands'), 'juniper_config.set'))}>Download Junos set file</Button>
        <Button disabled={busy} onClick={() => void run(async () => downloadFile(await api.download(source, artifact, 'bundle'), 'migration_fortigate_to_juniper_srx.zip'))}>Download reviewed migration bundle</Button>
      </>}
    </>}
    {busy && <LoadingState label="Preparing reviewed SRX migration…" />}
    {error && <ErrorBanner message={error} />}
  </section>
}
