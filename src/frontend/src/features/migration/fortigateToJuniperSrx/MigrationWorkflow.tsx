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
import type { JuniperSrxWorkspace, SrxOptions } from './types'
import { expandSelection } from './reviewSelection'
import { SrxDesignReview } from './DesignReview'

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

export function JuniperSRXMigrationWorkflow({ source, sourceKey, stage, onStageChange }: {
  source: SourceEvidence
  sourceKey: string
  stage: MigrationStage
  onStageChange: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<JuniperSrxWorkspace>(() => {
    const saved = workspace().panosMigration
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
  const [interfaceSearch, setInterfaceSearch] = useState('')
  const [interfacePage, setInterfacePage] = useState(1)
  const [findingPage, setFindingPage] = useState(1)
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, requirements, review, approval, artifact } = state
  const initialOptions = useRef(payloadOptions(options))

  useEffect(() => { void saveWorkspace({ panosMigration: state }) }, [state])
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
    setState((current) => ({ ...current, review: null, approval: null, artifact: null, previewText: null }))
    setSelected([])
    setApprovalPreview(null)
    setFindingPage(1)
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
    if (request !== requests.current) return
    if (preview.command_sha256 !== result.artifact.command_sha256) throw new Error('Command preview integrity check failed')
    setState((current) => ({ ...current, previewText: preview.text }))
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
    if (field === 'source_vdom') { setInterfaceSearch(''); setInterfacePage(1) }
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

  function setZone(vdom: string, name: string, value: string, kind: 'zones' | 'interface_zones' = 'zones') {
    const vdomMappings = { ...options[kind]?.[vdom] }
    if (value) vdomMappings[name] = value
    else delete vdomMappings[name]
    const zones = { ...options[kind] }
    if (Object.keys(vdomMappings).length) zones[vdom] = vdomMappings
    else delete zones[vdom]
    changeOptions({ ...options, [kind]: zones })
  }

  function openApprovalPreview(keys: string[]) {
    if (!review) return
    setApprovalPreview(expandSelection(review.report.items, keys))
  }

  const sourceScope = requirements.find((item) => item.target_field === 'source_vdom')
  const scopeRequirements = requirements.filter((item) => item.source_vdom === options.source_vdom)
  const interfaceRequirements = scopeRequirements.filter((item) => item.source_kind === 'interface' && item.target_field === 'target_interface')
  const zoneRequirements = scopeRequirements.filter((item) => item.source_kind === 'zone' && item.target_field === 'target_zone')
  const interfaceZones = new Set(scopeRequirements.filter((item) => item.source_kind === 'interface' && item.target_field === 'target_zone').map((item) => item.source_name))
  const targetChoice = (field: string) => requirements.find((item) => item.target_field === field)
  const filteredInterfaces = interfaceRequirements.filter((item) => `${item.source_name} ${options.interfaces[options.source_vdom]?.[item.source_name]?.target_interface ?? ''}`.toLowerCase().includes(interfaceSearch.trim().toLowerCase()))
  const interfacePages = Math.max(1, Math.ceil(filteredInterfaces.length / 10))
  const currentInterfacePage = Math.min(interfacePage, interfacePages)
  const mappedInterfaces = interfaceRequirements.filter((item) => {
    const mapping = options.interfaces[options.source_vdom]?.[item.source_name]
    return mapping?.target_interface?.trim() && Number.isInteger(mapping.unit) && mapping.unit! >= 0 && mapping.unit! <= 16385
  }).length
  const findingPages = Math.max(1, Math.ceil((review?.report.findings.length ?? 0) / 25))
  const currentFindingPage = Math.min(findingPage, findingPages)

  return <section className="panel" aria-labelledby="juniper-srx-migration-title">
    <h2 id="juniper-srx-migration-title">FortiGate → Juniper SRX</h2>
    <p>Review and export a Junos 25.2R1 set file with optional destination snapshot comparison. Device execution is unavailable.</p>
    {stage === 'load' && <>
      <p>Source: {source.source_name || 'Loaded FortiGate configuration'}</p>
      <p>The source stays unchanged. Unmapped and unsupported items remain visible as manual work.</p>
      <Button disabled={busy} onClick={() => onStageChange('place')}>Set up SRX target</Button>
    </>}

    {stage === 'place' && <>
      <section className="review-work-card" aria-label="New-device proposals">
        <h3>New SRX configuration</h3>
        <p>Propose root placement, ge-0/0/N physical ports, VLAN units and separate security zones for unzoned source interfaces. Review the proposed ports and cabling before approval. Hardware capacity and feature support remain unverified.</p>
        <Button disabled={busy || targetLoading || Boolean(state.destination)} onClick={() => void run(async () => {
          const request = ++requests.current
          const result = await api.proposeNewTarget(source, payloadOptions(options))
          if (request !== requests.current) return
          changeOptions({ ...emptyOptions(), ...result.options })
        })}>Propose new-device mappings</Button>
        {state.destination && <p>New-device proposals are unavailable while an existing destination snapshot is loaded.</p>}
      </section>
      <DestinationSnapshot vendor="juniper_srx" families={['addresses', 'applications', 'interfaces', 'zones', 'static_routes', 'schedules', 'policies', 'nat']} value={state.destination ?? null} disabled={busy} onChange={changeDestination} onPendingChange={setTargetLoading} />
      <section className="target-setup" aria-label="SRX target setup">
      <p>Choose placement, enter target mappings, then validate. Approval happens separately in Review migration.</p>
      <h3>Placement</h3>
      <div className="target-ownership">
      <label className="field">FortiGate VDOM<select disabled={busy} value={options.source_vdom} onChange={(event) => setGlobal('source_vdom', event.target.value)}><option value="">Choose source VDOM</option>{sourceScope?.choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>
      {(['target_context', 'target_version', 'target_mode', 'routing_table'] as const).map((field) => {
        const requirement = targetChoice(field)
        const label = requirement?.label ?? field
        return <label className="field" key={field}>{label}<select disabled={busy} value={options[field]} onChange={(event) => setGlobal(field, event.target.value)}><option value="">Choose explicitly</option>{requirement?.choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>
      })}
      </div>
      <details><summary>VLAN and source NAT prerequisites</summary>
      <label className="field">Target VLAN platform<select disabled={busy} value={options.target_platform ?? ''} onChange={(event) => changeOptions({ ...options, target_platform: event.target.value })}><option value="">VLAN export unavailable</option><option value="vsrx">vSRX 25.2R1 (tagged-only parent)</option></select></label>
      <label className="field"><span><input disabled={busy} type="checkbox" checked={options.vlan_interfaces_available ?? false} onChange={(event) => changeOptions({ ...options, vlan_interfaces_available: event.target.checked })} /> I verified VLAN capacity and mapped parent/unit availability</span></label>
      <label className="field"><span><input disabled={busy} type="checkbox" checked={options.nat_return_routing_confirmed ?? false} onChange={(event) => changeOptions({ ...options, nat_return_routing_confirmed: event.target.checked })} /> I confirmed return routing for the source NAT pool</span></label>
      </details>
      {hasSchedules && <label className="field">Confirmed FortiGate and SRX system timezone<input disabled={busy} value={options.timezone} onChange={(event) => setGlobal('timezone', event.target.value)} placeholder="Asia/Kuala_Lumpur" /></label>}

      {options.source_vdom && <>
        <h3>Interface mappings</h3>
        <p>{mappedInterfaces} of {interfaceRequirements.length} mappings entered. Validate to check target conflicts and source support.</p>
        <label className="field">Search interfaces<input value={interfaceSearch} onChange={(event) => { setInterfaceSearch(event.target.value); setInterfacePage(1) }} placeholder="Source or target interface" /></label>
        <div className="report-table-wrap"><table className="report-table"><caption>SRX interface mappings</caption><thead><tr><th>Source interface</th><th>Target physical interface</th><th>Logical unit</th><th>Security zone</th></tr></thead><tbody>
        {filteredInterfaces.slice((currentInterfacePage - 1) * 10, currentInterfacePage * 10).map((item) => <tr key={item.key}>
          <td>{item.source_vdom} / {item.source_name}</td>
          <td><input aria-label={`Target interface for ${item.source_vdom} / ${item.source_name}`} disabled={busy} value={options.interfaces[options.source_vdom]?.[item.source_name]?.target_interface ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'target_interface', event.target.value)} placeholder="ge-0/0/0" /></td>
          <td><input aria-label={`Logical unit for ${item.source_vdom} / ${item.source_name}`} disabled={busy} type="number" min="0" max="16385" step="1" value={options.interfaces[options.source_vdom]?.[item.source_name]?.unit ?? ''} onChange={(event) => setInterface(options.source_vdom, item.source_name, 'unit', event.target.value)} /></td>
          <td>{interfaceZones.has(item.source_name) ? <input aria-label={`Security zone for interface ${item.source_vdom} / ${item.source_name}`} disabled={busy} value={options.interface_zones?.[options.source_vdom]?.[item.source_name] ?? ''} onChange={(event) => setZone(options.source_vdom, item.source_name, event.target.value, 'interface_zones')} /> : 'Source zone mapping below'}</td>
        </tr>)}
        </tbody></table></div>
        {!filteredInterfaces.length && <p>No interfaces match this search.</p>}
        {interfacePages > 1 && <div className="report-pager"><Button className="secondary-button" disabled={busy || currentInterfacePage <= 1} onClick={() => setInterfacePage(currentInterfacePage - 1)}>Previous interfaces</Button><span>Page {currentInterfacePage} of {interfacePages}</span><Button className="secondary-button" disabled={busy || currentInterfacePage >= interfacePages} onClick={() => setInterfacePage(currentInterfacePage + 1)}>Next interfaces</Button></div>}
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
      <div className="action-row target-setup-actions"><Button disabled={busy || targetLoading || !options.source_vdom} onClick={() => void run(prepareReview)}>Validate changes</Button></div>
      </section>
    </>}

    {stage === 'review' && <>
      {!review ? <><p>Prepare the current target choices before review.</p><Button disabled={busy || targetLoading} onClick={() => void run(prepareReview)}>Prepare migration review</Button></> : <>
        <MigrationCoverage coverage={review.report.coverage} />
        <SrxDesignReview key={String(review.draft.digest)} items={review.report.items} busy={busy} selected={selected} onSelect={setSelected} approvalKeys={approvalPreview}
          onPreview={(keys) => void run(async () => openApprovalPreview(keys))} onApprove={() => void run(confirmApproval)} onCancel={() => setApprovalPreview(null)} onSetup={() => onStageChange('place')} />
        {!!review.report.findings.length && <details><summary>Technical findings ({review.report.findings.length})</summary>
          <ul>{review.report.findings.slice((currentFindingPage - 1) * 25, currentFindingPage * 25).map((finding, index) => <li key={index}><p>{String(finding.message ?? finding.code)}</p><pre>{JSON.stringify(finding, null, 2)}</pre></li>)}</ul>
          <div className="report-pager"><Button disabled={currentFindingPage <= 1} onClick={() => setFindingPage(currentFindingPage - 1)}>Previous findings</Button><span>Page {currentFindingPage} of {findingPages}</span><Button disabled={currentFindingPage >= findingPages} onClick={() => setFindingPage(currentFindingPage + 1)}>Next findings</Button></div>
        </details>}
      </>}
    </>}

    {stage === 'export' && <>
      {approval && !artifact && <Button disabled={busy} onClick={() => void run(() => generate())}>Retry with current approval</Button>}
      {!approval && <p>Review and approve the current plan before exporting.</p>}
      {artifact && <>
        <h3>{artifact.report.plan_status === 'READY_WITH_MANUAL_WORK' ? 'Partial offline export' : artifact.report.plan_status === 'BLOCKED' ? 'No approved commands' : 'Offline export ready'}</h3>
        <p className="artifact-identity">{artifact.command_count} command lines · SHA-256: {artifact.command_sha256}</p>
        <p>{String(artifact.report.verification ?? 'Destination compatibility and device acceptance are unverified.')}</p>
        {artifact.report.plan_status === 'READY_WITH_MANUAL_WORK' && <p role="status">Blocked, unsupported and unapproved work is excluded from this export.</p>}
        <MigrationCoverage coverage={artifact.report.coverage} />
        {!state.previewText ? <Button disabled={busy} onClick={() => void run(async () => {
          const request = ++requests.current
          const result = await api.commandPreview(artifact)
          if (request !== requests.current) return
          if (result.command_sha256 !== artifact.command_sha256) throw new Error('Command preview integrity check failed')
          setState((current) => ({ ...current, previewText: result.text }))
        })}>Load command preview</Button> : <details open><summary>Command preview</summary><label className="field">Approved Junos commands<textarea aria-label="Juniper SRX command preview" readOnly value={state.previewText} rows={14} wrap="off" /></label></details>}
        <div className="action-row">
        <Button disabled={busy || !artifact.command_count} onClick={() => void run(async () => downloadFile(await api.download(source, artifact, 'commands'), 'juniper_config.set'))}>Download Junos set file</Button>
        <Button disabled={busy} onClick={() => void run(async () => downloadFile(await api.download(source, artifact, 'bundle'), 'migration_fortigate_to_juniper_srx.zip'))}>Download reviewed migration bundle</Button>
        </div>
      </>}
    </>}
    {busy && <LoadingState label="Preparing reviewed SRX migration…" />}
    {error && <ErrorBanner message={error} />}
  </section>
}
