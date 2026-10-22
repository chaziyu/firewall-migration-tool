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
import type { JuniperSrxWorkspace, SrxOptions } from './types'
import { expandSelection } from './reviewSelection'
import { isReviewable } from './reviewSelection'

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
  const [preparing, setPreparing] = useState(false)
  const [reviewTab, setReviewTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const [selected, setSelected] = useState<string[]>([])
  const [approvalPreview, setApprovalPreview] = useState<string[] | null>(null)
  const [interfaceSearch, setInterfaceSearch] = useState('')
  const [interfacePage, setInterfacePage] = useState(1)
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
      const nextOptions = { ...options, ...result.options, interfaces: { ...result.options?.interfaces } }
      for (const [scope, rows] of Object.entries(options.interfaces)) {
        nextOptions.interfaces[scope] = { ...nextOptions.interfaces[scope], ...rows }
      }
      setState((current) => ({ ...current, requirements: result.requirements, review: JSON.stringify(nextOptions) === JSON.stringify(options) ? result : null,
        options: JSON.stringify(nextOptions) === JSON.stringify(options) ? options : nextOptions,
        ...(JSON.stringify(nextOptions) === JSON.stringify(options) ? {} : { approval: null, artifact: null }) }))
      setHasSchedules(result.report.items.some((item) => item.family === 'schedule'))
    }).catch((cause) => { if (active && request === requests.current) setError(cause instanceof Error ? cause.message : 'Could not prepare conversion') })
      .finally(() => { if (active) setPreparing(false) }) }, 250)
    return () => { active = false; clearTimeout(timer) }
  }, [source, options, state.destination])

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

  const unresolvedInputs = requirements.filter((item) => (item.value == null || item.value === '' || item.value === false) && (item.target_field !== 'timezone' || hasSchedules) && (!item.source_vdom || item.source_vdom === options.source_vdom))
  return <section className="panel" aria-labelledby="juniper-srx-migration-title">
    <h2 id="juniper-srx-migration-title">FortiGate → Juniper SRX</h2>
    <p>Review and export a Junos 25.2R1 set file with optional destination snapshot comparison. Device execution is unavailable.</p>
    {stage === 'load' && <>
      <p>Source: {source.source_name || 'Loaded FortiGate configuration'}</p>
      <p>The source stays unchanged. Unmapped and unsupported items remain visible as manual work.</p>
      <Button disabled={busy} onClick={() => onStageChange('place')}>Set up SRX target</Button>
    </>}

    {(stage === 'place' || stage === 'review') && <details open={stage === 'place'}><summary>Target setup and choices</summary>
      <section className="review-work-card" aria-label="New-device proposals">
        <h3>New SRX configuration</h3>
        <p>Propose root placement, ge-0/0/N physical ports, VLAN units and separate security zones for unzoned source interfaces. Review the proposed ports and cabling before approval. Hardware capacity and feature support remain unverified.</p>
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
    </details>}

    {(stage === 'review' || stage === 'place') && review && <>
      <MigrationCoverage coverage={review.report.coverage} />
      <OfflineMigrationReview id="fg-srx" title="Juniper SRX" rows={review.report.items.map((item) => ({
        key: item.key, family: item.family, sourceScope: item.source_vdom, sourceName: item.source_name,
        target: item.target_name, operation: item.render_disposition, settings: item.settings,
        dependencies: item.dependencies, reasons: item.blockers, ready: isReviewable(item),
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
        busy={busy || targetLoading} files={[{ key: 'commands', label: 'Junos set configuration', previewLabel: 'Juniper SRX command preview', text: artifact.command_text ?? '',
          sha256: artifact.command_sha256, count: `${artifact.command_count} commands`, downloadLabel: 'Download Junos set file', downloadable: true }]}
        onDownload={() => void run(async () => { const request = requests.current; const blob = await api.download(source, artifact, 'commands'); if (request === requests.current) downloadFile(blob, 'juniper_config.set') })}
        onBundle={() => void run(async () => { const request = requests.current; const blob = await api.download(source, artifact, 'bundle'); if (request === requests.current) downloadFile(blob, 'migration_fortigate_to_juniper_srx.zip') })}>
        <MigrationCoverage coverage={artifact.report.coverage} />
      </OfflineMigrationExport>}
    </>}
    {busy && <LoadingState label="Preparing reviewed SRX migration…" />}
    {error && <ErrorBanner message={error} />}
  </section>
}
