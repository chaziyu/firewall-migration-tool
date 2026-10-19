import { useEffect, useRef, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { FileUpload } from '../../source/FileUpload'
import { previewSource } from '../../source/sourceApi'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import { downloadFile } from '../migrationApi'
import * as api from './migrationApi'
import type { FortiGateOptions, FortiGateReview, FortiGateWorkspace, Requirement } from './types'

const emptyOptions = (): FortiGateOptions => ({ source_scope: '', vdom: '', interfaces: {}, zones: {}, routers: {}, profile: {}, timezone: '', policy_settings: {} })

export function FortiGateMigrationWorkflow({ source, sourceKey, onStageChange }: { source: SourceEvidence; sourceKey: string; onStageChange?: (stage: FortiGateWorkspace['stage']) => void }) {
  const [state, setState] = useState<FortiGateWorkspace>(() => {
    const saved = workspace().fortigateMigration
    return saved?.sourceKey === sourceKey ? saved : { sourceKey, options: emptyOptions(), targetSource: null, review: null, approval: null, artifact: null, stage: 'load' }
  })
  const [proposal, setProposal] = useState<FortiGateReview | null>(state.review)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [approvalPreview, setApprovalPreview] = useState<string[] | null>(null)
  const [targetFile, setTargetFile] = useState<File | null>(null)
  const [portsText, setPortsText] = useState<string | null>(null)
  const [requirementSearch, setRequirementSearch] = useState('')
  const [requirementPage, setRequirementPage] = useState(1)
  const [reviewFilter, setReviewFilter] = useState('ready')
  const [reviewPage, setReviewPage] = useState(1)
  const [previewPage, setPreviewPage] = useState(1)
  const [bulkChoice, setBulkChoice] = useState<{ field: string; value: string; rows: Requirement[] } | null>(null)
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, review, approval, artifact } = state
  const working = busy || (!review && !error)
  const requirements = proposal?.requirements
  const resolved = proposal?.resolved_options ?? options
  const profile = { ...resolved.profile, ...options.profile }

  useEffect(() => { void saveWorkspace({ fortigateMigration: state }) }, [state])
  useEffect(() => { onStageChange?.(state.stage) }, [state.stage, onStageChange])
  useEffect(() => () => { requests.current = -1 }, [])
  useEffect(() => {
    let active = true
    const request = ++requests.current
    api.prepare(source, options, state.targetSource).then((result) => {
      if (!active || request !== requests.current) return
      setProposal(result)
      setState((current) => ({ ...current, review: result, stage: current.stage === 'load' && result.resolved_options?.source_scope ? 'review' : current.stage }))
    }).catch((cause) => { if (active && request === requests.current) setError(cause instanceof Error ? cause.message : 'Could not prepare migration proposal') })
    return () => { active = false }
  }, [source, options, state.targetSource])

  function change(next: FortiGateOptions, targetSource = state.targetSource) {
    requests.current++
    setState((current) => ({ ...current, options: next, targetSource, review: null, approval: null, artifact: null }))
    setApprovalPreview(null); setSelected([]); setBulkChoice(null); setError(null)
  }

  async function run(action: () => Promise<void>) {
    if (pending.current) return
    pending.current = true; setBusy(true); setError(null)
    try { await action() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Migration request failed') }
    finally { pending.current = false; setBusy(false) }
  }

  async function prepareReview() {
    const request = ++requests.current
    setState((current) => ({ ...current, approval: null, artifact: null }))
    const result = await api.prepare(source, options, state.targetSource)
    if (request !== requests.current) return
    setProposal(result)
    setState((current) => ({ ...current, review: result, stage: 'review' }))
    setSelected([]); setApprovalPreview(null)
  }

  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = ++requests.current
    const result = await api.build(source, options, state.targetSource, currentApproval)
    if (request === requests.current) setState((current) => ({ ...current, artifact: result.artifact, stage: 'export' }))
  }

  async function confirmApproval() {
    if (!review || !approvalPreview?.length) return
    const request = ++requests.current
    const result = await api.approve(source, options, state.targetSource, review.draft, approvalPreview)
    if (request !== requests.current) return
    setState((current) => ({ ...current, approval: result.approval, stage: 'export' }))
    setApprovalPreview(null)
    await generate(result.approval)
  }

  function setRequirement(row: Requirement, value: string) {
    if (row.policy_key && row.field) {
      const choices = { ...options.policy_settings[row.policy_key] }
      if (value) choices[row.field] = value
      else delete choices[row.field]
      change({ ...options, policy_settings: { ...options.policy_settings, [row.policy_key]: choices } })
      return
    }
    const [family, ...rest] = row.key.split(':')
    const key = rest.join(':')
    if (family === 'vdom' || family === 'source_scope') { change({ ...emptyOptions(), ...options, [family]: value, ...(family === 'source_scope' ? { interfaces: {}, zones: {}, routers: {}, policy_settings: {} } : {}) }); return }
    if (family !== 'interfaces' && family !== 'zones' && family !== 'routers') return
    const entries = { ...options[family] }
    if (value) entries[key] = family === 'routers' ? Number(value) : value
    else delete entries[key]
    change({ ...options, [family]: entries })
  }

  function requirementValue(row: Requirement): string {
    if (row.policy_key && row.field) return options.policy_settings[row.policy_key]?.[row.field] ?? String(row.value ?? '')
    const [family, ...rest] = row.key.split(':')
    if (family === 'source_scope' || family === 'vdom') return options[family] || String(row.value ?? resolved[family])
    if (family === 'interfaces' || family === 'zones' || family === 'routers') return String(options[family][rest.join(':')] ?? row.value ?? '')
    return ''
  }

  const ready = review?.draft.configuration.filter((row) => row.render_disposition !== 'BLOCK' && !row.blocking_reasons.length) ?? []
  const previewRows = review?.draft.configuration.filter((row) => approvalPreview?.includes(row.key)) ?? []
  const filteredRequirements = requirements?.decisions.filter((row) => row.key !== 'source_scope' && row.label.toLowerCase().includes(requirementSearch.toLowerCase())) ?? []
  const requirementPages = Math.max(1, Math.ceil(filteredRequirements.length / 25))
  const currentRequirementPage = Math.min(requirementPage, requirementPages)
  const visibleRequirements = filteredRequirements.slice((currentRequirementPage - 1) * 25, currentRequirementPage * 25)
  const filteredRows = review?.draft.configuration.filter((row) => reviewFilter === 'all' || (reviewFilter === 'ready' ? row.render_disposition !== 'BLOCK' : row.render_disposition === 'BLOCK')) ?? []
  const reviewPages = Math.max(1, Math.ceil(filteredRows.length / 25))
  const currentReviewPage = Math.min(reviewPage, reviewPages)
  const visibleRows = filteredRows.slice((currentReviewPage - 1) * 25, currentReviewPage * 25)
  const previewPages = Math.max(1, Math.ceil(previewRows.length / 25))
  const currentPreviewPage = Math.min(previewPage, previewPages)
  const policyGroups = new Map<string, Requirement[]>()
  for (const row of requirements?.decisions ?? []) {
    if (!row.policy_key || !row.field || requirementValue(row)) continue
    const group = policyGroups.get(row.field)
    if (group) group.push(row)
    else policyGroups.set(row.field, [row])
  }
  const familyCounts = new Map<string, number>()
  for (const row of review?.draft.configuration ?? []) familyCounts.set(row.family, (familyCounts.get(row.family) ?? 0) + 1)
  const stage = state.stage
  return <section className="panel" aria-labelledby="fortigate-migration-title">
    <h2 id="fortigate-migration-title">PAN-OS → FortiGate</h2>
    <p>Review a FortiOS 7.4.6 CLI export. Live FortiGate deployment is unavailable. Unsupported work stays visible.</p>
    <nav className="migration-view-nav" aria-label="FortiGate migration workspace">
      {([['load', 'Source'], ['review', 'Proposed conversion'], ['place', 'Mappings and remaining choices'], ['export', 'Download']] as const).map(([value, label], index) =>
        <button key={value} type="button" disabled={working} aria-current={stage === value ? 'step' : undefined} onClick={() => setState({ ...state, stage: value })}>{index + 1}. {label}</button>)}
    </nav>
    {(stage === 'load' || stage === 'place') && <>
      <label className="field">Source device / VSYS<select disabled={working} value={options.source_scope || resolved.source_scope} onChange={(event) => setRequirement({ key: 'source_scope', label: '' }, event.target.value)}><option value="">Choose source scope</option>{requirements?.source_scopes.map((scope) => <option key={scope}>{scope}</option>)}</select></label>
      <p>Choose one standalone VSYS. Managed Panorama inheritance remains manual.</p>
      {stage === 'load' && <Button disabled={working || !(options.source_scope || resolved.source_scope)} onClick={() => void run(prepareReview)}>Generate proposed conversion</Button>}
    </>}
    {stage === 'place' && <>
      <h3>Target profile</h3>
      <p>Supported command baseline: FortiOS 7.4.6 · NAT operating mode · profile-based NGFW. Review this profile with the configuration before approval. Commands do not change device modes.</p>
      {(options.profile.fortios_version || options.profile.operating_mode || options.profile.ngfw_mode) && <Button disabled={working} onClick={() => {
        const next = { ...options.profile }
        delete next.fortios_version; delete next.operating_mode; delete next.ngfw_mode
        change({ ...options, profile: next })
      }}>Use supported command baseline</Button>}
      <div className="connection-grid">{([
        ['nat_mode', 'NAT mode', ['central', 'policy']], ['vdom_mode', 'VDOM scope', ['single', 'multi']],
      ] as const).map(([field, label, choices]) => <label className="field" key={field}>{label}<select disabled={working} value={String(profile[field] ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, [field]: event.target.value } })}><option value="">Choose explicitly</option>{choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>)}</div>
      <label className="field">Destination physical ports (comma separated)<input disabled={busy} value={portsText ?? (profile.ports as string[] | undefined)?.join(', ') ?? ''} onChange={(event) => { setPortsText(event.target.value); change({ ...options, profile: { ...options.profile, ports: event.target.value.split(',').map((port) => port.trim()).filter(Boolean) } }) }} placeholder="port1, port2" /></label>
      <p>Declare actual hardware ports. Configuration exports do not prove the complete chassis inventory.</p>
      {requirements?.has_schedules && <label className="field">Matching source and target timezone<input disabled={busy} value={options.timezone} placeholder="Asia/Kuala_Lumpur" onChange={(event) => change({ ...options, timezone: event.target.value })} /></label>}
      {requirements?.has_pool_snat && <label className="field">SNAT pool return routing<select disabled={working} value={String(options.profile.pool_return_routing ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, pool_return_routing: event.target.value } })}><option value="">Unverified</option><option value="confirmed">Engineer confirmed routed return traffic; no proxy ARP</option></select></label>}
      {requirements?.has_dnat && <details><summary>Static DNAT prerequisites</summary><label className="field">Target traffic baseline<select disabled={working} value={String(options.profile.traffic_baseline ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, traffic_baseline: event.target.value } })}><option value="">Unverified</option><option value="empty">Empty policies, VIPs and central SNAT tables</option></select></label><label className="field">VIP proxy ARP<select disabled={working} value={String(options.profile.vip_arp_reply ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, vip_arp_reply: event.target.value } })}><option value="">Choose explicitly</option><option value="enable">Enable for the reviewed public address</option><option value="disable">Disable; public address is routed to the firewall</option></select></label></details>}
      <h3>Proposed mappings and remaining choices</h3>
      <p>Edit proposed placement below. Unknown policy fields need explicit target choices; verified source behavior is shown separately.</p>
      {[...policyGroups].map(([field, rows]) => <label className="field" key={field}>Choose {field.replaceAll('_', ' ')} for {rows.length} policies<select disabled={working} value="" onChange={(event) => { if (event.target.value) setBulkChoice({ field, value: event.target.value, rows }) }}><option value="">Review a bulk choice</option>{rows[0].choices?.map((choice) => <option key={choice}>{choice}</option>)}</select></label>)}
      {bulkChoice && <section aria-label="Bulk policy choice preview"><p>Set {bulkChoice.field.replaceAll('_', ' ')} to {bulkChoice.value} for {bulkChoice.rows.length} policies. Existing per-policy choices are preserved.</p><ul>{bulkChoice.rows.slice(0, 25).map((row) => <li key={row.key}>{row.label}</li>)}</ul>{bulkChoice.rows.length > 25 && <p>{bulkChoice.rows.length - 25} more policies are included.</p>}<Button disabled={working} onClick={() => {
        const settings = { ...options.policy_settings }
        for (const row of bulkChoice.rows) if (row.policy_key) settings[row.policy_key] = { ...settings[row.policy_key], [bulkChoice.field]: bulkChoice.value }
        change({ ...options, policy_settings: settings })
      }}>Apply reviewed policy choice</Button><Button onClick={() => setBulkChoice(null)}>Cancel bulk choice</Button></section>}
      <label className="field">Find a placement or target choice<input value={requirementSearch} onChange={(event) => { setRequirementSearch(event.target.value); setRequirementPage(1) }} /></label>
      {visibleRequirements.map((row) => <label className="field" key={row.key}>{row.label}{row.choices ? <select disabled={working} value={requirementValue(row)} onChange={(event) => setRequirement(row, event.target.value)}><option value="">Choose explicitly</option>{row.choices.map((choice) => <option key={choice}>{choice}</option>)}</select> : <input disabled={busy} value={requirementValue(row)} type={row.key.startsWith('routers:') ? 'number' : 'text'} onChange={(event) => setRequirement(row, event.target.value)} />}<small>{row.evidence_source}{row.reason ? `: ${row.reason}` : ''}</small></label>)}
      {requirementPages > 1 && <div className="action-row"><Button disabled={currentRequirementPage === 1} onClick={() => setRequirementPage(currentRequirementPage - 1)}>Previous choices</Button><span>Page {currentRequirementPage} of {requirementPages}</span><Button disabled={currentRequirementPage === requirementPages} onClick={() => setRequirementPage(currentRequirementPage + 1)}>Next choices</Button></div>}
      <details><summary>Destination comparison and mapping files</summary>
        <p>Optional destination configuration is used only for conservative collision/reuse checks. It grants no live authority.</p>
        <FileUpload file={targetFile} disabled={working} accept=".conf,.cfg,.txt" description="FortiGate destination configuration" onChange={(file) => {
          if (!file) { setTargetFile(null); change(options, null); return }
          void run(async () => { const request = ++requests.current; const result = await previewSource(file, 'fortigate'); if (request === requests.current && result.source_evidence) { setTargetFile(file); change(options, result.source_evidence) } })
        }} />
        {state.targetSource && <Button disabled={working} onClick={() => { setTargetFile(null); change(options, null) }}>Remove destination evidence</Button>}
        <Button disabled={working} onClick={() => void run(async () => { const result = await api.exportDecisions(source, options, state.targetSource); downloadFile(new Blob([JSON.stringify(result.document, null, 2)], { type: 'application/json' }), 'palo_alto_to_fortigate_decisions.json') })}>Download mapping proposals</Button>
        <label className="field">Import mapping proposals<input disabled={working} type="file" accept=".json,application/json" onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) void run(async () => { const result = await api.importDecisions(source, JSON.parse(await file.text())); setPortsText(null); change(result.options) })
          event.target.value = ''
        }} /></label>
      </details>
      <Button disabled={working || !(options.source_scope || resolved.source_scope)} onClick={() => void run(prepareReview)}>Prepare migration review</Button>
    </>}
    {stage === 'review' && <>
      {!review ? <><p>Prepare the current target choices before review.</p><Button disabled={working} onClick={() => void run(prepareReview)}>Prepare migration review</Button></> : <>
        <p>{ready.length} items ready for review · {review.draft.configuration.length - ready.length} blocked or manual.</p>
        <p>Source: {resolved.source_scope} → target VDOM: {resolved.vdom || 'Unresolved'}. {policyGroups.size} groups of policy choices remain.</p>
        <ul>{[...familyCounts].map(([family, count]) => <li key={family}>{family.replaceAll('_', ' ')}: {count}</li>)}</ul>
        <p>Target profile: {String(resolved.profile.fortios_version ?? 'Unresolved version')} · {String(resolved.profile.operating_mode ?? 'Unresolved operating mode')} · {String(resolved.profile.ngfw_mode ?? 'Unresolved NGFW mode')} · {String(resolved.profile.nat_mode ?? 'Unresolved NAT mode')} NAT · {String(resolved.profile.vdom_mode ?? 'Unresolved VDOM scope')} VDOM scope.</p>
        {!resolved.profile.ports?.length && <p role="status">Declare destination physical ports once to generate interface and VLAN placement proposals.</p>}
        <Button disabled={working} onClick={() => setState({ ...state, stage: 'place' })}>Edit mappings and remaining choices</Button>
        {!!proposal?.effective_values?.length && <details><summary>Verified effective source values ({proposal.effective_values.length})</summary><p>These documented values are separate from explicit XML state.</p><ul>{proposal.effective_values.slice(0, 100).map((row, index) => <li key={index}>{row.identity[2]}: {row.field} = {row.value} (PAN-OS {row.version}) · <a href={row.reference} target="_blank" rel="noreferrer">Official reference</a></li>)}</ul>{proposal.effective_values.length > 100 && <p>All values are included in the approval context.</p>}</details>}
        {review.draft.findings.map((finding) => <p role="status" key={finding}>{finding}</p>)}
        <Button disabled={working || !ready.length} onClick={() => setApprovalPreview(api.approvalSelection(review.draft.configuration, ready.map((row) => row.key)))}>Review all ready changes</Button>
        <Button disabled={working || !selected.length} onClick={() => { try { setApprovalPreview(api.approvalSelection(review.draft.configuration, selected)) } catch (cause) { setError(String(cause)) } }}>Review selected changes</Button>
        {approvalPreview && <section className="review-work-card" aria-label="FortiGate approval preview">
          <h3>Approve exact changes and prerequisites</h3><p>{approvalPreview.length} items, including required supporting configuration and preceding policies.</p>
          <p>Approval includes the target profile and proposed placement. Confirm device modes, ownership, and physical cabling.</p><pre>{JSON.stringify({ profile: resolved.profile, vdom: resolved.vdom, interfaces: resolved.interfaces, zones: resolved.zones, routers: resolved.routers }, null, 2)}</pre>
          {previewRows.slice((currentPreviewPage - 1) * 25, currentPreviewPage * 25).map((row) => <details key={row.key}><summary>{row.render_disposition}: {row.source_scope} / {row.source_name} → {row.target_vdom} / {row.target_name}</summary><pre>{JSON.stringify({ settings: row.settings, dependencies: row.dependencies }, null, 2)}</pre></details>)}
          {previewPages > 1 && <div className="action-row"><Button disabled={currentPreviewPage === 1} onClick={() => setPreviewPage(currentPreviewPage - 1)}>Previous approval details</Button><span>Page {currentPreviewPage} of {previewPages}</span><Button disabled={currentPreviewPage === previewPages} onClick={() => setPreviewPage(currentPreviewPage + 1)}>Next approval details</Button></div>}
          <Button disabled={working || !approvalPreview.length} onClick={() => void run(confirmApproval)}>Approve these changes and generate commands</Button>
          <Button disabled={working} onClick={() => setApprovalPreview(null)}>Cancel approval preview</Button>
        </section>}
        <label className="field">Review status<select value={reviewFilter} onChange={(event) => { setReviewFilter(event.target.value); setReviewPage(1) }}><option value="ready">Ready</option><option value="blocked">Blocked and manual</option><option value="all">All</option></select></label>
        <div className="report-table-wrap"><table className="report-table"><caption>Planned FortiGate configuration</caption><thead><tr><th>Select</th><th>Source scope / name</th><th>Target</th><th>Operation</th><th>Reason</th></tr></thead><tbody>{visibleRows.map((row) => <tr key={row.key}>
          <td><input aria-label={`Select ${row.source_scope} ${row.source_name}`} type="checkbox" disabled={working || row.render_disposition === 'BLOCK'} checked={selected.includes(row.key)} onChange={(event) => setSelected(event.target.checked ? [...selected, row.key] : selected.filter((key) => key !== row.key))} /></td>
          <td>{row.source_scope} / {row.source_name}<small>{row.family}</small></td><td>{row.target_vdom} / {row.target_name}</td><td>{row.render_disposition}</td><td>{row.blocking_reasons.join(' ')}</td>
        </tr>)}</tbody></table></div>
        {reviewPages > 1 && <div className="action-row"><Button disabled={currentReviewPage === 1} onClick={() => setReviewPage(currentReviewPage - 1)}>Previous changes</Button><span>Page {currentReviewPage} of {reviewPages}</span><Button disabled={currentReviewPage === reviewPages} onClick={() => setReviewPage(currentReviewPage + 1)}>Next changes</Button></div>}
        <Button disabled={working} onClick={() => setState({ ...state, stage: 'place' })}>Resolve target choices</Button>
      </>}
    </>}
    {stage === 'export' && <>
      {approval && !artifact && <Button disabled={working} onClick={() => void run(() => generate())}>Retry generation with current approval</Button>}
      {!approval && <p>Review and approve current configuration before generating commands.</p>}
      {artifact && <>
        <h3>{artifact.report.plan_status === 'PARTIAL' ? 'Partial export' : artifact.report.plan_status === 'READY_NO_CHANGES' ? 'No changes needed' : 'Ready for export'}</h3>
        <p>{artifact.command_count} CLI lines · SHA-256: {artifact.command_sha256}</p><p>{artifact.report.verification}</p>
        <p>{artifact.report.deployment_eligibility.reason}</p>
        {artifact.report.plan_status === 'PARTIAL' && <p role="status">Blocked, unsupported and unapproved work is excluded. Review the report before applying this partial configuration.</p>}
        {!artifact.report.items.some((row) => ['policy', 'nat', 'static_route'].includes(row.family) && row.render_disposition !== 'BLOCK') && <p role="status">Supporting configuration only: no traffic policies, NAT or static routes are included.</p>}
        <details><summary>Command preview</summary><textarea aria-label="FortiGate command preview" readOnly value={artifact.commands.join('\n')} rows={12} /></details>
        {(['commands', 'bundle'] as const).map((kind) => <Button key={kind} disabled={working || (!artifact.command_count && kind === 'commands')} onClick={() => void run(async () => { const blob = await api.download(source, artifact, kind); downloadFile(blob, kind === 'bundle' ? 'migration_palo_alto_to_fortigate.zip' : 'fortigate_config.conf') })}>{kind === 'bundle' ? 'Download migration bundle' : 'Download FortiGate .conf'}</Button>)}
      </>}
    </>}
    {working && <p role="status" aria-live="polite">Preparing reviewed migration…</p>}
    {error && <ErrorBanner message={error} />}
  </section>
}
