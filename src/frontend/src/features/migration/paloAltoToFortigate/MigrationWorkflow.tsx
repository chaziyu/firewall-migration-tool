import { useEffect, useRef, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { FileUpload } from '../../source/FileUpload'
import { previewSource } from '../../source/sourceApi'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import { downloadFile } from '../migrationApi'
import * as api from './migrationApi'
import type { FortiGateOptions, FortiGateReview, FortiGateWorkspace, Requirement } from './types'
import { groupEffectiveValues, groupReviewIssues, isReady, offlineReviewRow, orderPlacementRequirements } from './reviewPresentation'

const emptyOptions = (): FortiGateOptions => ({ source_scope: '', vdom: '', interfaces: {}, zones: {}, routers: {}, profile: {}, timezone: '', policy_settings: {} })

export function FortiGateMigrationWorkflow({ source, sourceKey, stage: controlledStage, onStageChange, onReviewSource }: { source: SourceEvidence; sourceKey: string; stage?: FortiGateWorkspace['stage']; onStageChange?: (stage: FortiGateWorkspace['stage']) => void; onReviewSource?: () => void }) {
  const [state, setState] = useState<FortiGateWorkspace>(() => {
    const saved = workspace().panosMigration
    return saved?.pairId === 'palo_alto_to_fortigate' && saved.sourceKey === sourceKey ? saved : { pairId: 'palo_alto_to_fortigate', sourceKey, options: emptyOptions(), targetSource: null, review: null, approval: null, artifact: null, stage: 'load' }
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
  const [requirementKind, setRequirementKind] = useState('interfaces')
  const [policySearch, setPolicySearch] = useState('')
  const [policyPage, setPolicyPage] = useState(1)
  const [showResolvedChoices, setShowResolvedChoices] = useState(false)
  const [reviewTabChoice, setReviewTabChoice] = useState<'changes' | 'decisions' | 'manual' | null>(null)
  const [issueSearch, setIssueSearch] = useState('')
  const [issuePage, setIssuePage] = useState(1)
  const [selectedIssue, setSelectedIssue] = useState('')
  const [memberPage, setMemberPage] = useState(1)
  const [evidenceSearch, setEvidenceSearch] = useState('')
  const [evidencePage, setEvidencePage] = useState(1)
  const [evidenceSummaryPage, setEvidenceSummaryPage] = useState(1)
  const [bulkChoice, setBulkChoice] = useState<{ field: string; value: string; rows: Requirement[] } | null>(null)
  const requests = useRef(0)
  const pending = useRef(false)
  const { options, review, approval, artifact } = state
  const stage = controlledStage ?? state.stage
  const working = busy || (!review && !error)
  const requirements = proposal?.requirements
  const resolved = proposal?.resolved_options ?? options
  const profile = { ...resolved.profile, ...options.profile }

  useEffect(() => { void saveWorkspace({ panosMigration: { ...state, stage } }) }, [state, stage])
  useEffect(() => () => { requests.current = -1 }, [])

  function changeStage(next: FortiGateWorkspace['stage']) {
    setState((current) => ({ ...current, stage: next }))
    onStageChange?.(next)
  }
  useEffect(() => {
    let active = true
    const request = ++requests.current
    api.prepare(source, options, state.targetSource).then((result) => {
      if (!active || request !== requests.current) return
      setProposal(result)
      setState((current) => ({ ...current, review: result }))
      if (stage === 'load' && result.resolved_options?.source_scope) changeStage('place')
    }).catch((cause) => { if (active && request === requests.current) setError(cause instanceof Error ? cause.message : 'Could not prepare migration proposal') })
    return () => { active = false }
  }, [source, options, state.targetSource])

  function change(next: FortiGateOptions, targetSource = state.targetSource) {
    requests.current++
    setState((current) => ({ ...current, options: next, targetSource, review: null, approval: null, artifact: null }))
    setApprovalPreview(null); setSelected([]); setBulkChoice(null); setError(null)
    setReviewTabChoice(null); setSelectedIssue(''); setIssuePage(1)
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
    setState((current) => ({ ...current, review: result }))
    changeStage('review')
    setSelected([]); setApprovalPreview(null); setReviewTabChoice(null)
  }

  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = ++requests.current
    const result = await api.build(source, options, state.targetSource, currentApproval)
    if (request === requests.current) { setState((current) => ({ ...current, artifact: result.artifact })); changeStage('export') }
  }

  async function confirmApproval() {
    if (!review || !approvalPreview?.length) return
    const request = ++requests.current
    const result = await api.approve(source, options, state.targetSource, review.draft, approvalPreview)
    if (request !== requests.current) return
    setState((current) => ({ ...current, approval: result.approval }))
    changeStage('export')
    setApprovalPreview(null)
    await generate(result.approval)
  }

  function downloadArtifact(kind: 'commands' | 'bundle') {
    if (!artifact) return
    const request = requests.current
    void run(async () => {
      const blob = await api.download(source, artifact, kind)
      if (request === requests.current) downloadFile(blob, kind === 'bundle' ? 'migration_palo_alto_to_fortigate.zip' : 'fortigate_config.conf')
    })
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

  function requirementInput(row: Requirement) {
    return <label className="field" key={row.key}>{row.label}{row.choices ? <select disabled={working} value={requirementValue(row)} onChange={(event) => setRequirement(row, event.target.value)}><option value="">Choose explicitly</option>{row.choices.map((choice) => <option key={choice}>{choice}</option>)}</select> : <input disabled={busy} value={requirementValue(row)} type={row.key.startsWith('routers:') ? 'number' : 'text'} onChange={(event) => setRequirement(row, event.target.value)} />}<small>{row.mode === 'SUGGESTED' ? 'Proposed · ' : ''}{row.evidence_source}{row.reason ? `: ${row.reason}` : ''}</small></label>
  }

  const configuration = review?.draft.configuration ?? []
  const ready = configuration.filter(isReady)
  const placementRequirements = requirements?.decisions.filter((row) => row.key.startsWith(`${requirementKind}:`)) ?? []
  const orderedRequirements = requirementKind === 'interfaces' ? orderPlacementRequirements(placementRequirements, configuration)
    : [...placementRequirements].sort((a, b) => Number(!!requirementValue(a)) - Number(!!requirementValue(b)))
  const filteredRequirements = orderedRequirements.filter((row) => `${row.label} ${requirementValue(row)}`.toLowerCase().includes(requirementSearch.toLowerCase()))
  const requirementPages = Math.max(1, Math.ceil(filteredRequirements.length / 25))
  const currentRequirementPage = Math.min(requirementPage, requirementPages)
  const visibleRequirements = filteredRequirements.slice((currentRequirementPage - 1) * 25, currentRequirementPage * 25)
  const policyGroups = new Map<string, Requirement[]>()
  for (const row of requirements?.decisions ?? []) {
    if (!row.policy_key || !row.field || requirementValue(row)) continue
    const group = policyGroups.get(row.field)
    if (group) group.push(row)
    else policyGroups.set(row.field, [row])
  }
  const policyRequirements = (requirements?.decisions ?? []).filter((row) => row.policy_key && (showResolvedChoices || !requirementValue(row))
    && row.label.toLowerCase().includes(policySearch.toLowerCase()))
  const policyPages = Math.max(1, Math.ceil(policyRequirements.length / 25))
  const currentPolicyPage = Math.min(policyPage, policyPages)
  const issueGroups = review ? groupReviewIssues(review) : []
  const inputCategories = ['CHOICE', 'PREREQUISITE', 'CONFLICT', 'SOURCE', 'UNCLASSIFIED']
  const inputGroups = issueGroups.filter((group) => inputCategories.includes(group.category))
  const manualGroups = issueGroups.filter((group) => !inputCategories.includes(group.category))
  const findings = [...new Set(review?.draft.findings ?? [])]
  const reviewTab = reviewTabChoice ?? (!ready.length && (inputGroups.length || findings.length) ? 'decisions' : !ready.length && manualGroups.length ? 'manual' : 'changes')
  const groups = (reviewTab === 'manual' ? manualGroups : inputGroups).filter((group) => `${group.source_scope} ${group.explanation} ${group.reasons.join(' ')} ${group.affected.map((item) => item.source_name).join(' ')}`.toLowerCase().includes(issueSearch.toLowerCase()))
  const issuePages = Math.max(1, Math.ceil(groups.length / 10))
  const currentIssuePage = Math.min(issuePage, issuePages)
  const visibleGroups = groups.slice((currentIssuePage - 1) * 10, currentIssuePage * 10)
  const activeIssue = visibleGroups.find((group) => group.key === selectedIssue) ?? visibleGroups[0]
  const memberPages = Math.max(1, Math.ceil((activeIssue?.affected.length ?? 0) / 25))
  const currentMemberPage = Math.min(memberPage, memberPages)
  const effectiveValues = (review?.effective_values ?? []).filter((row) => `${row.identity.join(' ')} ${row.field} ${row.value} ${row.version} ${row.origin} ${row.reference}`.toLowerCase().includes(evidenceSearch.toLowerCase()))
  const effectiveGroups = groupEffectiveValues(effectiveValues)
  const evidencePages = Math.max(1, Math.ceil(effectiveValues.length / 25))
  const currentEvidencePage = Math.min(evidencePage, evidencePages)
  const evidenceSummaryPages = Math.max(1, Math.ceil(effectiveGroups.length / 25))
  const currentEvidenceSummaryPage = Math.min(evidenceSummaryPage, evidenceSummaryPages)
  const familyCounts = new Map<string, number>()
  for (const row of configuration) familyCounts.set(row.family, (familyCounts.get(row.family) ?? 0) + 1)
  return <section className="panel" aria-labelledby="fortigate-migration-title">
    <h2 id="fortigate-migration-title">PAN-OS → FortiGate</h2>
    <p>Review a FortiOS 7.4.6 CLI export. Live FortiGate deployment is unavailable. Unsupported work stays visible.</p>
    {!controlledStage && <nav className="migration-view-nav" aria-label="FortiGate migration workspace">
      {([['load', 'Source'], ['place', 'Target setup'], ['review', 'Review migration'], ['export', 'Download']] as const).map(([value, label], index) =>
        <button key={value} type="button" disabled={working} aria-current={stage === value ? 'step' : undefined} onClick={() => changeStage(value)}>{index + 1}. {label}</button>)}
    </nav>}
    {stage === 'load' && <>
      <label className="field">Source device / VSYS<select disabled={working} value={options.source_scope || resolved.source_scope} onChange={(event) => setRequirement({ key: 'source_scope', label: '' }, event.target.value)}><option value="">Choose source scope</option>{requirements?.source_scopes.map((scope) => <option key={scope}>{scope}</option>)}</select></label>
      <p>Choose one standalone VSYS. Managed Panorama inheritance remains manual.</p>
      <Button disabled={working || !(options.source_scope || resolved.source_scope)} onClick={() => changeStage('place')}>Continue to target setup</Button>
    </>}
    {(stage === 'place' || stage === 'review') && findings.length > 0 && <section className="review-work-card" aria-label="Shared migration blockers">
      <h3>Resolve shared blockers first</h3>
      <p>These findings block configuration across the draft. Target mappings alone may not resolve them.</p>
      {findings.map((finding) => <div key={finding}><p role="status">{finding}</p><small>{configuration.filter((row) => row.blocking_reasons.includes(finding)).length} affected configuration items</small></div>)}
      {onReviewSource && <Button className="secondary-button" onClick={onReviewSource}>Review source report</Button>}
    </section>}
    {stage === 'place' && <div className="target-setup">
      <h3>Target setup</h3>
      <p>Source: {resolved.source_scope || 'Choose a source scope'}. Review proposed placement before approving changes.</p>
      <section aria-label="Target placement">
      <h3>Target</h3>
      {requirements?.decisions.filter((row) => row.key === 'vdom').map(requirementInput)}
      <p>Supported command baseline: FortiOS 7.4.6 · NAT operating mode · profile-based NGFW. Review this profile with the configuration before approval. Commands do not change device modes.</p>
      <p>Current profile: {String(profile.fortios_version ?? 'Unresolved version')} · {String(profile.operating_mode ?? 'Unresolved operating mode')} · {String(profile.ngfw_mode ?? 'Unresolved NGFW mode')}.</p>
      {(options.profile.fortios_version || options.profile.operating_mode || options.profile.ngfw_mode) && <Button disabled={working} onClick={() => {
        const next = { ...options.profile }
        delete next.fortios_version; delete next.operating_mode; delete next.ngfw_mode
        change({ ...options, profile: next })
      }}>Use supported command baseline</Button>}
      <div className="connection-grid">{([
        ['nat_mode', 'NAT mode', ['central', 'policy']], ['vdom_mode', 'VDOM scope', ['single', 'multi']],
      ] as const).map(([field, label, choices]) => <label className="field" key={field}>{label}<select disabled={working} value={String(profile[field] ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, [field]: event.target.value } })}><option value="">Choose explicitly</option>{choices.map((choice) => <option key={choice}>{choice}</option>)}</select></label>)}</div>
      </section>
      <section aria-label="Interfaces and zones">
      <h3>Interfaces and zones</h3>
      {proposal?.proposals.some((row) => row.key === 'profile:ports' && row.evidence_source === 'ASSUMED_LAYOUT') && <p role="status">Assumed same layout: ethernet1/1 → port1, ethernet1/2 → port2. VLAN tags follow the mapped parent. Review or edit these proposals; target hardware and cabling are unverified.</p>}
      <label className="field">Target physical ports (comma separated)<input disabled={busy} value={portsText ?? (profile.ports as string[] | undefined)?.join(', ') ?? ''} onChange={(event) => { setPortsText(event.target.value); change({ ...options, profile: { ...options.profile, ports: event.target.value.split(',').map((port) => port.trim()).filter(Boolean) } }) }} placeholder="port1, port2" /></label>
      <p>Edit the target port list if the destination uses different ports. Configuration exports do not prove the complete chassis inventory.</p>
      <p role="status">{requirements?.decisions.filter((row) => row.key.startsWith('interfaces:') && !requirementValue(row)).length ?? 0} interface mappings unresolved. Physical mappings must use the target port list; VLANs need their parent mapping first.</p>
      <label className="field">Mapping type<select value={requirementKind} onChange={(event) => { setRequirementKind(event.target.value); setRequirementPage(1) }}>{[['interfaces', 'Interfaces'], ['zones', 'Zones'], ['routers', 'Routing domains']].map(([key, label]) => <option key={key} value={key}>{label} ({requirements?.decisions.filter((row) => row.key.startsWith(`${key}:`)).length ?? 0})</option>)}</select></label>
      <label className="field">Find a mapping<input value={requirementSearch} onChange={(event) => { setRequirementSearch(event.target.value); setRequirementPage(1) }} /></label>
      {visibleRequirements.map(requirementInput)}
      {!filteredRequirements.length && <p>No mappings match this view.</p>}
      {requirementPages > 1 && <div className="action-row"><Button disabled={currentRequirementPage === 1} onClick={() => setRequirementPage(currentRequirementPage - 1)}>Previous mappings</Button><span>Page {currentRequirementPage} of {requirementPages}</span><Button disabled={currentRequirementPage === requirementPages} onClick={() => setRequirementPage(currentRequirementPage + 1)}>Next mappings</Button></div>}
      {!!requirements?.manual?.length && <details><summary>Placement and policies requiring separate work ({requirements.manual.length})</summary><p>These items remain outside automatic conversion. Inspect their reasons in Review migration.</p></details>}
      </section>
      <section aria-label="Remaining target choices">
      <h3>Remaining choices</h3>
      {requirements?.has_schedules && <label className="field">Matching source and target timezone<input disabled={busy} value={options.timezone} placeholder="Asia/Kuala_Lumpur" onChange={(event) => change({ ...options, timezone: event.target.value })} /></label>}
      {requirements?.has_pool_snat && <label className="field">SNAT pool return routing<select disabled={working} value={String(options.profile.pool_return_routing ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, pool_return_routing: event.target.value } })}><option value="">Unverified</option><option value="confirmed">Engineer confirmed routed return traffic; no proxy ARP</option></select></label>}
      {requirements?.has_dnat && <details><summary>Static DNAT prerequisites</summary><label className="field">Target traffic baseline<select disabled={working} value={String(options.profile.traffic_baseline ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, traffic_baseline: event.target.value } })}><option value="">Unverified</option><option value="empty">Empty policies, VIPs and central SNAT tables</option></select></label><label className="field">VIP proxy ARP<select disabled={working} value={String(options.profile.vip_arp_reply ?? '')} onChange={(event) => change({ ...options, profile: { ...options.profile, vip_arp_reply: event.target.value } })}><option value="">Choose explicitly</option><option value="enable">Enable for the reviewed public address</option><option value="disable">Disable; public address is routed to the firewall</option></select></label></details>}
      <p>{policyGroups.size} unresolved policy-field groups. Source problems and unsupported work are reported separately.</p>
      {[...policyGroups].map(([field, rows]) => <label className="field" key={field}>Choose {field.replaceAll('_', ' ')} for {rows.length} policies<select disabled={working} value="" onChange={(event) => { if (event.target.value) setBulkChoice({ field, value: event.target.value, rows }) }}><option value="">Review a bulk choice</option>{rows[0].choices?.map((choice) => <option key={choice}>{choice}</option>)}</select></label>)}
      {bulkChoice && <section aria-label="Bulk policy choice preview"><p>Set {bulkChoice.field.replaceAll('_', ' ')} to {bulkChoice.value} for {bulkChoice.rows.length} policies. Existing per-policy choices are preserved.</p><ul>{bulkChoice.rows.slice(0, 25).map((row) => <li key={row.key}>{row.label}</li>)}</ul>{bulkChoice.rows.length > 25 && <p>{bulkChoice.rows.length - 25} more policies are included.</p>}<Button disabled={working} onClick={() => {
        const settings = { ...options.policy_settings }
        for (const row of bulkChoice.rows) if (row.policy_key) settings[row.policy_key] = { ...settings[row.policy_key], [bulkChoice.field]: bulkChoice.value }
        change({ ...options, policy_settings: settings })
      }}>Apply reviewed policy choice</Button><Button onClick={() => setBulkChoice(null)}>Cancel bulk choice</Button></section>}
      <details><summary>Individual policy choices</summary>
      <label className="field">Find a policy choice<input value={policySearch} onChange={(event) => { setPolicySearch(event.target.value); setPolicyPage(1) }} /></label>
      <label><input type="checkbox" checked={showResolvedChoices} onChange={(event) => { setShowResolvedChoices(event.target.checked); setPolicyPage(1) }} /> Show resolved choices</label>
      {policyRequirements.slice((currentPolicyPage - 1) * 25, currentPolicyPage * 25).map(requirementInput)}
      {!policyRequirements.length && <p>No policy choices match this view.</p>}
      {policyPages > 1 && <div className="action-row"><Button disabled={currentPolicyPage === 1} onClick={() => setPolicyPage(currentPolicyPage - 1)}>Previous choices</Button><span>Page {currentPolicyPage} of {policyPages}</span><Button disabled={currentPolicyPage === policyPages} onClick={() => setPolicyPage(currentPolicyPage + 1)}>Next choices</Button></div>}
      </details>
      </section>
      <details><summary>Advanced: destination comparison and mapping files</summary>
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
      <div className="target-setup-actions"><Button disabled={working || !(options.source_scope || resolved.source_scope)} onClick={() => void run(prepareReview)}>Review migration</Button></div>
    </div>}
    {stage === 'review' && <>
      {!review ? <><p>Prepare the current target choices before review.</p><Button disabled={working} onClick={() => void run(prepareReview)}>Prepare migration review</Button></> : <>
        <h3>Review migration</h3>
        <p>Source: {resolved.source_scope} → target VDOM: {resolved.vdom || 'Unresolved'}.</p>
        <OfflineMigrationReview id="fortigate" title="FortiGate" rows={configuration.map(offlineReviewRow)} busy={working}
          tab={reviewTab} onTabChange={(tab) => { setReviewTabChoice(tab); setIssuePage(1); setSelectedIssue(''); setMemberPage(1) }}
          inputCount={inputGroups.length + findings.length} manualCount={manualGroups.length}
          selected={selected} onSelect={(keys) => { setSelected(keys); setApprovalPreview(null) }} approvalKeys={approvalPreview}
          onPreview={(keys) => { try { setApprovalPreview(api.approvalSelection(configuration, keys)) } catch (cause) { setError(String(cause)) } }}
          onApprove={() => void run(confirmApproval)} onCancel={() => setApprovalPreview(null)} onSetup={() => changeStage('place')}
          approveLabel="Approve these changes and generate commands"
          approvalContext={<>
            <p>Confirm device modes, ownership, and physical cabling.</p>
            <dl><dt>Target VDOM</dt><dd>{resolved.vdom}</dd>{Object.entries(resolved.profile).map(([field, value]) => <div key={field}><dt>{field.replaceAll('_', ' ')}</dt><dd>{Array.isArray(value) ? value.join(', ') : value}</dd></div>)}</dl>
            <details><summary>Exact placement and technical context</summary><pre>{JSON.stringify({ profile: resolved.profile, vdom: resolved.vdom, interfaces: resolved.interfaces, zones: resolved.zones, routers: resolved.routers }, null, 2)}</pre></details>
          </>}
          issueContent={<>
          <p>{reviewTab === 'manual' ? 'These findings need separate review or implementation. Reading them does not resolve blocked configuration.' : 'Resolve target choices and prerequisites in Target setup. Review source corrections in the source report. Shared blockers are shown above.'}</p>
          <label className="field">Search issue groups<input value={issueSearch} onChange={(event) => { setIssueSearch(event.target.value); setIssuePage(1); setSelectedIssue(''); setMemberPage(1) }} /></label>
          <p>{groups.length} issue groups · {new Set(groups.flatMap((group) => group.affected.map((item) => item.key))).size} affected items. Impact can overlap between groups.</p>
          {!groups.length && <p>{issueSearch ? 'No issue groups match this search.' : findings.length && reviewTab === 'decisions' ? 'Review the shared blockers above.' : 'No issue groups in this view.'}</p>}
          <div className="action-row">{visibleGroups.map((group) => <button className="secondary-button" type="button" key={group.key} aria-pressed={activeIssue?.key === group.key} onClick={() => { setSelectedIssue(group.key); setMemberPage(1) }}>{group.source_scope} · {group.explanation} ({group.affected.length} items)</button>)}</div>
          {activeIssue && <article className="review-work-card" aria-label="Selected issue group">
            <h3>{activeIssue.category === 'SOURCE' ? 'Source correction required' : activeIssue.category === 'PREREQUISITE' ? 'Resolve the prerequisite first' : reviewTab === 'manual' ? 'Separate work required' : 'Review this blocker'}</h3>
            <p>{activeIssue.explanation}</p>
            {reviewTab !== 'manual' && <div className="action-row">{activeIssue.category !== 'SOURCE' && <Button disabled={working} onClick={() => changeStage('place')}>Resolve in target setup</Button>}{onReviewSource && <Button className="secondary-button" onClick={onReviewSource}>Review source report</Button>}</div>}
            <details><summary>Affected configuration ({activeIssue.affected.length})</summary><ul>{activeIssue.affected.slice((currentMemberPage - 1) * 25, currentMemberPage * 25).map((item) => <li key={item.key}>{item.source_scope} / {item.source_name}</li>)}</ul>
              {activeIssue.category === 'PREREQUISITE' && <details><summary>Reported dependency reasons ({activeIssue.reasons.length})</summary><ul>{activeIssue.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></details>}
              {memberPages > 1 && <div className="action-row"><Button disabled={currentMemberPage === 1} onClick={() => setMemberPage(currentMemberPage - 1)}>Previous affected items</Button><span>Page {currentMemberPage} of {memberPages}</span><Button disabled={currentMemberPage === memberPages} onClick={() => setMemberPage(currentMemberPage + 1)}>Next affected items</Button></div>}
            </details>
          </article>}
          {issuePages > 1 && <div className="action-row"><Button disabled={currentIssuePage === 1} onClick={() => { setIssuePage(currentIssuePage - 1); setMemberPage(1) }}>Previous issue groups</Button><span>Page {currentIssuePage} of {issuePages}</span><Button disabled={currentIssuePage === issuePages} onClick={() => { setIssuePage(currentIssuePage + 1); setMemberPage(1) }}>Next issue groups</Button></div>}
          </>} />
        <details><summary>Technical evidence</summary>
          <h3>Configuration inventory</h3><ul>{[...familyCounts].map(([family, count]) => <li key={family}>{family.replaceAll('_', ' ')}: {count}</li>)}</ul>
          <h3>Target profile and placement</h3><pre>{JSON.stringify(resolved, null, 2)}</pre>
          <h3>Verified effective source values ({review.effective_values.length})</h3><p>These documented values are separate from explicit XML state. Every value remains included in the approval context.</p>
          <label className="field">Search effective source values<input value={evidenceSearch} onChange={(event) => { setEvidenceSearch(event.target.value); setEvidencePage(1); setEvidenceSummaryPage(1) }} /></label>
          <p>{effectiveValues.length} values · {effectiveGroups.length} groups match.</p>
          <ul>{effectiveGroups.slice((currentEvidenceSummaryPage - 1) * 25, currentEvidenceSummaryPage * 25).map((group) => <li key={group.key}>{group.field} = {group.value} · {group.count} values · PAN-OS {group.version} · <a href={group.reference} target="_blank" rel="noreferrer">Official reference</a></li>)}</ul>
          {evidenceSummaryPages > 1 && <div className="action-row"><Button disabled={currentEvidenceSummaryPage === 1} onClick={() => setEvidenceSummaryPage(currentEvidenceSummaryPage - 1)}>Previous value groups</Button><span>Page {currentEvidenceSummaryPage} of {evidenceSummaryPages}</span><Button disabled={currentEvidenceSummaryPage === evidenceSummaryPages} onClick={() => setEvidenceSummaryPage(currentEvidenceSummaryPage + 1)}>Next value groups</Button></div>}
          <details><summary>All matching source values</summary><ul>{effectiveValues.slice((currentEvidencePage - 1) * 25, currentEvidencePage * 25).map((row, index) => <li key={index}>{row.identity.join(' / ')}: {row.field} = {row.value} · {row.origin} · PAN-OS {row.version} · <a href={row.reference} target="_blank" rel="noreferrer">Official reference</a></li>)}</ul>
            {evidencePages > 1 && <div className="action-row"><Button disabled={currentEvidencePage === 1} onClick={() => setEvidencePage(currentEvidencePage - 1)}>Previous source values</Button><span>Page {currentEvidencePage} of {evidencePages}</span><Button disabled={currentEvidencePage === evidencePages} onClick={() => setEvidencePage(currentEvidencePage + 1)}>Next source values</Button></div>}
          </details>
        </details>
      </>}
    </>}
    {stage === 'export' && <>
      {approval && !artifact && <Button disabled={working} onClick={() => void run(() => generate())}>Retry generation with current approval</Button>}
      {!approval && <p>Review and approve current configuration before generating commands.</p>}
      {artifact && <>
        <OfflineMigrationExport artifactId={artifact.artifact_id} partial={artifact.report.plan_status === 'PARTIAL'}
          noChanges={artifact.report.plan_status === 'READY_NO_CHANGES'} verification={artifact.report.verification} busy={working}
          files={[{ key: 'commands', label: 'Approved FortiOS commands', previewLabel: 'FortiGate command preview', text: artifact.commands.join('\n'),
            sha256: artifact.command_sha256, count: `${artifact.command_count} CLI lines`, downloadLabel: 'Download FortiGate .conf', downloadable: artifact.command_count > 0 }]}
          onDownload={() => downloadArtifact('commands')} onBundle={() => downloadArtifact('bundle')}>
          <p>{artifact.report.deployment_eligibility.reason}</p>
          {!artifact.report.items.some((row) => ['policy', 'nat', 'static_route'].includes(row.family) && ['CREATE', 'CONFIGURE', 'REUSE'].includes(row.render_disposition)) && <p role="status">Supporting configuration only: no traffic policies, NAT or static routes are included.</p>}
        </OfflineMigrationExport>
      </>}
    </>}
    {working && <p role="status" aria-live="polite">Preparing reviewed migration…</p>}
    {error && <ErrorBanner message={error} />}
  </section>
}
