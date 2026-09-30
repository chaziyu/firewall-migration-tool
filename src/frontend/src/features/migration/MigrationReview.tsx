import { useEffect, useRef, useState } from 'react'
import { postForm, postJson } from '../../api/client'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import { tabKeyboard } from '../../components/common/tabKeyboard'

type Decision = {
  key: string
  source_vdom: string
  source_kind: string
  source_name: string
  target_field: string
  suggested_value: string | null
  value: string | null
  mode: string
  review_state: string
  reason: string
  evidence_source?: string | null
  evidence_type?: string | null
  evidence_value?: string | null
  target_object?: string | null
  [key: string]: unknown
}

type DecisionDocument = { decisions?: Decision[]; [key: string]: unknown }
type Candidate = { value: string; class?: string; target_scope?: string; strong_evidence?: string[]; supporting_evidence?: string[] }
type Proposal = { decision_key: string; action: string; proposed_value: string | null; target_scope?: string; rationale?: string; evidence_refs?: string[]; validation_status: string }
type ReviewGroup = { queue: string; source_vdom: string; source_kind: string; source_name: string; decision_keys: string[]; decisions: Decision[]; candidates: Record<string, Candidate[]>; source_evidence: Record<string, unknown>; affected_count: number; dependent_decision_count: number; next_action?: string | null; actions?: Array<{ type: string; source_key: string; value: string; apply_to: string[] }> }
type ReviewData = {
  decisions: { decisions: Decision[] }
  decision_document: DecisionDocument
  target_devices: string[]
  target_device: string | null
  decision_candidates: Record<string, Candidate[]>
  review_groups: ReviewGroup[]
  review_summary: Record<string, number>
  rule_suggestions: Array<{ rule_type: string; source_vdom: string; source_zone: string; target_zone: string; confirmed_count: number; affected: string[]; apply_to: string[] }>
  architecture_questions?: Array<{ type: string; source_vdom: string; source_name: string; affected_count?: number; decision_key?: string; candidates?: string[]; fields?: Decision[] }>
  target_evidence: { device?: string; config_digest?: string } | null
  [key: string]: unknown
}

function download(text: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  URL.revokeObjectURL(url)
}

export function MigrationReview({ preview, vendor, onDecisionDocument, onContextChange, requestedDecision }: {
  preview: SourcePreviewData
  vendor: string
  onDecisionDocument?: (document: MigrationDecisionDocument | null) => void
  onContextChange?: (targetPreviewId: string, targetDevice: string) => void
  requestedDecision?: { key: string; request: number } | null
}) {
  const previewId = typeof preview.preview_id === 'string' ? preview.preview_id : ''
  const [targetPreviewId, setTargetPreviewId] = useState('')
  const [targetDevices, setTargetDevices] = useState<string[]>([])
  const [targetDevice, setTargetDevice] = useState('')
  const [review, setReview] = useState<ReviewData | null>(null)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [proposals, setProposals] = useState<Proposal[]>([])
  const [designSessionId, setDesignSessionId] = useState('')
  const [activeQueue, setActiveQueue] = useState('NEEDS_INPUT')
  const [groupPage, setGroupPage] = useState(1)
  const [decisionPage, setDecisionPage] = useState(1)
  const [bulkPreview, setBulkPreview] = useState<Array<{ key: string; scope: string; value: string }>>([])
  const [bulkPage, setBulkPage] = useState(1)
  const requestVersion = useRef(0)
  const [search, setSearch] = useState('')
  const [vdomFilter, setVdomFilter] = useState('all')
  const [advisorStatus, setAdvisorStatus] = useState('Advisor status not checked.')
  const [decisionFilter, setDecisionFilter] = useState('all')
  const [evidenceFilter, setEvidenceFilter] = useState('all')
  const [pendingOnly, setPendingOnly] = useState(false)
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [bulkValue, setBulkValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [autoVerified, setAutoVerified] = useState(false)
  const [autoDerived, setAutoDerived] = useState(false)
  const [error, setError] = useState('')
  const [status, setStatus] = useState('')

  async function loadReview(document?: DecisionDocument, targetId = targetPreviewId, device = targetDevice) {
    if (!previewId) return
    const request = ++requestVersion.current
    onDecisionDocument?.(null)
    const result = await postJson<ReviewData>('/api/migration/requirements', {
      preview_id: previewId,
      ...(document ? { decision_document: document } : {}),
      ...(targetId ? { target_preview_id: targetId } : {}),
      ...(device ? { target_device: device } : {}),
    })
    if (request !== requestVersion.current) return
    setReview(result)
    setTargetDevices(result.target_devices || [])
    setTargetDevice(result.target_device || '')
    onDecisionDocument?.(result.decision_document as unknown as MigrationDecisionDocument)
    onContextChange?.(targetId, result.target_device || device || '')
    setDrafts(Object.fromEntries(result.decisions.decisions.map((item) => [item.key, item.value ?? item.suggested_value ?? ''])))
    setBulkPreview([])
    setSelectedKeys([])
    setGroupPage(1)
  }

  useEffect(() => {
    if (vendor === 'fortigate' && previewId) {
      void loadReview().catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Could not load migration review'))
    }
    return () => {
      // Invalidate in-flight requests; this ref is a version counter, not a DOM node.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      requestVersion.current++
    }
    // Reload only when the source preview changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewId, vendor])

  useEffect(() => {
    if (!requestedDecision || !review) return
    const group = review.review_groups.find((item) => item.decision_keys.includes(requestedDecision.key))
    if (!group) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setStatus('This finding has no editable mapping in the current review. Review its support guidance.')
      return
    }
    // Synchronize a plan blocker navigation request with the server-owned queue.
    setActiveQueue(group.queue)
    setSearch('')
    setVdomFilter('all')
    const index = review.review_groups.filter((item) => item.queue === group.queue).indexOf(group)
    setGroupPage(Math.floor(index / 10) + 1)
  }, [requestedDecision, review])

  useEffect(() => {
    if (!requestedDecision) return
    const input = document.getElementById(`decision-${requestedDecision.key}`)
    const destination = input ?? document.getElementById('migration-review-title')
    destination?.scrollIntoView({ block: 'center' })
    destination?.focus()
  }, [requestedDecision, activeQueue, groupPage, review])

  if (vendor !== 'fortigate' || !previewId) return null

  async function run(action: () => Promise<void>, done?: string) {
    setBusy(true)
    setError('')
    setStatus('')
    try {
      await action()
      if (done) setStatus(done)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Migration review failed')
    } finally {
      setBusy(false)
    }
  }

  function currentDocument(decisions = review?.decisions.decisions ?? []): DecisionDocument {
    return { ...(review?.decision_document ?? {}), decisions }
  }

  async function updateDecisions(decisions: Decision[]) {
    await loadReview(currentDocument(decisions))
    setProposals([])
    setDesignSessionId('')
  }

  async function uploadTarget(file: File | undefined) {
    if (!file) return
    setError('')
    setStatus('Reading PAN-OS target XML…')
    setBusy(true)
    try {
      onDecisionDocument?.(null)
      const form = new FormData()
      form.append('source_vendor', 'palo_alto')
      form.append('file', file)
      const result = await postForm<SourcePreviewData & { preview_id?: string }>('/api/preview', form)
      if (!result.preview_id) throw new Error('PAN-OS preview did not return a preview ID')
      const nextTargetId = result.preview_id
      setTargetPreviewId(nextTargetId)
      setProposals([])
      setDesignSessionId('')
      await loadReview(review ? currentDocument() : undefined, nextTargetId, '')
      setStatus('Target evidence loaded. Review each suggested mapping before confirming it.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not read target PAN-OS XML')
      setStatus('')
      if (review) onDecisionDocument?.(review.decision_document as unknown as MigrationDecisionDocument)
    } finally {
      setBusy(false)
    }
  }

  async function selectTargetDevice(device: string) {
    setTargetDevice(device)
    setProposals([])
    setDesignSessionId('')
    await loadReview(currentDocument(), targetPreviewId, device)
  }

  async function confirmDecision(decision: Decision, value: string) {
    if (!value.trim()) return
    const confirmed = engineerConfirmation(decision, value)
    await updateDecisions((review?.decisions.decisions ?? []).map((item) => item.key === decision.key ? confirmed : item))
  }

  function engineerConfirmation(decision: Decision, value: string): Decision {
    const targetEvidence = review?.target_evidence
    const confirmedTargetSuggestion = Boolean(targetEvidence?.config_digest && targetEvidence.device
      && decision.evidence_source === 'TARGET' && value === decision.suggested_value)
    return {
      ...decision,
      value,
      mode: decision.mode === 'AUTO' ? 'REQUIRED' : decision.mode,
      review_state: 'CONFIRMED',
      evidence_source: 'ENGINEER',
      evidence_type: confirmedTargetSuggestion ? 'ENGINEER_TARGET_SUGGESTION' : 'MANUAL',
      evidence_value: value,
      target_object: value,
      evidence_target_digest: confirmedTargetSuggestion ? targetEvidence?.config_digest ?? null : null,
      evidence_target_device: confirmedTargetSuggestion ? targetEvidence?.device ?? null : null,
    }
  }

  async function importIntent(file: File | undefined) {
    if (!file || !review) return
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/target-intent/import', {
      preview_id: previewId,
      decision_document: currentDocument(),
      yaml: await file.text(),
      ...(targetPreviewId ? { target_preview_id: targetPreviewId, target_device: targetDevice } : {}),
    })
    await loadReview(result.decision_document)
  }

  async function exportIntent() {
    const result = await postJson<{ yaml: string }>('/api/migration/target-intent/export', {
      preview_id: previewId,
      decision_document: currentDocument(),
    })
    download(result.yaml, 'target-intent.yaml', 'text/yaml')
  }

  function exportMappingTemplate() {
    const namesByKind = (kind: string) => {
      const names = new Map<string, string[]>()
      for (const item of decisions.filter((decision) => decision.source_kind === kind)) {
        names.set(item.source_vdom, [...new Set([...(names.get(item.source_vdom) ?? []), item.source_name])])
      }
      return names
    }
    const vdoms = [...new Set(decisions.filter((item) => item.source_kind === 'vdom').map((item) => item.source_vdom))]
    const entries = (values: Map<string, string[]>, fields: string[]) => [...values].flatMap(([vdom, names]) => [
      `  ${JSON.stringify(vdom)}:`, ...names.flatMap((name) => [`    ${JSON.stringify(name)}:`, ...fields.map((field) => `      ${field}:`)]),
    ])
    const yaml = [
      'vdoms:', ...vdoms.flatMap((vdom) => [`  ${JSON.stringify(vdom)}:`, '    vsys:', '    virtual_router:']),
      'interfaces:', ...entries(namesByKind('interface'), ['target_interface', 'target_zone']),
      'zones:', ...entries(namesByKind('zone'), ['target_zone']),
    ].join('\n') + '\n'
    download(yaml, 'target-mapping.yaml', 'text/yaml')
  }

  async function importMapping(file: File | undefined) {
    if (!file || !review) return
    const result = await postJson<{ mapping: { vdoms?: Record<string, Record<string, string | null>>; interfaces?: Record<string, Record<string, Record<string, string | null>>>; zones?: Record<string, Record<string, { target_zone?: string | null }>> } }>('/api/migration/mapping/import', { yaml: await file.text() })
    const next = new Map(decisions.map((decision) => [decision.key, decision]))
    let matched = 0
    let ignored = 0
    const confirm = (vdom: string, kind: string, name: string, field: string, value: string | null | undefined) => {
      const decision = decisions.find((item) => item.source_vdom === vdom && item.source_kind === kind && item.source_name === name && item.target_field === field)
      if (!decision || decision.mode === 'UNSUPPORTED' || value == null || value === '') { ignored++; return }
      next.set(decision.key, engineerConfirmation(decision, value))
      matched++
    }
    for (const [vdom, values] of Object.entries(result.mapping.vdoms ?? {})) for (const [field, value] of Object.entries(values)) confirm(vdom, 'vdom', vdom, field, value)
    for (const [vdom, entries] of Object.entries(result.mapping.interfaces ?? {})) for (const [name, values] of Object.entries(entries)) for (const [field, value] of Object.entries(values)) {
      const kind = decisions.some((item) => item.source_vdom === vdom && item.source_kind === 'interface' && item.source_name === name && item.target_field === field) ? 'interface' : field === 'target_zone' ? 'zone' : 'interface'
      confirm(vdom, kind, name, field, value)
    }
    for (const [vdom, entries] of Object.entries(result.mapping.zones ?? {})) for (const [name, values] of Object.entries(entries)) confirm(vdom, 'zone', name, 'target_zone', values.target_zone)
    await updateDecisions([...next.values()])
    setStatus(`Mapping imported: ${matched} decisions updated; ${ignored} entries ignored.`)
  }

  async function exportDecisions() {
    const result = await postJson<{ document: DecisionDocument }>('/api/migration/decisions/export', { preview_id: previewId, decision_document: currentDocument() })
    download(JSON.stringify(result.document, null, 2), 'migration_decisions.json', 'application/json')
  }

  async function importDecisions(file: File | undefined) {
    if (!file) return
    const document = JSON.parse(await file.text()) as DecisionDocument
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/decisions/import', { preview_id: previewId, document })
    setProposals([])
    setDesignSessionId('')
    await loadReview(result.decision_document, targetPreviewId, targetDevice)
  }

  async function runAutomation() {
    const enabledPolicies = [autoVerified && 'AUTO_APPLY_VERIFIED', autoDerived && 'AUTO_APPLY_DERIVED'].filter((item): item is string => Boolean(item))
    const result = await postJson<{ decision_document: DecisionDocument; audit?: unknown[] }>('/api/migration/automation/run', {
      preview_id: previewId,
      decision_document: currentDocument(),
      enabled_policies: enabledPolicies,
      ...(targetPreviewId ? { target_preview_id: targetPreviewId, target_device: targetDevice } : {}),
    })
    setProposals([])
    setDesignSessionId('')
    await loadReview(result.decision_document, targetPreviewId, targetDevice)
    setStatus(`${enabledPolicies.length ? result.audit?.length ?? 0 : 0} decisions resolved by deterministic automation.`)
  }

  async function buildProposals(retry = false) {
    const result = await postJson<{ design_session: { design_session_id: string; proposals: Proposal[] } }>('/api/migration/ai/design', {
      preview_id: previewId,
      decision_document: currentDocument(),
      target_preview_id: targetPreviewId,
      target_device: targetDevice,
      ...(designSessionId ? { design_session_id: designSessionId } : {}),
      ...(retry && designSessionId ? { retry_exceptions: true } : {}),
    })
    setDesignSessionId(result.design_session.design_session_id)
    setProposals(result.design_session.proposals || [])
  }

  async function approveProposal(proposal: Proposal) {
    if (!designSessionId || proposal.validation_status !== 'VALID') return
    const result = await postJson<{ decisions: { decisions: Decision[] }; decision_document: DecisionDocument }>(
      `/api/migration/ai/design/${encodeURIComponent(designSessionId)}/approve`,
      {
        preview_id: previewId,
        decision_document: currentDocument(),
        target_preview_id: targetPreviewId,
        target_device: targetDevice,
        decision_keys: [proposal.decision_key],
      },
    )
    await loadReview(result.decision_document)
    setProposals((items) => items.filter((item) => item.decision_key !== proposal.decision_key))
  }

  async function approveProposals(keys: string[]) {
    if (!designSessionId || !keys.length) return
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/ai/design/' + encodeURIComponent(designSessionId) + '/approve', {
      preview_id: previewId, decision_document: currentDocument(), target_preview_id: targetPreviewId, target_device: targetDevice, decision_keys: keys,
    })
    await loadReview(result.decision_document)
    setProposals((items) => items.filter((item) => !keys.includes(item.decision_key)))
  }

  async function rejectProposals(keys: string[]) {
    if (!designSessionId || !keys.length) return
    await postJson(`/api/migration/ai/design/${encodeURIComponent(designSessionId)}/reject`, {
      preview_id: previewId, decision_document: currentDocument(), target_preview_id: targetPreviewId,
      target_device: targetDevice, decision_keys: keys,
    })
    setProposals((items) => items.filter((item) => !keys.includes(item.decision_key)))
  }

  async function testAdvisor() {
    try {
      const response = await fetch('/api/migration/ai/status')
      const config = await response.json() as { enabled?: boolean; provider?: string; model?: string; groq_configured?: boolean; local_configured?: boolean; error?: string }
      setAdvisorStatus(config.enabled ? `${config.provider === 'qwen_local' ? 'Local Qwen' : 'Groq'} · ${config.model} · ${(config.provider === 'qwen_local' ? config.local_configured : config.groq_configured) ? 'Ready' : 'Configuration error'}` : 'AI advisor disabled.')
      const result = await postJson<{ provider: string; model: string; checks?: Array<{ name: string; success: boolean }> }>('/api/migration/ai/test', {})
      setAdvisorStatus(`${result.provider} · ${result.model} · ${(result.checks ?? []).map((item) => `${item.name}: ${item.success ? 'PASS' : 'FAIL'}`).join(' · ') || 'Test passed'}`)
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Advisor test failed'
      setAdvisorStatus(message)
      throw cause
    }
  }

  async function confirmGroup(group: ReviewGroup) {
    const keys = new Set(group.decision_keys)
    const next = decisions.map((item) => keys.has(item.key) && item.mode !== 'UNSUPPORTED' && (drafts[item.key] ?? item.value ?? item.suggested_value ?? '').trim()
      ? engineerConfirmation(item, (drafts[item.key] ?? item.value ?? item.suggested_value ?? '').trim()) : item)
    await updateDecisions(next)
  }

  async function applyGroupAction(action: NonNullable<ReviewGroup['actions']>[number]) {
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/rules/apply', {
      preview_id: previewId, decision_document: currentDocument(), rule_type: action.type, source_key: action.source_key, value: action.value, apply_to: action.apply_to,
    })
    await loadReview(result.decision_document)
  }

  async function applyRuleSuggestion(suggestion: ReviewData['rule_suggestions'][number]) {
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/rules/apply', {
      preview_id: previewId, decision_document: currentDocument(), rule_type: suggestion.rule_type,
      source_vdom: suggestion.source_vdom, source_zone: suggestion.source_zone,
      value: suggestion.target_zone, apply_to: suggestion.apply_to,
    })
    await loadReview(result.decision_document)
  }

  const decisions = review?.decisions.decisions ?? []
  const suggestions = decisions.filter((item) => item.mode === 'SUGGESTED' && item.review_state !== 'CONFIRMED' && item.suggested_value)
  const devices = targetDevices
  const reviewGroups = review?.review_groups ?? []
  const vdoms = [...new Set(reviewGroups.map((group) => group.source_vdom))].sort()
  const queueNames = ['READY_TO_CONFIRM', 'CHOOSE_CANDIDATE', 'NEEDS_INPUT', 'CONFLICT', 'COMPLETE']
  const visibleGroups = reviewGroups.filter((group) => group.queue === activeQueue && (vdomFilter === 'all' || group.source_vdom === vdomFilter)
    && `${group.source_vdom} ${group.source_kind} ${group.source_name}`.toLowerCase().includes(search.toLowerCase()))
  const validProposalKeys = proposals.filter((proposal) => proposal.validation_status === 'VALID' && proposal.proposed_value).map((proposal) => proposal.decision_key)
  const visibleDecisions = decisions.filter((item) => {
    if (decisionFilter === 'zones' && item.source_kind !== 'zone') return false
    if (decisionFilter === 'interfaces' && item.source_kind !== 'interface') return false
    if (decisionFilter === 'route-nat' && !/route|nat/i.test(`${item.source_kind} ${item.target_field}`)) return false
    if (vdomFilter !== 'all' && item.source_vdom !== vdomFilter) return false
    if (evidenceFilter === 'target' && item.evidence_source !== 'TARGET') return false
    if (evidenceFilter === 'source' && item.evidence_source === 'TARGET') return false
    if (evidenceFilter === 'conflict' && item.review_state !== 'CONFLICT') return false
    if (evidenceFilter === 'required' && item.mode !== 'REQUIRED') return false
    if (evidenceFilter === 'confirmed' && item.review_state !== 'CONFIRMED') return false
    return !pendingOnly || item.review_state !== 'CONFIRMED'
  })

  function bulkConfirm(keys: string[], valueFor: (decision: Decision) => string) {
    const selected = new Set(keys)
    setBulkPreview(decisions.filter((item) => selected.has(item.key) && item.mode !== 'UNSUPPORTED' && valueFor(item).trim())
      .map((item) => ({ key: item.key, scope: `${item.source_vdom} · ${item.source_kind} · ${item.source_name} · ${item.target_field}`, value: valueFor(item).trim() })))
    setBulkPage(1)
    requestAnimationFrame(() => document.querySelector('[aria-label="Bulk confirmation review"]')?.scrollIntoView({ block: 'start' }))
  }

  function clearSelected() {
    const selected = new Set(selectedKeys)
    void run(() => updateDecisions(decisions.map((item) => selected.has(item.key) ? {
      ...item, value: null, mode: item.mode === 'AUTO' ? 'REQUIRED' : item.mode, review_state: 'PENDING',
      evidence_source: null, evidence_type: null, evidence_value: null, target_object: null,
      evidence_target_digest: null, evidence_target_device: null,
    } : item)), 'Selected values cleared.')
  }

  return (
    <section className="panel migration-review" aria-labelledby="migration-review-title">
      <h2 id="migration-review-title" tabIndex={-1}>Target evidence and mappings</h2>
      <p className="migration-review-intro">Target XML is optional. Suggestions stay pending until you confirm them.</p>
      <p className="report-count-note">FortiGate → PAN-OS · Review VDOM, VSYS, and virtual router decisions before dependent mappings.</p>

      <div className="migration-toolbar">
        <label className="field">Optional PAN-OS target XML
          <input type="file" accept=".xml,application/xml,text/xml" disabled={busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void uploadTarget(file) }} />
        </label>
        {targetPreviewId && <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(async () => {
          setTargetPreviewId(''); setTargetDevices([]); setTargetDevice(''); setProposals([]); setDesignSessionId('')
          onContextChange?.('', '')
          await loadReview(currentDocument(), '', '')
        }, 'Target evidence removed.')}>Remove target</button>}
        {devices.length > 0 && <label className="field">Target device
          <select value={targetDevice} disabled={busy} onChange={(event) => void run(() => selectTargetDevice(event.target.value))}>
            <option value="">Select a device</option>
            {devices.map((device) => <option key={device} value={device}>{device}</option>)}
          </select>
        </label>}
      </div>

      {error && <div className="error-banner" role="alert">{error}</div>}
      {(status || busy) && <p role="status" aria-live="polite" className="migration-status">{busy ? 'Updating migration review…' : status}</p>}
      {review && <>
        <p className="migration-counts">{decisions.filter((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED').length} remaining decisions · {reviewGroups.filter((item) => item.queue !== 'COMPLETE').length} remaining groups. Affected-object counts are per group and may overlap.</p>
        <section className="architecture-decisions" aria-label="Architecture decisions">
          <h3>Architecture decisions</h3>
          {(review.architecture_questions ?? []).map((question) => {
            const group = reviewGroups.find((item) => item.source_vdom === question.source_vdom && item.source_name === question.source_name)
            return <article key={`${question.type}:${question.source_vdom}:${question.source_name}`} className="review-work-card">
              <strong>{question.source_vdom} · {question.source_name}</strong>
              <p>{question.type === 'VDOM_CONTEXT' ? 'Choose target VSYS and virtual router.' : question.type === 'AGGREGATE_MAPPING' ? 'Choose the target aggregate interface.' : 'Choose the target zone.'} {question.affected_count ?? group?.affected_count ?? 0} affected objects.</p>
              {group && <button type="button" className="secondary-button" onClick={() => {
                setActiveQueue(group.queue); setSearch(''); setVdomFilter('all'); setGroupPage(Math.floor(reviewGroups.filter((item) => item.queue === group.queue).indexOf(group) / 10) + 1)
                requestAnimationFrame(() => { const input = document.getElementById(`decision-${group.decision_keys[0]}`); input?.scrollIntoView({ block: 'center' }); input?.focus() })
              }}>Review architecture mapping</button>}
            </article>
          })}
          {!review.architecture_questions?.length && <p>No architecture questions reported.</p>}
        </section>
        <div className="review-summary">
          {[
            ['verified', 'Verified'], ['derived', 'Derived'], ['choose_candidate', 'Choices'],
            ['needs_input', 'Manual'], ['conflicts', 'Conflicts'],
          ].map(([key, label]) => <div className="review-summary-card" key={key}><strong>{review.review_summary[key] ?? 0}</strong><span>{label} decisions</span></div>)}
        </div>
        <section className="review-workflow" aria-label="Migration review queues">
          <nav className="review-queues" role="tablist" aria-label="Migration review work queues" onKeyDown={tabKeyboard}>
            {queueNames.map((queue) => <button type="button" role="tab" key={queue} id={`queue-tab-${queue}`} aria-controls={`queue-panel-${queue}`} tabIndex={activeQueue === queue ? 0 : -1} aria-selected={activeQueue === queue} onClick={() => { setActiveQueue(queue); setGroupPage(1) }}>
              {({ READY_TO_CONFIRM: 'Ready to approve', CHOOSE_CANDIDATE: 'Choose match', NEEDS_INPUT: 'Needs design', CONFLICT: 'Conflicts', COMPLETE: 'Completed' } as Record<string, string>)[queue]} <span>{reviewGroups.filter((group) => group.queue === queue).length} groups</span>
            </button>)}
          </nav>
          {queueNames.filter((queue) => queue !== activeQueue).map((queue) => <div key={queue} hidden role="tabpanel" id={`queue-panel-${queue}`} aria-labelledby={`queue-tab-${queue}`} />)}
          <div role="tabpanel" id={`queue-panel-${activeQueue}`} aria-labelledby={`queue-tab-${activeQueue}`} tabIndex={0}>
          <div className="migration-toolbar">
            <label className="field">Search review groups<input value={search} onChange={(event) => { setSearch(event.target.value); setGroupPage(1) }} placeholder="Search source mappings" /></label>
            <label className="field">VDOM<select value={vdomFilter} onChange={(event) => { setVdomFilter(event.target.value); setGroupPage(1); setDecisionPage(1) }}><option value="all">All VDOMs</option>{vdoms.map((item) => <option key={item}>{item}</option>)}</select></label>
          </div>
          {!visibleGroups.length && <p>{reviewGroups.length ? 'Nothing in this queue.' : 'No migration decisions are required.'}</p>}
          {review.rule_suggestions.map((suggestion) => <article className="review-work-card architecture-question" key={`${suggestion.source_vdom}:${suggestion.source_zone}`}>
            <h3>Apply {suggestion.target_zone} to {suggestion.affected.length} other interfaces in {suggestion.source_zone}?</h3>
            <p>Based on {suggestion.confirmed_count} engineer-confirmed mappings for explicit zone members.</p>
            <details><summary>Review affected mappings</summary><ul>{suggestion.affected.map((name) => <li key={name}>{name}</li>)}</ul></details>
            <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyRuleSuggestion(suggestion))}>Apply to {suggestion.affected.length} mappings</button>
          </article>)}
          {visibleGroups.slice((groupPage - 1) * 10, groupPage * 10).map((group) => <article className={`review-work-card queue-${group.queue.toLowerCase()}`} key={`${group.source_vdom}:${group.source_kind}:${group.source_name}`}>
            <div className="review-work-heading"><div><h3>{group.source_kind === 'vdom' ? `${group.source_name} VDOM` : group.source_name}</h3><p>{group.source_vdom} · {group.source_kind}{typeof group.source_evidence.source_type === 'string' ? ` · ${group.source_evidence.source_type}` : ''}</p></div><span className="review-work-badge">{group.queue.replaceAll('_', ' ')}</span></div>
            {(review.architecture_questions ?? []).filter((question) => question.source_vdom === group.source_vdom && question.source_name === group.source_name).map((question) => <div className="review-work-suggestion" key={`${question.type}:${question.source_name}`}>
              <p>{question.type === 'AGGREGATE_MAPPING' ? `Architecture question: Which PAN aggregate replaces this interface? ${question.affected_count ?? 0} VLAN mappings will be re-evaluated.` : question.type === 'VDOM_CONTEXT' ? 'Architecture question: Choose the target VSYS and virtual router for this VDOM.' : 'Architecture question: Choose the PAN zone for this source zone.'}</p>
              {question.type === 'VDOM_CONTEXT' ? question.fields?.filter((item) => item.suggested_value).map((item) => <button className="secondary-button" type="button" key={item.key} onClick={() => setDrafts((current) => ({ ...current, [item.key]: item.suggested_value ?? '' }))}>{item.target_field === 'vsys' ? 'VSYS' : 'VR'}: {item.suggested_value}</button>) : (question.candidates ?? []).map((value) => <button className="secondary-button" type="button" key={value} onClick={() => question.decision_key && setDrafts((current) => ({ ...current, [question.decision_key as string]: value }))}>Use {value}</button>)}
            </div>)}
            {group.decisions.filter((item) => item.mode !== 'UNSUPPORTED').map((decision) => {
              const value = drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? ''
              const candidates = group.candidates[decision.key] ?? review.decision_candidates[decision.key] ?? []
              return <div className="review-work-field" key={decision.key}>
                <label>{decision.target_field.replaceAll('_', ' ')}<input id={`decision-${decision.key}`} disabled={busy} aria-label={`${decision.target_field} for ${group.source_name}`} value={value} onChange={(event) => setDrafts((current) => ({ ...current, [decision.key]: event.target.value }))} placeholder={decision.suggested_value ? `Suggested: ${decision.suggested_value}` : 'Enter mapping'} /></label>
                {decision.suggested_value && decision.review_state !== 'CONFIRMED' && <p className="review-work-suggestion">Suggested: {decision.suggested_value}</p>}
                {candidates.length > 0 && <details className="review-work-candidates"><summary>{candidates.length} possible matches</summary>{candidates.map((candidate) => <div className="review-work-candidate" key={candidate.value}><span>{candidate.class === 'STRONG' ? 'Recommended' : 'Possible match'}: {candidate.value}{candidate.target_scope ? ` · ${candidate.target_scope}` : ''}</span><button className="text-button" type="button" onClick={() => setDrafts((current) => ({ ...current, [decision.key]: candidate.value }))}>Use</button><details><summary>Why?</summary><ul>{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].map((fact) => <li key={fact}>{fact}</li>)}</ul></details></div>)}</details>}
                {proposals.find((item) => item.decision_key === decision.key) && <p className="review-work-suggestion">AI proposal is available in the optional AI review section.</p>}
              </div>
            })}
            <div className="review-work-impact"><p>{group.affected_count} affected objects · {group.dependent_decision_count} dependent mappings will be re-evaluated</p>{group.next_action && <p>Next action: {group.next_action}</p>}
              {Object.keys(group.source_evidence).length > 0 && <details><summary>Source facts</summary><ul>{Object.entries(group.source_evidence).map(([key, value]) => <li key={key}>{key.replace(/^source_/, '').replaceAll('_', ' ')}: {Array.isArray(value) ? value.join(', ') || '(explicitly empty)' : String(value)}</li>)}</ul></details>}
            </div>
            {group.decisions.filter((item) => item.mode === 'UNSUPPORTED').map((item) => <p key={item.key}>Unsupported: {item.target_field} · {item.reason}</p>)}
            {group.actions?.map((action) => <div key={`${action.type}:${action.source_key}`}><details><summary>Review member decision scope</summary><p>{group.source_vdom} · {action.source_key} → {action.value}</p><ul>{action.apply_to.map((key) => <li key={key}>{key}</li>)}</ul></details><button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyGroupAction(action))}>Apply {action.value} to {action.apply_to.length} member decisions</button></div>)}
            {group.decisions.some((item) => item.mode !== 'UNSUPPORTED') && <button className="primary-button" type="button" disabled={busy || !group.decision_keys.some((key) => (drafts[key] ?? decisions.find((item) => item.key === key)?.value ?? decisions.find((item) => item.key === key)?.suggested_value ?? '').trim())} onClick={() => void run(() => confirmGroup(group), 'Mapping confirmed.')}>Confirm mapping</button>}
          </article>)}
          <div className="report-pager"><button type="button" className="secondary-button" disabled={groupPage <= 1} onClick={() => setGroupPage((page) => page - 1)}>Previous groups</button><span role="status">Page {groupPage} of {Math.max(1, Math.ceil(visibleGroups.length / 10))} · {visibleGroups.length} groups</span><button type="button" className="secondary-button" disabled={groupPage * 10 >= visibleGroups.length} onClick={() => setGroupPage((page) => page + 1)}>Next groups</button></div>
          </div>
        </section>
        <div className="migration-toolbar">
          <label className="field">Import target intent YAML
            <input type="file" accept=".yaml,.yml,text/yaml" disabled={busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void run(() => importIntent(file), 'Target intent imported.') }} />
          </label>
          <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(exportIntent, 'Target intent downloaded.')}>Export target intent</button>
<button className="secondary-button" type="button" disabled={busy || !suggestions.length} onClick={() => bulkConfirm(suggestions.map((item) => item.key), (item) => item.suggested_value ?? '')}>Review all suggestions</button>
        </div>

          <details className="ai-review-controls"><summary>AI-assisted review (optional)</summary>
            <h3>AI-assisted review</h3>
            <p>AI suggestions remain provisional. Approving a validated proposal records an engineer-confirmed decision.</p>
            <p role="status" aria-live="polite">{advisorStatus}</p>
            <div className="migration-toolbar">
              <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(testAdvisor)}>Test advisor</button>
              {targetPreviewId && targetDevice && <>
                <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => buildProposals(Boolean(designSessionId)), 'Ready proposals refreshed.')}>{designSessionId ? 'Retry ready proposals' : 'Propose ready mappings'}</button>
                <button className="secondary-button" type="button" disabled={busy || !validProposalKeys.length} onClick={() => void run(() => approveProposals(validProposalKeys), 'Valid proposals approved by engineer.')}>Approve valid proposals ({validProposalKeys.length})</button>
              </>}
              <a className="secondary-button" href="/api/migration/ai/audit/export">Download AI review audit</a>
            </div>
            {proposals.map((proposal) => <article className="ai-proposal" key={proposal.decision_key}>
              <strong>{proposal.proposed_value ?? 'No safe proposal'}</strong><p>{proposal.target_scope || proposal.action} · {proposal.rationale || proposal.validation_status}</p>
              {proposal.evidence_refs?.length ? <small>Evidence: {proposal.evidence_refs.join(', ')}</small> : null}
              {proposal.validation_status === 'VALID' && proposal.proposed_value && <button type="button" className="text-button" disabled={busy} onClick={() => void run(() => approveProposal(proposal), 'Proposal approved by engineer.')}>Approve proposal</button>}
              {proposal.proposed_value && <button type="button" className="text-button" disabled={busy} onClick={() => setDrafts((current) => ({ ...current, [proposal.decision_key]: proposal.proposed_value ?? '' }))}>Use value to edit</button>}
              <button type="button" className="text-button" disabled={busy} onClick={() => void run(() => rejectProposals([proposal.decision_key]), 'Proposal dismissed.')}>Dismiss</button>
            </article>)}
          </details>
        <details className="migration-review-tools">
          <summary>Advanced review tools</summary>
          <div className="migration-toolbar">
            <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(async () => exportMappingTemplate(), 'Mapping template downloaded.')}>Download mapping template</button>
            <label className="field">Import mapping YAML
              <input type="file" accept=".yaml,.yml,text/yaml" disabled={busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void run(() => importMapping(file)) }} />
            </label>
            <label className="field">Import decisions JSON
              <input type="file" accept=".json,application/json" disabled={busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void run(() => importDecisions(file), 'Migration decisions imported.') }} />
            </label>
            <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(exportDecisions, 'Migration decisions downloaded.')}>Export decisions</button>
          </div>
          <div className="migration-toolbar">
            <label><input type="checkbox" checked={autoVerified} disabled={busy} onChange={(event) => setAutoVerified(event.target.checked)} /> Apply verified decisions</label>
            <label><input type="checkbox" checked={autoDerived} disabled={busy} onChange={(event) => setAutoDerived(event.target.checked)} /> Apply derived decisions</label>
            <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(runAutomation)}>Run deterministic automation</button>
          </div>
        </details>

        <details className="migration-review-tools"><summary>Advanced decision view</summary>
        <div className="migration-toolbar">
          <label className="field">Show<select value={decisionFilter} onChange={(event) => { setDecisionFilter(event.target.value); setDecisionPage(1) }}><option value="all">All decisions</option><option value="zones">Zones</option><option value="interfaces">Interfaces</option><option value="route-nat">Route/NAT impact</option></select></label>
          <label className="field">Evidence<select value={evidenceFilter} onChange={(event) => { setEvidenceFilter(event.target.value); setDecisionPage(1) }}><option value="all">All evidence</option><option value="target">Target-backed</option><option value="source">Source-only</option><option value="conflict">Conflicts</option><option value="required">Required</option><option value="confirmed">Confirmed</option></select></label>
          <label><input type="checkbox" checked={pendingOnly} onChange={(event) => { setPendingOnly(event.target.checked); setDecisionPage(1) }} /> Show pending only</label>
          <button className="secondary-button" type="button" onClick={() => setSelectedKeys(visibleDecisions.slice((decisionPage - 1) * 50, decisionPage * 50).filter((item) => item.mode !== 'UNSUPPORTED').map((item) => item.key))}>Select all visible</button>
          <button className="secondary-button" type="button" onClick={() => setSelectedKeys([])}>Clear selection</button>
          <span aria-live="polite">Selected: {selectedKeys.length}</span>
          <button className="primary-button" type="button" disabled={busy || !selectedKeys.length} onClick={() => bulkConfirm(selectedKeys, (item) => drafts[item.key] ?? item.value ?? item.suggested_value ?? '')}>Confirm selected</button>
          <button className="secondary-button" type="button" disabled={busy || !suggestions.length} onClick={() => bulkConfirm(suggestions.map((item) => item.key), (item) => item.suggested_value ?? '')}>Confirm all mapping suggestions</button>
        </div>
        <div className="migration-toolbar"><label className="field">Final value for selected<input value={bulkValue} onChange={(event) => setBulkValue(event.target.value)} /></label>
          <button className="secondary-button" type="button" disabled={busy || !selectedKeys.length || !bulkValue.trim()} onClick={() => {
            const selected = decisions.filter((item) => selectedKeys.includes(item.key))
            if (new Set(selected.map((item) => item.target_field)).size > 1) { setError('Select decisions with one target field before setting a shared value.'); return }
            bulkConfirm(selectedKeys, () => bulkValue)
          }}>Set selected value</button>
          <button className="secondary-button" type="button" disabled={busy || !selectedKeys.length} onClick={() => bulkConfirm(selectedKeys, (item) => item.suggested_value ?? '')}>Use suggestion</button>
          <button className="secondary-button" type="button" disabled={busy || !selectedKeys.length} onClick={clearSelected}>Clear selected values</button>
        </div>
        <p className="migration-counts" aria-live="polite">{decisions.filter((item) => item.review_state === 'CONFIRMED' || item.mode === 'AUTO').length} confirmed · {suggestions.length} suggestions · {decisions.filter((item) => item.mode === 'REQUIRED' && item.review_state !== 'CONFIRMED').length} required</p>
        <div className="report-table-wrap">
          <table className="report-table migration-decision-table">
            <thead><tr><th>Source</th><th>Target field</th><th>Suggestion and candidates</th><th>Final value</th><th>Review</th></tr></thead>
            <tbody>{visibleDecisions.slice((decisionPage - 1) * 50, decisionPage * 50).map((decision) => {
              const candidates = review.decision_candidates[decision.key] ?? []
              const value = drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? ''
              return <tr key={decision.key}>
                <td><input aria-label={`Select ${decision.source_name}`} type="checkbox" checked={selectedKeys.includes(decision.key)} onChange={(event) => setSelectedKeys((keys) => event.target.checked ? [...keys, decision.key] : keys.filter((key) => key !== decision.key))} /> {decision.source_vdom} · {decision.source_kind} · {decision.source_name}<small className="decision-reason">{decision.reason}</small></td>
                <td>{decision.target_field}</td>
                <td>{decision.suggested_value || '—'}{candidates.length > 0 && <details><summary>{candidates.length} target candidates</summary><ul>{candidates.map((candidate) => <li key={`${decision.key}:${candidate.value}`}>
                  <span>{candidate.value}{candidate.target_scope ? ` · ${candidate.target_scope}` : ''}{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].length ? ` · ${[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].join(', ')}` : ''}</span>
                  <button type="button" className="text-button" onClick={() => setDrafts((current) => ({ ...current, [decision.key]: candidate.value }))}>Use candidate</button>
                </li>)}</ul></details>}</td>
                <td><input aria-label={`${decision.target_field} for ${decision.source_name}`} value={value} disabled={decision.mode === 'UNSUPPORTED'} onChange={(event) => setDrafts((current) => ({ ...current, [decision.key]: event.target.value }))} /></td>
                <td>{decision.review_state === 'CONFIRMED' || decision.mode === 'AUTO' ? 'Confirmed' : 'Pending'}{decision.mode !== 'UNSUPPORTED' && decision.review_state !== 'CONFIRMED' && decision.mode !== 'AUTO' && <button className="text-button" type="button" disabled={busy || !value.trim()} onClick={() => void run(() => confirmDecision(decision, value))}>Confirm</button>}</td>
              </tr>
            })}</tbody>
          </table>
        </div>
          <div className="report-pager"><button type="button" disabled={decisionPage <= 1} onClick={() => setDecisionPage((page) => page - 1)}>Previous decisions</button><span>Page {decisionPage} of {Math.max(1, Math.ceil(visibleDecisions.length / 50))}</span><button type="button" disabled={decisionPage * 50 >= visibleDecisions.length} onClick={() => setDecisionPage((page) => page + 1)}>Next decisions</button></div>
        </details>
        {!!bulkPreview.length && <section className="review-work-card" aria-label="Bulk confirmation review">
          <h3>Review {bulkPreview.length} decisions before confirming</h3>
          <ul>{bulkPreview.slice((bulkPage - 1) * 50, bulkPage * 50).map((item) => <li key={item.key}>{item.scope} → <strong>{item.value}</strong></li>)}</ul>
          <div className="report-pager"><button type="button" disabled={bulkPage <= 1} onClick={() => setBulkPage((page) => page - 1)}>Previous values</button><span>Page {bulkPage} of {Math.ceil(bulkPreview.length / 50)}</span><button type="button" disabled={bulkPage * 50 >= bulkPreview.length} onClick={() => setBulkPage((page) => page + 1)}>Next values</button></div>
          <button type="button" className="primary-button" disabled={busy} onClick={() => void run(async () => {
            const values = new Map(bulkPreview.map((item) => [item.key, item.value]))
            await updateDecisions(decisions.map((item) => values.has(item.key) && item.mode !== 'UNSUPPORTED' ? engineerConfirmation(item, values.get(item.key)!) : item))
          }, 'Reviewed decisions confirmed.')}>Apply reviewed confirmations</button>
          <button type="button" className="secondary-button" onClick={() => setBulkPreview([])}>Cancel bulk confirmation</button>
        </section>}
      </>}


    </section>
  )
}
