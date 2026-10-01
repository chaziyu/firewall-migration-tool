import { useEffect, useRef, useState } from 'react'
import { postForm, postJson } from '../../api/client'
import { FileUpload } from '../source/FileUpload'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import type { Decision, DecisionDocument, Proposal, ReviewData, ReviewGroup } from './reviewTypes'
import { download } from './download'
import { MigrationReviewQueues } from './components/MigrationReviewQueues'
import { MigrationAIReview } from './components/MigrationAIReview'
import { MigrationDecisionTable } from './components/MigrationDecisionTable'
import { reconcileReviewDrafts } from './reviewDrafts'

export function MigrationReview({ preview, vendor, onDecisionDocument, onContextChange, requestedDecision }: {
  preview: SourcePreviewData
  vendor: string
  onDecisionDocument?: (document: MigrationDecisionDocument | null) => void
  onContextChange?: (targetPreviewId: string, targetDevice: string) => void
  requestedDecision?: { key: string; request: number } | null
}) {
  const previewId = typeof preview.preview_id === 'string' ? preview.preview_id : ''
  const [targetPreviewId, setTargetPreviewId] = useState('')
  const [targetFilename, setTargetFilename] = useState('')
  const [targetDevices, setTargetDevices] = useState<string[]>([])
  const [targetDevice, setTargetDevice] = useState('')
  const [review, setReview] = useState<ReviewData | null>(null)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [proposals, setProposals] = useState<Proposal[]>([])
  const [designSessionId, setDesignSessionId] = useState('')
  const [activeQueue, setActiveQueue] = useState('NEEDS_INPUT')
  const [selectedGroupKey, setSelectedGroupKey] = useState('')
  const [replaceTarget, setReplaceTarget] = useState(false)
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
    const currentGroupKey = selectedGroupKey || review?.review_groups.find((group) => group.queue === activeQueue)?.decision_keys[0]
    const selected = result.review_groups.find((group) => group.decision_keys[0] === currentGroupKey)
    const previousSelected = review?.review_groups.find((group) => group.decision_keys[0] === currentGroupKey)
    if (selected?.queue === 'COMPLETE' && previousSelected?.queue !== 'COMPLETE') {
      const next = result.review_groups.find((group) => group.queue === activeQueue && group.queue !== 'COMPLETE')
        ?? result.review_groups.find((group) => group.queue !== 'COMPLETE')
      if (next) { setActiveQueue(next.queue); setSelectedGroupKey(next.decision_keys[0]) }
      else { setActiveQueue('COMPLETE'); setSelectedGroupKey(selected.decision_keys[0]) }
    }
    setTargetDevices(result.target_devices || [])
    setTargetDevice(result.target_device || '')
    onDecisionDocument?.(result.decision_document as unknown as MigrationDecisionDocument)
    onContextChange?.(targetId, result.target_device || device || '')
    const contextChanged = targetId !== targetPreviewId || device !== targetDevice || result.target_evidence_changed
    setDrafts((current) => reconcileReviewDrafts(current, review?.decisions.decisions ?? [], result.decisions.decisions, Boolean(contextChanged)))
    setBulkPreview([])
    setSelectedKeys([])
  }

  useEffect(() => {
    if (vendor === 'fortigate' && previewId) {
      // Invalidate the previous decision document immediately; local state updates follow the awaited API response.
      // eslint-disable-next-line react-hooks/set-state-in-effect
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
    setSelectedGroupKey(group.decision_keys[0])
  }, [requestedDecision, review])

  useEffect(() => {
    if (!requestedDecision) return
    const input = document.getElementById(`decision-${requestedDecision.key}`)
    const destination = input ?? document.getElementById('migration-review-title')
    destination?.scrollIntoView({ block: 'center' })
    destination?.focus()
  }, [requestedDecision, activeQueue, selectedGroupKey, review])

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
      setTargetFilename(file.name)
      setReplaceTarget(false)
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
    const unfilled = group.decisions.filter((item) => item.mode !== 'UNSUPPORTED' && item.mode !== 'AUTO' && !(drafts[item.key] ?? item.value ?? item.suggested_value ?? '').trim()).length
    setStatus(unfilled ? 'Entered mappings confirmed. This group still needs additional values.' : 'Entered mappings confirmed; dependent mappings re-evaluated.')
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
  const queueNames = ['NEEDS_INPUT', 'CHOOSE_CANDIDATE', 'READY_TO_CONFIRM', 'CONFLICT', 'COMPLETE']
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
      <h2 id="migration-review-title" tabIndex={-1}>Review target mappings</h2>
      <p className="migration-review-intro">Target XML is optional. Suggestions stay pending until you confirm them.</p>
      <p className="report-count-note">FortiGate → PAN-OS · Review VDOM, VSYS, and virtual router decisions before dependent mappings.</p>

      <details className="migration-target-evidence" open={targetPreviewId ? undefined : true}>
        <summary>Target configuration — optional{targetFilename ? ` · ${targetFilename}` : ''}</summary>
      <div className="migration-toolbar">
        <div className="target-xml-upload">
          <h3>Optional PAN-OS target XML</h3>
          {(!targetPreviewId || replaceTarget) && <FileUpload file={null} accept=".xml,application/xml,text/xml" disabled={busy} title="Drop your target XML here" helpText="Optional · Supports .xml files" onChange={(file) => { if (file) void uploadTarget(file) }} />}
          {targetFilename && <p className="report-count-note">Loaded target: {targetFilename}</p>}
        </div>
        {targetPreviewId && <button className="secondary-button" type="button" disabled={busy} onClick={() => setReplaceTarget((value) => !value)}>Replace XML</button>}
        {targetPreviewId && <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(async () => {
          setTargetPreviewId(''); setTargetFilename(''); setTargetDevices([]); setTargetDevice(''); setProposals([]); setDesignSessionId('')
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

      </details>

      {error && <div className="error-banner" role="alert">{error}</div>}
      {(status || busy) && <p role="status" aria-live="polite" className="migration-status">{busy ? 'Updating migration review…' : status}</p>}
      {review && <>
        <p className="migration-counts"><strong>{reviewGroups.filter((item) => item.queue !== 'COMPLETE').length} mapping groups remaining · {reviewGroups.filter((item) => item.queue === 'CONFLICT').length} conflict groups</strong></p>
        {review.architecture_questions?.[0] && <button className="secondary-button" type="button" onClick={() => {
          const question = review.architecture_questions![0]
          const group = reviewGroups.find((item) => item.source_vdom === question.source_vdom && item.source_name === question.source_name)
          if (group) { setActiveQueue(group.queue); setSearch(''); setVdomFilter('all'); setSelectedGroupKey(group.decision_keys[0]) }
        }}>Recommended next mapping: {review.architecture_questions[0].source_vdom} · {review.architecture_questions[0].source_name}</button>}
        <details className="migration-review-tools"><summary>Decision counts and impact</summary><p className="migration-counts">{decisions.filter((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED').length} remaining decisions · {reviewGroups.filter((item) => item.queue !== 'COMPLETE').length} remaining groups. Affected-object counts are per group and may overlap.</p></details>
        <MigrationReviewQueues
          review={review}
          reviewGroups={reviewGroups}
          queueNames={queueNames}
          activeQueue={activeQueue}
          setActiveQueue={setActiveQueue}
          search={search}
          setSearch={setSearch}
          vdomFilter={vdomFilter}
          setVdomFilter={setVdomFilter}
          vdoms={vdoms}
          visibleGroups={visibleGroups}
          selectedGroupKey={selectedGroupKey}
          setSelectedGroupKey={setSelectedGroupKey}
          setDecisionPage={setDecisionPage}
          drafts={drafts}
          setDrafts={setDrafts}
          proposals={proposals}
          decisions={decisions}
          busy={busy}
          run={run}
          applyRuleSuggestion={applyRuleSuggestion}
          applyGroupAction={applyGroupAction}
          confirmGroup={confirmGroup}
        />
        <details className="migration-review-tools"><summary>Import / export target intent</summary><div className="migration-toolbar">
          <label className="field">Import target intent YAML
            <input type="file" accept=".yaml,.yml,text/yaml" disabled={busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void run(() => importIntent(file), 'Target intent imported.') }} />
          </label>
          <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(exportIntent, 'Target intent downloaded.')}>Export target intent</button>
<button className="secondary-button" type="button" disabled={busy || !suggestions.length} onClick={() => bulkConfirm(suggestions.map((item) => item.key), (item) => item.suggested_value ?? '')}>Review all suggestions</button>
        </div>

        </details>
        <p className="report-count-note">AI assistance requires target XML and a selected target device. Proposals need your approval.</p>
        <MigrationAIReview
          advisorStatus={advisorStatus}
          busy={busy}
          targetPreviewId={targetPreviewId}
          targetDevice={targetDevice}
          designSessionId={designSessionId}
          validProposalKeys={validProposalKeys}
          proposals={proposals}
          run={run}
          testAdvisor={testAdvisor}
          buildProposals={buildProposals}
          approveProposals={approveProposals}
          approveProposal={approveProposal}
          rejectProposals={rejectProposals}
          setDrafts={setDrafts}
        />
        <details className="migration-review-tools">
          <summary>Mapping files and explicit automation</summary>
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

        <MigrationDecisionTable
          decisionFilter={decisionFilter}
          setDecisionFilter={setDecisionFilter}
          evidenceFilter={evidenceFilter}
          setEvidenceFilter={setEvidenceFilter}
          pendingOnly={pendingOnly}
          setPendingOnly={setPendingOnly}
          decisionPage={decisionPage}
          setDecisionPage={setDecisionPage}
          visibleDecisions={visibleDecisions}
          selectedKeys={selectedKeys}
          setSelectedKeys={setSelectedKeys}
          busy={busy}
          bulkConfirm={bulkConfirm}
          suggestions={suggestions}
          drafts={drafts}
          decisions={decisions}
          bulkValue={bulkValue}
          setBulkValue={setBulkValue}
          setError={setError}
          clearSelected={clearSelected}
          review={review}
          setDrafts={setDrafts}
          run={run}
          confirmDecision={confirmDecision}
        />
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
