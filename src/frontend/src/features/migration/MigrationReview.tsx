import { saveWorkspace, workspace } from '../../storage/workspaceStore'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { useEffect, useRef, useState } from 'react'
import type { SetStateAction } from 'react'
import { postForm } from '../../api/client'
import { FileUpload } from '../source/FileUpload'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import type { MigrationDraft, ReferenceRole } from './types'
import { MigrationDesignReview } from './components/MigrationDesignReview'
import type { Decision, DecisionDocument, ReviewData, ReviewGroup } from './reviewTypes'
import { download } from './download'
import { MigrationReviewQueues } from './components/MigrationReviewQueues'
import { MigrationDecisionTable } from './components/MigrationDecisionTable'
import { reconcileReviewDrafts } from './reviewDrafts'
import { MigrationInterfaceMappings } from './components/MigrationInterfaceMappings'
import { useMigrationReviewActivity } from './hooks/useMigrationReviewActivity'
import {
  buildBulkPreview,
  reviewQueueNames,
  reviewSuggestions,
  reviewVdoms,
  visibleReviewDecisions,
  visibleReviewGroups,
} from './reviewPresentation'

export function MigrationReview({ preview, vendor, onDecisionDocument, onContextChange, requestedDecision }: {
  preview: SourcePreviewData
  vendor: string
  onDecisionDocument?: (document: MigrationDecisionDocument | null) => void
  onContextChange?: (targetSource: SourceEvidence | null, targetDevice: string) => void
  requestedDecision?: { key: string; request: number } | null
}) {
  const source = preview.source_evidence
  const previewId = preview.source_digest || (source ? 'source' : '')
  const [targetSource, setTargetSource] = useState<SourceEvidence | null>(workspace().targetSource)
  const [targetFilename, setTargetFilename] = useState('')
  const [targetDevices, setTargetDevices] = useState<string[]>([])
  const [targetDevice, setTargetDevice] = useState(workspace().targetDevice)
  const [referenceRole, setReferenceRole] = useState<ReferenceRole>(workspace().referenceRole)
  const [deterministicDraft, setDeterministicDraft] = useState<MigrationDraft | null>(workspace().deterministicDraft)
  const [review, setReview] = useState<ReviewData | null>(null)
  const [drafts, updateDrafts] = useState<Record<string, string>>({})
  const [activeQueue, setActiveQueue] = useState('NEEDS_INPUT')
  const [selectedGroupKey, setSelectedGroupKey] = useState('')
  const [replaceTarget, setReplaceTarget] = useState(false)
  const [decisionPage, setDecisionPage] = useState(1)
  const [bulkPreview, setBulkPreview] = useState<Array<{ key: string; scope: string; value: string }>>([])
  const [bulkPage, setBulkPage] = useState(1)
  const [search, setSearch] = useState('')
  const [vdomFilter, setVdomFilter] = useState('all')
  const [decisionFilter, setDecisionFilter] = useState('all')
  const [evidenceFilter, setEvidenceFilter] = useState('all')
  const [pendingOnly, setPendingOnly] = useState(false)
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [bulkValue, setBulkValue] = useState('')
  const {
    postJson,
    run,
    busy,
    setReviewLoading,
    error,
    setError,
    status,
    setStatus,
    beginReviewRequest,
    finishReviewRequest,
    invalidateReviewRequests,
    reviewRequestIsCurrent,
    currentReviewVersion,
    beginStandaloneAction,
    finishStandaloneAction,
    actionIsCurrent,
    invalidateActions,
  } = useMigrationReviewActivity({ source, targetSource, targetDevice })
  const manualToolsRef = useRef<HTMLDetailsElement>(null)

  function setDrafts(value: SetStateAction<Record<string, string>>) {
    updateDrafts(value)
    setBulkPreview([])
  }

  async function prepareValues(values: Map<string, string>) {
    const overrides = { ...deterministicDraft?.context.overrides, ...Object.fromEntries(values) }
    await loadReview(currentDocument(), targetSource, targetDevice, referenceRole, overrides)
  }

  async function loadReview(document?: DecisionDocument, targetId = targetSource, device = targetDevice,
                            role = referenceRole, overrides = deterministicDraft?.context.overrides) {
    if (!previewId) return
    const request = beginReviewRequest()
    try {
      onDecisionDocument?.(null)
      setDeterministicDraft(null)
      void saveWorkspace({ deterministicDraft: null, artifact: null })
      const result = await postJson<ReviewData & { draft: MigrationDraft }>('/api/migration/design/prepare', {
        source,
        target_source: targetId, target_device: device, reference_role: role,
        ...(overrides ? { draft_overrides: overrides } : {}),
        ...(document ? { decision_document: document } : {}),
        ...(targetId ? { target_source: targetId } : {}),
        ...(device ? { target_device: device } : {}),
      })
      if (!reviewRequestIsCurrent(request)) return
      setReview(result)
      setDeterministicDraft(result.draft)
      await saveWorkspace({ targetSource: targetId, targetDevice: result.target_device || device || '',
        referenceRole: role, decisionDocument: result.decision_document as unknown as MigrationDecisionDocument,
        deterministicDraft: result.draft })
      if (!reviewRequestIsCurrent(request)) return
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
      const contextChanged = targetId !== targetSource || device !== targetDevice || result.target_evidence_changed
      const proposals = Object.fromEntries(result.draft.decisions.map((row) => [row.decision_key!, row.proposed_value ?? null]))
      const previousProposals = Object.fromEntries((deterministicDraft?.decisions ?? []).map((row) => [row.decision_key!, row.proposed_value ?? null]))
      setDrafts((current) => reconcileReviewDrafts(current, review?.decisions.decisions ?? [], result.decisions.decisions, Boolean(contextChanged), result.decision_candidates, proposals, previousProposals))
      setBulkPreview([])
      setSelectedKeys([])
    } catch (cause) {
      if (!reviewRequestIsCurrent(request)) return
      setError(cause instanceof Error ? cause.message : 'Could not load migration review')
      throw cause
    } finally {
      finishReviewRequest(request)
    }
  }

  useEffect(() => {
    if (vendor === 'fortigate' && previewId) {
      // Invalidate the previous decision document immediately; local state updates follow the awaited API response.
      void loadReview(workspace().decisionDocument as unknown as DecisionDocument | undefined).catch(() => {})
    }
    return () => {
      // Invalidate in-flight requests; this ref is a version counter, not a DOM node.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      invalidateReviewRequests()
      // This is also a request version counter, not a DOM node.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      invalidateActions()
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
    if (manualToolsRef.current) manualToolsRef.current.open = true
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setActiveQueue(group.queue)
    setSearch('')
    setVdomFilter('all')
    setSelectedGroupKey(group.decision_keys[0])
  }, [requestedDecision, review, setStatus])

  useEffect(() => {
    if (!requestedDecision) return
    const input = document.getElementById(`decision-${requestedDecision.key}`)
    const destination = input ?? document.getElementById('migration-review-title')
    destination?.scrollIntoView({ block: 'center' })
    destination?.focus()
  }, [requestedDecision, activeQueue, selectedGroupKey, review])

  if (vendor !== 'fortigate' || !previewId) return null

  function currentDocument(decisions = review?.decisions.decisions ?? []): DecisionDocument {
    return { ...(review?.decision_document ?? {}), decisions }
  }

  async function approveDesign(groups: string[]) {
    if (!deterministicDraft) return
    const version = currentReviewVersion()
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/design/approve', {
      decision_document: currentDocument(), draft: deterministicDraft, draft_digest: deterministicDraft.digest,
      reference_role: referenceRole, draft_overrides: deterministicDraft.context.overrides, selected_groups: groups,
    })
    if (!reviewRequestIsCurrent(version)) return
    await loadReview(result.decision_document)
  }

  async function uploadTarget(file: File | undefined) {
    if (!file) return
    const version = beginStandaloneAction('Reading PAN-OS target XML…')
    invalidateReviewRequests()
    setReviewLoading(false)
    try {
      onDecisionDocument?.(null)
      const form = new FormData()
      form.append('source_vendor', 'palo_alto')
      form.append('file', file)
      const result = await postForm<SourcePreviewData>('/api/preview', form)
      if (!actionIsCurrent(version)) return
      if (!result.source_evidence) throw new Error('PAN-OS preview did not return source evidence')
      const nextTargetId = result.source_evidence
      setTargetSource(nextTargetId)
      await loadReview(review ? currentDocument() : undefined, nextTargetId, '')
      if (!actionIsCurrent(version)) return
      setTargetFilename(file.name)
      setReplaceTarget(false)
      setStatus('Target evidence loaded. Review each suggested mapping before approving it.')
    } catch (cause) {
      if (!actionIsCurrent(version)) return
      setError(cause instanceof Error ? cause.message : 'Could not read target PAN-OS XML')
      setStatus('')
    } finally {
      finishStandaloneAction(version)
    }
  }

  async function selectTargetDevice(device: string) {
    setTargetDevice(device)
    await loadReview(currentDocument(), targetSource, device)
  }

  async function updateProposal(decision: Decision, value: string) {
    if (!value.trim()) return
    await prepareValues(new Map([[decision.key, value.trim()]]))
  }

  async function importIntent(file: File | undefined) {
    if (!file || !review) return
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/target-intent/import', {
      source,
      decision_document: currentDocument(),
      yaml: await file.text(),
      ...(targetSource ? { target_source: targetSource, target_device: targetDevice } : {}),
    })
    await prepareValues(new Map((result.decision_document.decisions ?? []).filter((row) => row.value).map((row) => [row.key, row.value!])))
  }

  async function exportIntent() {
    const result = await postJson<{ yaml: string }>('/api/migration/target-intent/export', {
      source,
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
    const next = new Map<string, string>()
    let matched = 0
    let ignored = 0
    const propose = (vdom: string, kind: string, name: string, field: string, value: string | null | undefined) => {
      const decision = decisions.find((item) => item.source_vdom === vdom && item.source_kind === kind && item.source_name === name && item.target_field === field)
      if (!decision || decision.mode === 'UNSUPPORTED' || value == null || value === '') { ignored++; return }
      next.set(decision.key, value)
      matched++
    }
    for (const [vdom, values] of Object.entries(result.mapping.vdoms ?? {})) for (const [field, value] of Object.entries(values)) propose(vdom, 'vdom', vdom, field, value)
    for (const [vdom, entries] of Object.entries(result.mapping.interfaces ?? {})) for (const [name, values] of Object.entries(entries)) for (const [field, value] of Object.entries(values)) {
      const kind = decisions.some((item) => item.source_vdom === vdom && item.source_kind === 'interface' && item.source_name === name && item.target_field === field) ? 'interface' : field === 'target_zone' ? 'zone' : 'interface'
      propose(vdom, kind, name, field, value)
    }
    for (const [vdom, entries] of Object.entries(result.mapping.zones ?? {})) for (const [name, values] of Object.entries(entries)) propose(vdom, 'zone', name, 'target_zone', values.target_zone)
    await prepareValues(next)
    setStatus(`Mapping imported: ${matched} decisions updated; ${ignored} entries ignored.`)
  }

  async function exportDecisions() {
    const result = await postJson<{ document: DecisionDocument }>('/api/migration/decisions/export', { source, decision_document: currentDocument() })
    download(JSON.stringify(result.document, null, 2), 'migration_decisions.json', 'application/json')
  }

  async function importDecisions(file: File | undefined) {
    if (!file) return
    const document = JSON.parse(await file.text()) as DecisionDocument
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/decisions/import', { source, document })
    await loadReview(result.decision_document, targetSource, targetDevice)
  }

  async function updateGroup(group: ReviewGroup) {
    const keys = new Set(group.decision_keys)
    const values = new Map(decisions.filter((item) => keys.has(item.key) && item.mode !== 'UNSUPPORTED')
      .map((item) => [item.key, (drafts[item.key] ?? item.value ?? item.suggested_value ?? '').trim()] as const).filter(([, value]) => value))
    await prepareValues(values)
    const unfilled = group.decisions.filter((item) => item.mode !== 'UNSUPPORTED' && item.mode !== 'AUTO' && !(drafts[item.key] ?? item.value ?? item.suggested_value ?? '').trim()).length
    setStatus(unfilled ? 'Draft updated. This group still needs additional values.' : 'Draft updated. Review and approve the proposed configuration.')
  }

  async function applyGroupAction(action: NonNullable<ReviewGroup['actions']>[number]) {
    if (action.value) await prepareValues(new Map(action.apply_to.map((key) => [key, action.value])))
    else await loadReview(currentDocument())
  }

  async function applyRuleSuggestion(suggestion: ReviewData['rule_suggestions'][number]) {
    await prepareValues(new Map(suggestion.apply_to.map((key) => [key, suggestion.target_zone])))
  }

  const decisions = review?.decisions.decisions ?? []
  const suggestions = reviewSuggestions(decisions)
  const devices = targetDevices
  const reviewGroups = review?.review_groups ?? []
  const vdoms = reviewVdoms(reviewGroups)
  const queueNames = [...reviewQueueNames]
  const visibleGroups = visibleReviewGroups(reviewGroups, activeQueue, vdomFilter, search)
  const visibleDecisions = visibleReviewDecisions(decisions, decisionFilter, evidenceFilter, vdomFilter, pendingOnly, reviewGroups)

  function reviewProposals(keys: string[], valueFor: (decision: Decision) => string) {
    setBulkPreview(buildBulkPreview(decisions, keys, valueFor))
    setBulkPage(1)
    requestAnimationFrame(() => document.querySelector('[aria-label="Bulk proposal review"]')?.scrollIntoView({ block: 'start' }))
  }

  function clearSelected() {
    const selected = new Set(selectedKeys)
    const overrides = Object.fromEntries(Object.entries(deterministicDraft?.context.overrides ?? {}).filter(([key]) => !selected.has(key)))
    void run(() => loadReview(currentDocument(decisions.map((item) => selected.has(item.key) ? {
      ...item, value: null, mode: item.mode === 'AUTO' ? 'REQUIRED' : item.mode, review_state: 'PENDING',
      evidence_source: null, evidence_type: null, evidence_value: null, target_object: null,
      evidence_target_digest: null, evidence_target_device: null,
      approved_operation: null, approval_context: null,
    } : item)), targetSource, targetDevice, referenceRole, overrides), 'Selected allocations cleared. Derived proposals may be suggested again.')
  }

  return (
    <section className="panel migration-review" aria-labelledby="migration-review-title">
      <h2 id="migration-review-title" tabIndex={-1}>Review migration design</h2>
      <p className="migration-review-intro">Review the proposed configuration, resolve exceptions, then approve the ready groups.</p>
      <p className="report-count-note">FortiGate → PAN-OS · Review VDOM, VSYS, and virtual router decisions before dependent mappings.</p>

      <details className="migration-target-evidence" open={targetSource ? undefined : true}>
        <summary>Target configuration — optional{targetFilename ? ` · ${targetFilename}` : ''}</summary>
      <div className="migration-toolbar">
        <div className="target-xml-upload">
          <h3>Optional PAN-OS target XML</h3>
          {(!targetSource || replaceTarget) && <FileUpload file={null} accept=".xml,application/xml,text/xml" disabled={busy} title="Drop your target XML here" helpText="Optional · Supports .xml files" onChange={(file) => { if (file) void uploadTarget(file) }} />}
          {targetFilename && <p className="report-count-note">Loaded target: {targetFilename}</p>}
        </div>
        {targetSource && <button className="secondary-button" type="button" disabled={busy} onClick={() => setReplaceTarget((value) => !value)}>Replace XML</button>}
        {targetSource && <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(async () => {
          setTargetSource(null); setTargetFilename(''); setTargetDevices([]); setTargetDevice('')
          onContextChange?.(null, '')
          await loadReview(currentDocument(), null, '')
        }, 'Target evidence removed.')}>Remove target</button>}
        {devices.length > 0 && <label className="field">Target device
          <select value={targetDevice} disabled={busy} onChange={(event) => void run(() => selectTargetDevice(event.target.value))}>
            <option value="">Select a device</option>
            {devices.map((device) => <option key={device} value={device}>{device}</option>)}
          </select>
        </label>}
        {targetSource && <label className="field">Reference role<select value={referenceRole} disabled={busy}
          onChange={(event) => { const role = event.target.value as ReferenceRole; setReferenceRole(role); void run(() => loadReview(currentDocument(), targetSource, targetDevice, role)) }}>
          <option value="DESTINATION">Destination configuration</option><option value="TEMPLATE">Architecture template</option>
        </select></label>}
      </div>

      </details>

      {error && <div className="error-banner" role="alert">{error}</div>}
      {(status || busy) && <p role="status" aria-live="polite" className="migration-status">{busy ? 'Updating migration review…' : status}</p>}
      {review && <>
        {deterministicDraft && <MigrationDesignReview key={deterministicDraft.digest} draft={deterministicDraft} busy={busy}
          approvedItems={Object.keys((review.decision_document.design_approval as { configuration?: Record<string, unknown> } | undefined)?.configuration || {})}
          onPrepare={(overrides) => void run(() => loadReview(currentDocument(), targetSource, targetDevice, referenceRole, overrides), 'Draft updated. Review the changed configuration.')}
          onApprove={(groups) => void run(() => approveDesign(groups), 'Selected design groups approved.')} />}
        <details ref={manualToolsRef} className="migration-review-tools"><summary>Advanced proposal editors</summary>
        <p>These tools update the same design draft. Approve changes in Proposed configuration.</p>
        <p className="migration-counts"><strong>{reviewGroups.filter((item) => item.queue !== 'COMPLETE').length} mapping groups remaining · {reviewGroups.filter((item) => item.queue === 'CONFLICT').length} conflict groups</strong></p>
        {review.architecture_questions?.[0] && <button className="secondary-button" type="button" onClick={() => {
          const question = review.architecture_questions![0]
          const group = reviewGroups.find((item) => item.source_vdom === question.source_vdom && item.source_name === question.source_name)
          if (group) { setActiveQueue(group.queue); setSearch(''); setVdomFilter('all'); setSelectedGroupKey(group.decision_keys[0]) }
        }}>Recommended next mapping: {review.architecture_questions[0].source_vdom} · {review.architecture_questions[0].source_name}</button>}
        <details className="migration-review-tools"><summary>Decision counts and impact</summary><p className="migration-counts">{decisions.filter((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED').length} remaining decisions · {reviewGroups.filter((item) => item.queue !== 'COMPLETE').length} remaining groups. Affected-object counts are per group and may overlap.</p></details>
        <MigrationInterfaceMappings review={review} drafts={drafts} setDraft={(key, value) => setDrafts((current) => ({ ...current, [key]: value }))}
          selectedKeys={selectedKeys} setSelectedKeys={(keys) => { setSelectedKeys(keys); setBulkPreview([]) }} busy={busy} reviewSelected={reviewProposals}
          openDetails={(key) => { const group = reviewGroups.find((item) => item.decision_keys.includes(key)); if (group) { setActiveQueue(group.queue); setSelectedGroupKey(group.decision_keys[0]); setSearch(''); setVdomFilter('all') } }} />
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
          decisions={decisions}
          busy={busy}
          run={run}
          applyRuleSuggestion={applyRuleSuggestion}
          applyGroupAction={applyGroupAction}
          updateGroup={updateGroup}
        />
        </details>
        <details className="migration-review-tools"><summary>Import / export target intent</summary><div className="migration-toolbar">
          <label className="field">Import target intent YAML
            <input type="file" accept=".yaml,.yml,text/yaml" disabled={busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void run(() => importIntent(file), 'Target intent imported.') }} />
          </label>
          <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(exportIntent, 'Target intent downloaded.')}>Export target intent</button>
<button className="secondary-button" type="button" disabled={busy || !suggestions.length} onClick={() => reviewProposals(suggestions.map((item) => item.key), (item) => item.suggested_value ?? '')}>Review all suggestions</button>
        </div>

        </details>
        <details className="migration-review-tools">
          <summary>Mapping files</summary>
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
          reviewProposals={reviewProposals}
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
          updateProposal={updateProposal}
        />
        {!!bulkPreview.length && <section className="review-work-card" aria-label="Bulk proposal review">
          <h3>Review {bulkPreview.length} proposed mappings</h3>
          <ul>{bulkPreview.slice((bulkPage - 1) * 50, bulkPage * 50).map((item) => <li key={item.key}>{item.scope} → <strong>{item.value}</strong></li>)}</ul>
          <div className="report-pager"><button type="button" disabled={bulkPage <= 1} onClick={() => setBulkPage((page) => page - 1)}>Previous values</button><span>Page {bulkPage} of {Math.ceil(bulkPreview.length / 50)}</span><button type="button" disabled={bulkPage * 50 >= bulkPreview.length} onClick={() => setBulkPage((page) => page + 1)}>Next values</button></div>
          <button type="button" className="primary-button" disabled={busy} onClick={() => void run(async () => {
            const values = new Map(bulkPreview.map((item) => [item.key, item.value]))
            await prepareValues(values)
          }, 'Draft updated. Review and approve the proposed configuration.')}>Update design draft</button>
          <button type="button" className="secondary-button" onClick={() => setBulkPreview([])}>Cancel proposal review</button>
        </section>}
      </>}


    </section>
  )
}
