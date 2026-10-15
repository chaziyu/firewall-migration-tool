import { saveWorkspace, workspace } from '../../storage/workspaceStore'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { SetStateAction } from 'react'
import { postForm } from '../../api/client'
import { FileUpload } from '../source/FileUpload'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import type { MigrationStage, MigrationDraft, ReferenceRole, ConversionSettings } from './types'
import { MigrationDesignReview } from './components/MigrationDesignReview'
import type { Decision, DecisionDocument, ReviewData, ReviewGroup } from './reviewTypes'
import { download } from './download'
import { MigrationReviewQueues } from './components/MigrationReviewQueues'
import { MigrationDecisionTable } from './components/MigrationDecisionTable'
import { draftRowKey, orderReviewGroups, reconcileReviewDrafts, reviewGroupActionable } from './reviewDrafts'
import { MigrationInterfaceMappings } from './components/MigrationInterfaceMappings'
import { MigrationTargetSetup } from './components/MigrationTargetSetup'
import { MigrationConversionSettings } from './components/MigrationConversionSettings'
import { Button } from '../../components/common/Button'
import { useMigrationReviewActivity } from './hooks/useMigrationReviewActivity'
import {
  buildBulkPreview,
  approvedDraftKeys,
  reviewQueueNames,
  reviewSuggestions,
  reviewVdoms,
  taskCategories,
  taskCategory,
  mappingReviewGroups,
  visibleReviewDecisions,
  visibleReviewGroups,
} from './reviewPresentation'

function focusMappingInput(key: string) {
  requestAnimationFrame(() => {
    const input = document.getElementById(`setup-${key}`) ?? document.getElementById(`decision-${key}`)
    if (!input) return
    const details = input.closest('details')
    if (details) details.open = true
    input.scrollIntoView({ block: 'center' })
    input.focus()
  })
}

export function MigrationReview({ preview, vendor, onDecisionDocument, onContextChange, requestedDecision, stage, onStageChange, onApproved }: {
  stage?: MigrationStage
  onStageChange?: (stage: MigrationStage) => void
  onApproved?: () => void
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
  const [localReviewSection, setLocalReviewSection] = useState<'target' | 'mappings' | 'configuration'>('mappings')
  const reviewSection = stage === 'load' ? 'target' : stage === 'place' ? 'mappings' : stage === 'review' ? 'configuration' : localReviewSection
  const setReviewSection = useCallback((value: 'target' | 'mappings' | 'configuration') => { setLocalReviewSection(value); onStageChange?.(value === 'target' ? 'load' : value === 'mappings' ? 'place' : 'review') }, [onStageChange])
  const [mappingView, setMappingView] = useState<'guided' | 'bulk'>('guided')
  const [deterministicDraft, setDeterministicDraft] = useState<MigrationDraft | null>(workspace().deterministicDraft)
  const [workflowMode, setWorkflowMode] = useState<'offline' | 'destination'>(workspace().workflowMode ?? 'offline')
  const [issuePage, setIssuePage] = useState(1)
  const [exceptionsOpen, setExceptionsOpen] = useState(false)
  const [setupFocus, setSetupFocus] = useState<{ key: string; request: number } | null>(null)
  const [reviewCurrent, setReviewCurrent] = useState(false)
  const [settingsDirty, setSettingsDirty] = useState(false)
  const retryReview = useRef<(() => Promise<unknown>) | null>(null)
  const [review, setReview] = useState<ReviewData | null>(null)
  const [drafts, updateDrafts] = useState<Record<string, string>>(workspace().proposals ?? {})
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
    actionBusy,
    elapsedSeconds,
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
  } = useMigrationReviewActivity({ source, targetSource, targetDevice, workflowMode })
  const manualToolsRef = useRef<HTMLDetailsElement>(null)
  const bulkMappingsRef = useRef<HTMLDetailsElement>(null)
  const focusNextGroupKey = useRef('')
  const onSettingsDirty = useCallback((dirty: boolean) => {
    setSettingsDirty(dirty)
    if (dirty) { onDecisionDocument?.(null); void saveWorkspace({ artifact: null }) }
  }, [onDecisionDocument])

  function setDrafts(value: SetStateAction<Record<string, string>>) {
    const next = typeof value === 'function' ? value(drafts) : value
    if (Object.keys(next).length === Object.keys(drafts).length && Object.entries(next).every(([key, value]) => drafts[key] === value)) return
    updateDrafts(next)
    void saveWorkspace({ proposals: { ...workspace().proposals, ...next } })
    setBulkPreview([])
    setStatus('Draft saved locally. Validate staged changes before approval.')
    onDecisionDocument?.(null)
    void saveWorkspace({ artifact: null })
  }

  async function prepareValues(values: Map<string, string>, serviceNames = deterministicDraft?.context.service_names) {
    const overrides = { ...deterministicDraft?.context.overrides, ...Object.fromEntries([...values].filter(([, value]) => value.trim()).map(([key, value]) => [key, value.trim()])) }
    return loadReview(currentDocument(), targetSource, targetDevice, referenceRole, overrides, serviceNames)
  }

  async function loadReview(document?: DecisionDocument, targetId = targetSource, device = targetDevice,
                            role = referenceRole, overrides = deterministicDraft?.context.overrides,
                            serviceNames = deterministicDraft?.context.service_names, mode = workflowMode,
                            conversionSettings: ConversionSettings = deterministicDraft?.context.conversion_settings ?? {}) {
    if (!previewId) return null
    void saveWorkspace({ proposals: { ...workspace().proposals, ...overrides }, serviceNames: serviceNames ?? {} })
    retryReview.current = () => loadReview(document, targetId, device, role, overrides, serviceNames, mode, conversionSettings)
    const request = beginReviewRequest()
    setReviewCurrent(false)
    try {
      onDecisionDocument?.(null)
      void saveWorkspace({ artifact: null })
      const result = await postJson<ReviewData & { draft: MigrationDraft }>('/api/migration/design/prepare', {
        source,
        workflow_mode: mode === 'offline' ? 'OFFLINE_EXPORT' : 'DESTINATION_AWARE',
        conversion_settings: conversionSettings,
        ...(serviceNames ? { service_name_overrides: serviceNames } : {}),
        target_source: targetId, target_device: device, reference_role: role,
        ...(overrides ? { draft_overrides: overrides } : {}),
        ...(document ? { decision_document: document } : {}),
        ...(targetId ? { target_source: targetId } : {}),
        ...(device ? { target_device: device } : {}),
      })
      if (!reviewRequestIsCurrent(request)) return null
      setReview(result)
      setReviewCurrent(true)
      setSettingsDirty(false)
      setDeterministicDraft(result.draft)
      await saveWorkspace({ targetSource: targetId, targetDevice: result.target_device || device || '',
        referenceRole: role, decisionDocument: result.decision_document as unknown as MigrationDecisionDocument,
        deterministicDraft: result.draft, proposals: overrides ?? {}, serviceNames: serviceNames ?? {} })
      if (!reviewRequestIsCurrent(request)) return null
      const reviewRows = [...result.draft.decisions, ...result.draft.configuration]
      const orderedGroups = orderReviewGroups(mappingReviewGroups(result.review_groups, reviewRows, mode === 'offline', approvedDraftKeys(result.decision_document)), reviewRows, result.decision_context ?? {})
      const currentGroupKey = selectedGroupKey || orderedGroups.find((group) => group.queue !== 'COMPLETE')?.decision_keys[0]
      if (!selectedGroupKey) {
        const rows = [...result.draft.decisions, ...result.draft.configuration]
        const first = orderedGroups.find((group) => reviewGroupActionable(group, rows)) ?? orderedGroups.find((group) => group.queue !== 'COMPLETE')
        if (first) { setActiveQueue(first.queue); setSelectedGroupKey(first.decision_keys[0]) }
      }
      const selected = orderedGroups.find((group) => group.decision_keys[0] === currentGroupKey)
      const previousSelected = review?.review_groups.find((group) => group.decision_keys[0] === currentGroupKey)
      if (selected?.queue === 'COMPLETE' && previousSelected?.queue !== 'COMPLETE') {
        const next = orderedGroups.find((group) => group.queue === activeQueue && group.queue !== 'COMPLETE')
          ?? orderedGroups.find((group) => group.queue !== 'COMPLETE')
        if (next) { setActiveQueue(next.queue); setSelectedGroupKey(next.decision_keys[0]) }
        else { setActiveQueue('COMPLETE'); setSelectedGroupKey(selected.decision_keys[0]) }
      }
      setTargetDevices(result.target_devices || [])
      setTargetDevice(result.target_device || '')
      onDecisionDocument?.(result.decision_document as unknown as MigrationDecisionDocument)
      onContextChange?.(targetId, result.target_device || device || '')
      const contextChanged = JSON.stringify(targetId) !== JSON.stringify(targetSource) || device !== targetDevice || result.target_evidence_changed
      const proposals = Object.fromEntries(result.draft.decisions.map((row) => [row.decision_key!, row.proposed_value ?? null]))
      const previousProposals = Object.fromEntries((deterministicDraft?.decisions ?? []).map((row) => [row.decision_key!, row.proposed_value ?? null]))
      const reconciled = reconcileReviewDrafts(drafts, review?.decisions.decisions ?? [], result.decisions.decisions, Boolean(contextChanged), result.decision_candidates, proposals, previousProposals)
      updateDrafts(reconciled)
      void saveWorkspace({ proposals: { ...overrides, ...reconciled } })
      setBulkPreview([])
      setSelectedKeys([])
      return result
    } catch (cause) {
      if (!reviewRequestIsCurrent(request)) return null
      setError(cause instanceof Error ? cause.message : 'Could not load migration review')
      throw cause
    } finally {
      finishReviewRequest(request)
    }
  }

  useEffect(() => {
    let active = true
    // StrictMode replays effects; defer so its cancelled setup never starts a request.
    queueMicrotask(() => {
      if (active && vendor === 'fortigate' && previewId) {
        void loadReview(workspace().decisionDocument as unknown as DecisionDocument | undefined).catch(() => {})
      }
    })
    return () => {
      active = false
      // Invalidate in-flight requests; this ref is a version counter, not a DOM node.
      invalidateReviewRequests()
      // This is also a request version counter, not a DOM node.
      invalidateActions()
    }
    // Reload only when the source preview changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewId, vendor])

  useEffect(() => {
    if (!requestedDecision || !review) return
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setReviewSection(requestedDecision.key ? 'mappings' : 'configuration')
    setSetupFocus(requestedDecision)
    if (!requestedDecision.key) return
    const group = review.review_groups.find((item) => item.decision_keys.includes(requestedDecision.key))
    if (!group) {
      setStatus('This finding has no editable mapping in the current review. Review its support guidance.')
      return
    }
    // Synchronize a plan blocker navigation request with the server-owned queue.
    if (manualToolsRef.current) manualToolsRef.current.open = true
    setMappingView('guided')
    setActiveQueue(group.queue)
    setSearch('')
    setVdomFilter('all')
    setSelectedGroupKey(group.decision_keys[0])
  }, [requestedDecision, review, setStatus, setReviewSection])

  useEffect(() => {
    const key = requestedDecision?.key
    if (!key || !review) return
    const input = document.getElementById(`setup-${key}`) ?? document.getElementById(`decision-${key}`)
    if (input) {
      const details = input.closest('details')
      if (details) details.open = true
      input.scrollIntoView({ block: 'center' })
      input.focus()
    } else if (requestedDecision) {
      const title = document.getElementById('migration-review-title')
      title?.scrollIntoView({ block: 'center' })
      title?.focus()
    }
  }, [requestedDecision, activeQueue, selectedGroupKey, review])

  useEffect(() => {
    if (!focusNextGroupKey.current || !review) return
    const heading = document.getElementById(`review-group-heading-${focusNextGroupKey.current}`)
    if (heading) { heading.scrollIntoView({ block: 'center' }); heading.focus(); focusNextGroupKey.current = '' }
  }, [selectedGroupKey, review])

  const proposalRows = useMemo(() => [...(deterministicDraft?.decisions ?? []), ...(deterministicDraft?.configuration ?? [])], [deterministicDraft])
  const proposalByKey = useMemo(() => new Map(proposalRows.map((row) => [draftRowKey(row), row])), [proposalRows])
  const reviewGroups = useMemo(() => review ? orderReviewGroups(mappingReviewGroups(review.review_groups, proposalRows, workflowMode === 'offline', approvedDraftKeys(review.decision_document)), proposalRows, review.decision_context ?? {}) : [], [review, proposalRows, workflowMode])
  const actionableGroups = useMemo(() => reviewGroups.filter((group) => reviewGroupActionable(group, proposalByKey) && group.decision_keys.some((key) => proposalByKey.get(key)?.status !== 'READY' || !Object.hasOwn(deterministicDraft?.context.overrides ?? {}, key))), [reviewGroups, proposalByKey, deterministicDraft])

  if (vendor !== 'fortigate' || !previewId) return null

  function currentDocument(decisions = review?.decisions.decisions ?? []): DecisionDocument {
    return { ...(review?.decision_document ?? {}), decisions }
  }

  async function approveDesign(groups: string[]) {
    if (!deterministicDraft || !reviewCurrent || settingsDirty) return
    const version = currentReviewVersion()
    const result = await postJson<{ decision_document: DecisionDocument }>('/api/migration/design/approve', {
      decision_document: currentDocument(), draft: deterministicDraft, draft_digest: deterministicDraft.digest,
      reference_role: referenceRole, draft_overrides: deterministicDraft.context.overrides, selected_groups: groups,
      service_name_overrides: deterministicDraft.context.service_names ?? {},
      conversion_settings: deterministicDraft.context.conversion_settings ?? {},
    })
    if (!reviewRequestIsCurrent(version)) return
    setReview((current) => current ? { ...current, decision_document: result.decision_document } : current)
    await saveWorkspace({ decisionDocument: result.decision_document as unknown as MigrationDecisionDocument })
    onDecisionDocument?.(result.decision_document as unknown as MigrationDecisionDocument)
    setReviewCurrent(false)
    onApproved?.()
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

  async function selectReferenceRole(role: ReferenceRole) {
    if (role === referenceRole) return
    setReferenceRole(role)
    setReviewCurrent(false)
    setDeterministicDraft(null)
    onDecisionDocument?.(null)
    await saveWorkspace({ referenceRole: role, decisionDocument: null, artifact: null,
      proposals: { ...workspace().proposals, ...drafts }, serviceNames: deterministicDraft?.context.service_names ?? {} })
    await loadReview(currentDocument(), targetSource, targetDevice, role)
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
    const result = await postJson<{ mapping: { vdoms?: Record<string, Record<string, string | null>>; interfaces?: Record<string, Record<string, Record<string, string | null>>>; zones?: Record<string, Record<string, { target_zone?: string | null }>>; service_names?: Record<string, Record<string, string>> } }>('/api/migration/mapping/import', { yaml: await file.text() })
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
    await prepareValues(next, result.mapping.service_names ?? deterministicDraft?.context.service_names)
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
    reviewProposals([...new Set([...group.decision_keys, ...changedMappings.map((row) => row.decision_key!)])],
      (item) => drafts[item.key] ?? item.value ?? item.suggested_value ?? '')
  }

  async function validateStagedChanges() {
    const values = new Map(bulkPreview.map((item) => [item.key, item.value]))
    const result = await prepareValues(values)
    if (!result) return
    const rows = [...result.draft.decisions, ...result.draft.configuration]
    const byKey = new Map(rows.map((row) => [draftRowKey(row), row]))
    const touchedKeys = result.review_groups.filter((group) => group.decision_keys.some((key) => values.has(key)))
      .flatMap((group) => group.decisions.filter((item) => item.mode !== 'UNSUPPORTED').map((item) => item.key))
    const validated = [...new Set([...values.keys(), ...touchedKeys])].every((key) => {
      const row = byKey.get(key)
      return row && (row.status === 'READY' || row.approved)
    })
    setStatus(validated ? 'Staged changes validated — awaiting approval.' : 'Draft prepared. Validation findings or unresolved prerequisites remain; review the root tasks.')
    if (!validated) return
    const ordered = orderReviewGroups(result.review_groups, rows, result.decision_context ?? {})
    const next = ordered.find((candidate) => reviewGroupActionable(candidate, byKey) && !candidate.decision_keys.some((key) => values.has(key))
      && candidate.decision_keys.some((key) => byKey.get(key)?.status !== 'READY' || !Object.hasOwn(result.draft.context.overrides, key)))
    if (next) {
      focusNextGroupKey.current = next.decision_keys[0]
      setActiveQueue(next.queue)
      setSelectedGroupKey(next.decision_keys[0])
      setSearch('')
      setVdomFilter('all')
    }
  }

  async function applyMappings() {
    const values = new Map(changedMappings.filter((row) => drafts[row.decision_key!].trim())
      .map((row) => [row.decision_key!, drafts[row.decision_key!]]))
    if (!values.size) return
    const result = await prepareValues(values)
    if (result) setStatus(result.draft.decisions.filter((row) => values.has(row.decision_key!)).every((row) => row.status === 'READY')
      ? 'Mappings validated. Review the supported changes before approval.' : 'Mappings checked. Resolve the remaining input or conflicts before approving dependent changes.')
  }

  async function applyGroupAction(action: NonNullable<ReviewGroup['actions']>[number]) {
    if (action.value) setDrafts((current) => ({ ...current, ...Object.fromEntries(action.apply_to.map((key) => [key, action.value])) }))
  }

  async function applyRuleSuggestion(suggestion: ReviewData['rule_suggestions'][number]) {
    setDrafts((current) => ({ ...current, ...Object.fromEntries(suggestion.apply_to.map((key) => [key, suggestion.target_zone])) }))
  }

  const decisions = review?.decisions.decisions ?? []
  const suggestions = reviewSuggestions(decisions)
  const devices = targetDevices
  const vdoms = reviewVdoms(reviewGroups)
  const queueNames = [...reviewQueueNames]
  const visibleGroups = visibleReviewGroups(reviewGroups, activeQueue, vdomFilter, search)
  const visibleDecisions = visibleReviewDecisions(decisions, decisionFilter, evidenceFilter, vdomFilter, pendingOnly, reviewGroups)
  const changedMappings = deterministicDraft?.decisions.filter((row) => row.decision_key && drafts[row.decision_key] !== undefined
    && drafts[row.decision_key].trim() !== (row.proposed_value ?? '')) ?? []
  const approvedItems = changedMappings.length ? [] : approvedDraftKeys(review?.decision_document ?? {})
  const approvedKeys = new Set(approvedItems)
  const stagedKeys = new Set(bulkPreview.map((item) => item.key))
  const stagedDependents = proposalRows.filter((row) => (row.dependencies ?? []).some((key) => stagedKeys.has(key)))

  function reviewProposals(keys: string[], valueFor: (decision: Decision) => string) {
    const preview = buildBulkPreview(decisions, keys, valueFor)
    setBulkPreview(preview)
    if (!preview.length) setStatus('Enter at least one target value to validate. Blank fields remain local and unresolved.')
    setBulkPage(1)
    requestAnimationFrame(() => document.querySelector('[aria-label="Bulk proposal review"]')?.scrollIntoView({ block: 'start' }))
  }

  function clearSelected() {
    const selected = new Set(selectedKeys)
    const overrides = Object.fromEntries(Object.entries(deterministicDraft?.context.overrides ?? {}).filter(([key]) => !selected.has(key)))
    void run(async () => { await loadReview(currentDocument(decisions.map((item) => selected.has(item.key) ? {
      ...item, value: null, mode: item.mode === 'AUTO' ? 'REQUIRED' : item.mode, review_state: 'PENDING',
      evidence_source: null, evidence_type: null, evidence_value: null, target_object: null,
      evidence_target_digest: null, evidence_target_device: null,
      approved_operation: null, approval_context: null,
    } : item)), targetSource, targetDevice, referenceRole, overrides) }, 'Selected allocations cleared. Derived proposals may be suggested again.')
  }

  return (
    <section className="panel migration-review" aria-labelledby="migration-review-title">
      <h2 id="migration-review-title" tabIndex={-1}>{stage === 'load' ? 'Source and conversion settings' : stage === 'review' ? 'Review conversion' : workflowMode === 'offline' ? 'Target setup' : 'Resolve mappings'}</h2>

      <div hidden={stage != null && stage !== 'load'}>
      <label className="field">Migration intent<select aria-label="Migration intent" value={workflowMode} disabled={busy} onChange={async (event) => {
        const mode = event.target.value as 'offline' | 'destination'
        setWorkflowMode(mode)
        setReviewCurrent(false)
        setDeterministicDraft(null)
        setTargetSource(null); setTargetDevice(''); setTargetFilename(''); setTargetDevices([])
        onDecisionDocument?.(null); onContextChange?.(null, '')
        void saveWorkspace({ workflowMode: mode, targetSource: null, targetDevice: '', decisionDocument: null, artifact: null })
        await run(async () => { await loadReview(currentDocument(), null, '', referenceRole, {}, {}, mode) })
      }}>
        <option value="offline">Offline .set export</option><option value="destination">Advanced: destination-aware migration</option>
      </select></label>
      <p>{workflowMode === 'offline' ? 'Review the source-derived proposals and allocate target ports, then approve and download PAN-OS commands. Destination compatibility remains unverified.' : 'Upload actual destination XML to check target mappings and reuse.'}</p>
      <details key={workflowMode} hidden={workflowMode === 'offline'} className="migration-target-evidence" open={workflowMode === 'destination'}>
        <summary>{workflowMode === 'offline' ? 'Optional PAN-OS reference' : 'PAN-OS destination XML'}{targetFilename ? ` · ${targetFilename}` : ''}</summary>
      <div className="migration-toolbar">
        <div className="target-xml-upload">
          <label className="field">Reference role<select aria-label="Reference role" value={referenceRole} disabled={busy}
            onChange={async (event) => { await run(() => selectReferenceRole(event.target.value as ReferenceRole)) }}>
            <option value="DESTINATION">Destination configuration</option><option value="TEMPLATE">Architecture template</option>
          </select></label>
          {(!targetSource || replaceTarget) && <FileUpload file={null} accept=".xml,application/xml,text/xml" disabled={actionBusy} title="Drop your target XML here" helpText="Supports .xml files · Select the evidence role explicitly" onChange={(file) => { if (file) void uploadTarget(file) }} />}
          {targetFilename && <p className="report-count-note">Loaded target: {targetFilename}</p>}
          {targetSource && !replaceTarget && <p className="report-count-note">Reference role: {referenceRole === 'DESTINATION' ? 'Destination configuration' : 'Architecture template'}</p>}
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
      </div>

      </details>
      <Button disabled={busy || !reviewCurrent} onClick={() => setReviewSection('mappings')}>Continue to target setup</Button>
      </div>

      {error && <div className="error-banner" role="alert">{error}<button type="button" disabled={busy} onClick={() => void run(async () => { await retryReview.current?.() })}>Retry intended draft update</button></div>}
      {review && !reviewCurrent && <p role="status">{review.decision_document.design_approval && !error && !busy ? 'This proposal was approved. Revalidate the draft before changing the approved selection.' : 'Previous successful review — stale and read-only. Pending changes have no approval or execution authority.'}</p>}
      {review?.decision_document.design_approval != null && <p role="status">Approval expires {new Date(Number((review.decision_document.design_approval as { expires_at?: number }).expires_at ?? 0) * 1000).toLocaleString()}. After expiration, revalidate and approve the design again. Server checks govern execution. <button type="button" disabled={busy || !!changedMappings.length} onClick={() => void run(async () => { await loadReview(currentDocument()) })}>Renew review</button></p>}
      {(status || busy) && <p role="status" aria-live="polite" className="migration-status">{busy ? 'Preparing and validating the design draft…' : status}{busy && <span aria-hidden="true"> · {elapsedSeconds}s elapsed</span>}</p>}
      {review && <>
        {!stage && <nav className="migration-view-nav" aria-label="Design review stages">
          <button type="button" aria-pressed={reviewSection === 'mappings'} onClick={() => setReviewSection('mappings')}>Resolve mappings</button>
          <button type="button" aria-pressed={reviewSection === 'configuration'} onClick={() => setReviewSection('configuration')}>Review &amp; approve</button>
          <button type="button" disabled={busy || !!changedMappings.length} onClick={() => void run(async () => { await loadReview(currentDocument()) }, 'Design revalidated.')}>Revalidate design</button>
        </nav>}
        {workflowMode !== 'offline' && !!changedMappings.length && <div className="review-work-card" role="status"><p>{changedMappings.length} staged mapping edits. Blank fields stay local and unresolved.</p><button type="button" className="secondary-button" disabled={busy || !changedMappings.some((row) => drafts[row.decision_key!].trim())} onClick={() => reviewProposals(changedMappings.map((row) => row.decision_key!), (decision) => drafts[decision.key])}>Review staged mappings</button></div>}
        {deterministicDraft && <div hidden={stage ? stage !== 'review' : reviewSection !== 'configuration'}><MigrationDesignReview draft={deterministicDraft} busy={busy || !reviewCurrent || !!changedMappings.length || settingsDirty}
          approvedItems={approvedItems}
          onApprove={(groups) => void run(() => approveDesign(groups), 'Selected design groups approved.')}
          onRenameService={(row, name) => { const names = deterministicDraft.context.service_names ?? {}; void run(async () => { await loadReview(currentDocument(), targetSource, targetDevice, referenceRole, deterministicDraft.context.overrides, { ...names, [row.source_vdom]: { ...names[row.source_vdom], [row.source_name]: name } }) }, 'Service name proposed. Review and approve the rebuilt configuration.') }} /></div>}
        <section hidden={stage ? stage !== 'place' : reviewSection !== 'mappings'} aria-label="Resolve mappings">
        {deterministicDraft && <MigrationConversionSettings key={deterministicDraft.digest} draft={deterministicDraft} busy={busy || !reviewCurrent || !!changedMappings.length}
          onDirtyChange={onSettingsDirty}
          onApply={(settings) => void run(async () => { await loadReview(currentDocument(), targetSource, targetDevice, referenceRole, deterministicDraft.context.overrides, deterministicDraft.context.service_names, workflowMode, settings) }, 'Conversion settings validated. Review and approve the updated design.')} />}
        {workflowMode === 'offline' && deterministicDraft && <MigrationTargetSetup draft={deterministicDraft} review={review} drafts={drafts}
          approvedItems={approvedItems} busy={busy || !reviewCurrent || settingsDirty} focusRequest={setupFocus}
          onChange={(key, value) => setDrafts((current) => ({ ...current, [key]: value }))}
          onApply={() => run(applyMappings)} onReview={() => setReviewSection('configuration')} />}
        {workflowMode === 'destination' && <details className="migration-review-tools" open>
        <summary>Advanced mapping editors</summary>
        <p>Review VDOM, VSYS, and virtual-router ownership, then allocate parent ports. Changes remain proposals until design approval.</p>
         {workflowMode === 'destination' && <div className="migration-summary" aria-label="Mapping task dashboard">{taskCategories.map((category) => <p key={category}><strong>{category}</strong><br />{(deterministicDraft?.decisions ?? []).filter((row) => taskCategory(row, proposalByKey, approvedKeys) === category).length} mapping fields · {(deterministicDraft?.configuration ?? []).filter((row) => taskCategory(row, proposalByKey, approvedKeys) === category).length} configuration items</p>)}</div>}
         {actionableGroups[0] && <button className="secondary-button" type="button" onClick={() => {
           const group = actionableGroups[0]
           setMappingView('guided')
           setActiveQueue(group.queue); setSearch(''); setVdomFilter('all'); setSelectedGroupKey(group.decision_keys[0])
         }}>Recommended next mapping: {actionableGroups[0].source_vdom} · {actionableGroups[0].source_name}</button>}
         <details className="migration-review-tools"><summary>Decision counts and impact</summary><p className="migration-counts">{decisions.filter((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED').length} decision fields remaining · {reviewGroups.filter((item) => item.queue !== 'COMPLETE').length} mapping groups remaining. Affected-object counts are per group and may overlap.</p></details>
        <nav className="migration-view-nav" aria-label="Mapping editor view"><button type="button" aria-pressed={mappingView === 'guided'} onClick={() => setMappingView('guided')}>Guided editing</button><button type="button" aria-pressed={mappingView === 'bulk'} onClick={() => setMappingView('bulk')}>Bulk editing</button></nav>
        <div hidden={mappingView !== 'guided'}><details ref={manualToolsRef} className="migration-review-tools" open><summary>Ownership, zones and selected mapping</summary>
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
           proposals={proposalRows}
          busy={busy || !reviewCurrent || settingsDirty}
          run={run}
          applyRuleSuggestion={applyRuleSuggestion}
          applyGroupAction={applyGroupAction}
          updateGroup={updateGroup}
        />
        </details></div>
        <div hidden={mappingView !== 'bulk'}><details open ref={bulkMappingsRef} className="migration-review-tools"><summary>Bulk edit interfaces</summary><MigrationInterfaceMappings review={review} drafts={drafts} setDraft={(key, value) => setDrafts((current) => ({ ...current, [key]: value }))}
          proposals={deterministicDraft?.decisions}
          selectedKeys={selectedKeys} setSelectedKeys={(keys) => { setSelectedKeys(keys); setBulkPreview([]) }} busy={busy || !reviewCurrent || settingsDirty} reviewSelected={reviewProposals}
          openDetails={(key) => { const group = reviewGroups.find((item) => item.decision_keys.includes(key)); if (group) { setMappingView('guided'); if (manualToolsRef.current) manualToolsRef.current.open = true; if (bulkMappingsRef.current) bulkMappingsRef.current.open = true; setActiveQueue(group.queue); setSelectedGroupKey(group.decision_keys[0]); setSearch(''); setVdomFilter('all'); manualToolsRef.current?.scrollIntoView({ block: 'start' }); focusMappingInput(key) } }} /></details></div>
        </details>}
        {workflowMode === 'destination' && <div className="action-row"><Button disabled={busy || !deterministicDraft || !!changedMappings.length} onClick={() => setReviewSection('configuration')}>Review supported changes</Button></div>}
        </section>
        <details className="migration-review-tools migration-exceptions" hidden={workflowMode === 'offline'
          ? (stage ? stage !== 'review' : reviewSection !== 'configuration')
          : (stage ? stage !== 'place' : reviewSection !== 'mappings')} onToggle={(event) => setExceptionsOpen(event.currentTarget.open)}>
         <summary>{workflowMode === 'offline' ? 'Conversion issues and manual work' : 'Unresolved choices and manual work'} ({deterministicDraft?.task_summary?.manual_items ?? 0} configuration items)</summary>
        {exceptionsOpen && <section aria-label="Migration exceptions">
          <h3>Root-cause exceptions and manual work</h3>
          {deterministicDraft?.task_summary && <p>{deterministicDraft.task_summary.prerequisites} dependent task groups · {deterministicDraft.task_summary.conflicts} conflicts · {deterministicDraft.task_summary.manual_issues} manual issue groups. Several issues can affect the same configuration item.</p>}
          <p>Tasks retain source scope. Affected counts are deduplicated within each task and may overlap between tasks.</p>
          {(deterministicDraft?.issues ?? []).slice((issuePage - 1) * 30, issuePage * 30).map((issue) => <article className="review-work-card" key={issue.id}>
            <h3>{({ CHOICE: 'Needs your choice', PREREQUISITE: 'Blocked by a prerequisite', CONFLICT: 'Conflict', MANUAL: 'Requires manual implementation' })[issue.category]} · {issue.source_vdom} / {issue.source_name}</h3>
            <p>{issue.explanation}</p><p>{issue.affected_keys.length} affected items</p>
            {!!issue.explanations?.length && <details><summary>Technical reasons ({issue.explanations.length})</summary><ul className="migration-technical-reasons">{issue.explanations.map((reason, index) => <li key={index}>{reason}</li>)}</ul></details>}
            <details><summary>Affected source identities</summary><ul>{issue.affected_sources.slice(0, 30).map((item, index) => <li key={index}>{item.source_vdom} / {item.source_kind} / {item.source_name}</li>)}</ul>{issue.affected_sources.length > 30 && <p>{issue.affected_sources.length - 30} more affected identities; inspect placement and configuration lists.</p>}</details>
            {issue.category === 'MANUAL' && <p>Requires manual implementation. Excluded from generated commands.</p>}
            {issue.action && <div className="action-row"><Button className="secondary-button" disabled={busy || !reviewCurrent} onClick={() => { setReviewSection('mappings'); setSetupFocus({ key: issue.action!.decision_key, request: Date.now() }); setMappingView('guided'); const group = reviewGroups.find((group) => group.decision_keys.includes(issue.action!.decision_key)); if (group) { setActiveQueue(group.queue); setSelectedGroupKey(group.decision_keys[0]); setSearch(''); setVdomFilter('all') }; focusMappingInput(issue.action!.decision_key) }}>{workflowMode === 'offline' ? 'Review target setup' : 'Resolve placement'}</Button></div>}
          </article>)}
          {(deterministicDraft?.issues?.length ?? 0) > 30 && <div className="report-pager"><button type="button" disabled={issuePage <= 1} onClick={() => setIssuePage((page) => page - 1)}>Previous tasks</button><span>Page {issuePage}</span><button type="button" disabled={issuePage * 30 >= (deterministicDraft?.issues?.length ?? 0)} onClick={() => setIssuePage((page) => page + 1)}>Next tasks</button></div>}
        </section>}
        </details>
        {workflowMode === 'destination' && <details className="migration-review-tools" hidden={stage ? stage !== 'place' : reviewSection !== 'mappings'}><summary>Advanced tools and mapping files</summary>
        <button type="button" disabled={busy || !!changedMappings.length} onClick={() => void run(async () => { await loadReview(currentDocument()) }, 'Design revalidated.')}>Revalidate design</button>
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
          busy={busy || !reviewCurrent || settingsDirty}
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
        </details>}
        {!!bulkPreview.length && <section className="review-work-card" aria-label="Bulk proposal review">
          <h3>Review {bulkPreview.length} proposed mappings</h3>
          <p>Only these nonempty values will be submitted. Related configuration and dependent mappings will be re-evaluated. Approval is separate.</p>
          <p>{stagedDependents.filter((row) => row.decision_key).length} directly dependent mapping fields · {stagedDependents.filter((row) => !row.decision_key).length} directly dependent configuration items in the current draft.</p>
          {!!stagedDependents.length && <details><summary>Review direct dependents</summary><ul>{stagedDependents.slice(0, 30).map((row) => <li key={draftRowKey(row)}>{row.source_vdom} / {row.source_name} · {row.target_field || row.family} · {row.status}</li>)}</ul>{stagedDependents.length > 30 && <p>{stagedDependents.length - 30} more direct dependents. Review the full configuration after validation.</p>}</details>}
          <ul>{bulkPreview.slice((bulkPage - 1) * 50, bulkPage * 50).map((item) => <li key={item.key}>{item.scope} → <strong>{item.value}</strong></li>)}</ul>
          <div className="report-pager"><button type="button" disabled={bulkPage <= 1} onClick={() => setBulkPage((page) => page - 1)}>Previous values</button><span>Page {bulkPage} of {Math.ceil(bulkPreview.length / 50)}</span><button type="button" disabled={bulkPage * 50 >= bulkPreview.length} onClick={() => setBulkPage((page) => page + 1)}>Next values</button></div>
          <button type="button" className="primary-button" disabled={busy} onClick={() => run(validateStagedChanges)}>Validate staged changes</button>
          <button type="button" className="secondary-button" onClick={() => setBulkPreview([])}>Cancel proposal review</button>
        </section>}
      </>}


    </section>
  )
}
