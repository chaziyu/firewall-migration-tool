import type { Candidate, Decision, DecisionDocument, ReviewGroup } from './reviewTypes'
import type { DraftRow } from './types'

export const taskCategories = ['Needs decision', 'Ready for review', 'Blocked', 'Approved', 'Manual work'] as const

export function approvedDraftKeys(document: DecisionDocument) {
  const approval = document.design_approval as { configuration?: Record<string, unknown>; decisions?: Record<string, { review_state?: string; approved_operation?: string | null }> } | undefined
  return [...Object.keys(approval?.configuration ?? {}), ...Object.entries(approval?.decisions ?? {})
    .filter(([, row]) => row.review_state === 'CONFIRMED' && row.approved_operation).map(([key]) => key)]
}

export function taskCategory(row: DraftRow, byKey: Map<string, DraftRow>, approvedItems?: Set<string>): typeof taskCategories[number] {
  if (row.approved || approvedItems?.has(row.item_key || row.decision_key || '')) return 'Approved'
  if (row.status === 'UNSUPPORTED') return 'Manual work'
  if ((row.dependencies ?? []).some((key) => {
    const parent = byKey.get(key)
    return !parent || (parent.status !== 'READY' && !parent.approved && !approvedItems?.has(parent.item_key || parent.decision_key || ''))
  })) return 'Blocked'
  return row.status === 'READY' ? 'Ready for review' : 'Needs decision'
}

export function mappingReviewGroups(groups: ReviewGroup[], rows: DraftRow[], offline: boolean, approvedItems: string[] = []) {
  if (!offline) return groups
  const byKey = new Map(rows.map((row) => [row.decision_key || row.group_key!, row]))
  const approved = new Set(approvedItems)
  return groups.map((group) => {
    const proposals = group.decision_keys.map((key) => byKey.get(key))
    const categories = proposals.map((row) => row ? taskCategory(row, byKey, approved) : 'Needs decision')
    const queue = proposals.some((row) => row?.status === 'CONFLICT') ? 'CONFLICT'
      : categories.length > 0 && categories.every((category) => category === 'Approved' || category === 'Manual work') ? 'COMPLETE'
      : !categories.length || categories.some((category) => category === 'Needs decision' || category === 'Blocked') ? 'NEEDS_INPUT'
      : 'READY_TO_CONFIRM'
    return { ...group, queue }
  })
}

export function orderedCandidates(candidates: Candidate[]) {
  const rank = (candidate: Candidate) => candidate.available === false || candidate.contested ? 3
    : candidate.class === 'STRONG' || candidate.strong_evidence?.length ? 0
    : candidate.supporting_evidence?.some((fact) => !['INTERFACE_FAMILY_MATCH', 'physical interface family'].includes(fact)) ? 1 : 2
  return [...candidates].sort((a, b) => rank(a) - rank(b))
}

export function reviewSourceSummary(group: ReviewGroup) {
  if (group.source_kind === 'vdom') return 'Choose target VSYS and virtual-router ownership for this VDOM.'
  if (group.source_kind === 'zone') return `Source zone: ${group.source_name}. Review its explicit member evidence below.`
  return [['IP address', group.source_evidence.source_ip ?? group.source_evidence.source_ip_address],
    ['Type', group.source_evidence.source_type], ['Parent', group.source_evidence.source_parent], ['VLAN', group.source_evidence.source_vlan]]
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([label, value]) => `${label}: ${String(value)}`).join(' · ') || 'No explicit interface details in available source evidence.'
}

export function draftStatusCounts(rows: DraftRow[]) {
  return rows.reduce((counts, row) => { counts[row.status] = (counts[row.status] ?? 0) + 1; return counts }, {} as Record<string, number>)
}

export function draftReviewRows(rows: DraftRow[], filter: string, family: string, search: string, grouped: Set<string>, approvedItems: Set<string> = new Set()) {
  const query = search.trim().toLowerCase()
  const byKey = new Map(rows.map((row) => [row.decision_key || row.group_key!, row]))
  return rows.filter((row) => (filter === 'all' || (filter === 'ACTIONABLE'
    ? ['NEEDS_INPUT', 'CONFLICT'].includes(row.status) && !grouped.has(row.decision_key || row.group_key!)
    : filter === 'APPROVED' ? taskCategory(row, byKey, approvedItems) === 'Approved'
    : filter === 'BLOCKED' ? taskCategory(row, byKey, approvedItems) === 'Blocked'
    : filter === 'READY' ? taskCategory(row, byKey, approvedItems) === 'Ready for review'
    : row.status === filter)) && (family === 'all' || (row.family || row.source_kind) === family)
    && `${row.source_vdom} ${row.source_name} ${row.target_name || row.proposed_value || ''}`.toLowerCase().includes(query))
}

export function planFamilySummary(items: Array<Record<string, unknown>>) {
  const summary: Record<string, { included: number; blocked: number }> = {}
  for (const item of items) {
    const family = String(item.source_object_type || item.source_kind || 'Other')
    const row = summary[family] ??= { included: 0, blocked: 0 }
    if (item.render_disposition === 'BLOCK') row.blocked++
    else row.included++
  }
  return summary
}

export function groupPlanBlockers(rows: Array<Record<string, unknown>>) {
  const groups = new Map<string, Record<string, unknown>>()
  for (const row of rows) {
    const keys = [...new Set([row.decision_key, ...(Array.isArray(row.decision_keys) ? row.decision_keys : [])].filter((key): key is string => typeof key === 'string' && !!key))].sort()
    const key = JSON.stringify([row.code, keys, row.source_vdom, row.category ?? '', row.next_action ?? ''])
    const group = groups.get(key)
    if (group) {
      group.count = Number(group.count) + 1
      ;(group.affected as Array<Record<string, unknown>>).push(row)
    } else groups.set(key, { ...row, decision_keys: keys, count: 1, affected: [row] })
  }
  return [...groups.values()]
}

export const reviewQueueNames = ['NEEDS_INPUT', 'CHOOSE_CANDIDATE', 'READY_TO_CONFIRM', 'CONFLICT', 'COMPLETE'] as const

type BulkPreviewRow = { key: string; scope: string; value: string }

export function reviewSuggestions(decisions: Decision[]) {
  return decisions.filter((item) => item.mode === 'SUGGESTED' && item.review_state !== 'CONFIRMED' && item.suggested_value)
}

export function reviewVdoms(groups: ReviewGroup[]) {
  return [...new Set(groups.map((group) => group.source_vdom))].sort()
}

export function visibleReviewGroups(
  groups: ReviewGroup[],
  activeQueue: string,
  vdomFilter: string,
  search: string,
) {
  const query = search.toLowerCase()
  return groups.filter((group) =>
    group.queue === activeQueue
    && (vdomFilter === 'all' || group.source_vdom === vdomFilter)
    && `${group.source_vdom} ${group.source_kind} ${group.source_name}`.toLowerCase().includes(query))
}

export function visibleReviewDecisions(
  decisions: Decision[],
  decisionFilter: string,
  evidenceFilter: string,
  vdomFilter: string,
  pendingOnly: boolean,
  reviewGroups: ReviewGroup[] = [],
) {
  return decisions.filter((item) => {
    if (decisionFilter === 'zones' && item.source_kind !== 'zone') return false
    if (decisionFilter === 'interfaces' && item.source_kind !== 'interface') return false
    if (decisionFilter === 'route-nat' && !/route|nat/i.test(`${item.source_kind} ${item.target_field}`)) return false
    if (vdomFilter !== 'all' && item.source_vdom !== vdomFilter) return false
    if (evidenceFilter === 'target' && item.evidence_source !== 'TARGET') return false
    if (evidenceFilter === 'source' && item.evidence_source === 'TARGET') return false
    if (evidenceFilter === 'conflict' && !reviewGroups.some((group) => group.conflicts?.some((finding) => finding.decision_key === item.key))) return false
    if (evidenceFilter === 'required' && item.mode !== 'REQUIRED') return false
    if (evidenceFilter === 'confirmed' && item.review_state !== 'CONFIRMED') return false
    return !pendingOnly || item.review_state !== 'CONFIRMED'
  })
}

export function buildBulkPreview(
  decisions: Decision[],
  keys: string[],
  valueFor: (decision: Decision) => string,
): BulkPreviewRow[] {
  const selected = new Set(keys)
  return decisions
    .filter((item) => selected.has(item.key) && item.mode !== 'UNSUPPORTED' && valueFor(item).trim())
    .map((item) => ({
      key: item.key,
      scope: `${item.source_vdom} · ${item.source_kind} · ${item.source_name} · ${item.target_field}`,
      value: valueFor(item).trim(),
    }))
}

export function mappingIdentityLabel(key: string): string {
  try {
    const identity: unknown = JSON.parse(key)
    if (Array.isArray(identity) && identity.length === 4 && identity.every((value) => typeof value === 'string')) {
      return `${identity[0]} / ${identity[2]} · ${identity[3].replaceAll('_', ' ')}`
    }
  } catch { /* Legacy keys remain available in technical details. */ }
  return 'related placement'
}
