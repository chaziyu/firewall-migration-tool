import type { Decision, ReviewGroup } from './reviewTypes'

export const reviewQueueNames = ['NEEDS_INPUT', 'CHOOSE_CANDIDATE', 'READY_TO_CONFIRM', 'CONFLICT', 'COMPLETE'] as const

export type BulkPreviewRow = { key: string; scope: string; value: string }

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
) {
  return decisions.filter((item) => {
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
