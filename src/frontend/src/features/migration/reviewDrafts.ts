import type { Candidate, Decision } from './reviewTypes'
import type { DraftRow } from './types'

export const draftRowKey = (row: DraftRow) => row.decision_key || row.group_key!

export function draftDependencies(rows: DraftRow[] | Map<string, DraftRow>, keys: string[], approvedItems: string[] = []): string[] {
  const byKey = rows instanceof Map ? rows : new Map(rows.map((row) => [draftRowKey(row), row]))
  const approved = new Set(approvedItems)
  const result = new Set(keys)
  for (const key of result) for (const parent of byKey.get(key)?.dependencies || []) {
    const row = byKey.get(parent)
    if (row && !row.approved && !approved.has(row.item_key || row.decision_key || '')) result.add(parent)
  }
  return [...result]
}

export function portExceptionGroups(rows: DraftRow[]): Map<string, DraftRow[]> {
  const ports = rows.filter((row) => row.target_field === 'target_interface' && ['NEEDS_INPUT', 'CONFLICT'].includes(row.status))
  const byKey = new Map(rows.map((row) => [draftRowKey(row), row]))
  const portKeys = new Set(ports.map(draftRowKey))
  const dependents = new Map<string, string[]>()
  const order = new Map(rows.map((row, index) => [draftRowKey(row), index]))
  for (const row of rows) for (const parent of row.dependencies) {
    const children = dependents.get(parent) ?? []
    children.push(draftRowKey(row))
    dependents.set(parent, children)
  }
  const groups = new Map<string, DraftRow[]>()
  for (const port of ports) {
    if (draftDependencies(byKey, port.dependencies).some((key) => portKeys.has(key))) continue
    const key = draftRowKey(port)
    const visited = new Set([key])
    const expanded = new Set([key])
    const queue = [key]
    const affected: DraftRow[] = []
    for (const parent of queue) for (const child of dependents.get(parent) ?? []) {
      const row = byKey.get(child)!
      if (!visited.has(child)) {
        visited.add(child)
        if (row !== port && row.status === 'NEEDS_INPUT') affected.push(row)
      }
      // Approved keys can be direct prerequisites, but are excluded when discovered transitively.
      if (!byKey.get(parent)?.approved && !expanded.has(child)) {
        expanded.add(child)
        queue.push(child)
      }
    }
    affected.sort((a, b) => order.get(draftRowKey(a))! - order.get(draftRowKey(b))!)
    groups.set(draftRowKey(port), affected)
  }
  return groups
}

export function candidateLabel(candidate: Candidate, targetField = 'target_interface') {
  if (candidate.available === false) return `Already assigned to ${candidate.assigned_to?.map((owner) => `${owner.source_vdom} / ${owner.source_name}`).join(', ')}`
  if (candidate.contested) return 'Competing suggestion'
  if (candidate.class === 'STRONG') return 'Strong match'
  if (candidate.supporting_evidence?.some((fact) => !['INTERFACE_FAMILY_MATCH', 'physical interface family'].includes(fact))) return 'Possible match'
  const field = ({ target_interface: 'interface', target_zone: 'zone', target_virtual_router: 'virtual router', vsys: 'VSYS' } as Record<string, string>)[targetField] ?? 'target'
  return `Available ${field} — no match evidence`
}

export function orderReviewGroups<T extends { decision_keys: string[]; source_vdom: string; source_kind: string; source_name: string; queue: string; affected_count: number }>(
  groups: T[], rows: DraftRow[], context: Record<string, Record<string, unknown>>,
) {
  const rowByKey = new Map(rows.map((row) => [draftRowKey(row), row]))
  const groupByKey = new Map(groups.flatMap((group) => group.decision_keys.map((key) => [key, group] as const)))
  const prerequisites = new Map(groups.map((group) => [group, new Set<T>()]))
  for (const group of groups) for (const key of group.decision_keys) {
    for (const dependency of rowByKey.get(key)?.dependencies ?? []) {
      const row = rowByKey.get(dependency)
      const owner = groupByKey.get(dependency)
      if (owner && owner !== group && !row?.approved && row?.status !== 'READY') prerequisites.get(group)!.add(owner)
    }
  }
  const originalOrder = new Map(groups.map((group, index) => [group, index]))
  const rank = (group: T) => {
    const facts = group.decision_keys.map((key) => context[key] ?? {})
    const parent = facts.some((item) => item.source_parent)
    const physical = facts.some((item) => ['physical', 'ethernet', 'aggregate'].includes(String(item.source_type)))
    const unavailable = group.decision_keys.some((key) => !rowByKey.has(key) || (rowByKey.get(key)?.dependencies ?? []).some((dependency) => !rowByKey.has(dependency)))
    if (unavailable) return [1, originalOrder.get(group)!]
    return [group.queue === 'COMPLETE' ? 3 : reviewGroupActionable(group, rowByKey) ? 0 : 2,
      group.source_kind === 'vdom' ? 0 : parent ? 3 : physical ? 1 : group.source_kind === 'zone' ? 2 : 2,
      -Number(group.affected_count ?? 0), group.source_vdom, group.source_name]
  }
  const ranks = new Map(groups.map((group) => [group, rank(group)]))
  const compare = (a: T, b: T) => {
    const x = ranks.get(a)!, y = ranks.get(b)!
    for (let i = 0; i < x.length; i++) {
      const result = typeof x[i] === 'number' ? Number(x[i]) - Number(y[i]) : String(x[i]).localeCompare(String(y[i]))
      if (result) return result
    }
    return 0
  }
  const remaining = new Set(groups)
  const ordered: T[] = []
  while (remaining.size) {
    const ready = [...remaining].filter((group) => [...prerequisites.get(group)!].every((item) => !remaining.has(item))).sort(compare)
    const next = ready[0] ?? [...remaining].sort(compare)[0]
    ordered.push(next)
    remaining.delete(next)
  }
  return ordered
}

export function reviewGroupActionable(group: { decision_keys: string[]; queue: string }, rows: DraftRow[] | Map<string, DraftRow>) {
  if (group.queue === 'COMPLETE') return false
  const byKey = rows instanceof Map ? rows : new Map(rows.map((row) => [draftRowKey(row), row]))
  const taskKeys = new Set(group.decision_keys)
  const taskRows = group.decision_keys.map((key) => byKey.get(key))
  if (taskRows.some((row) => !row)) return false
  if (taskRows.some((row) => (row!.dependencies ?? []).some((key) => {
    if (taskKeys.has(key)) return false
    const prerequisite = byKey.get(key)
    return !prerequisite || (prerequisite.status !== 'READY' && !prerequisite.approved)
  }))) return false
  return ['READY_TO_CONFIRM', 'CHOOSE_CANDIDATE'].includes(group.queue)
    || taskRows.some((row) => row!.status === 'NEEDS_INPUT' || row!.status === 'CONFLICT')
}

export function reconcileReviewDrafts(current: Record<string, string>, previous: Decision[], next: Decision[], contextChanged: boolean, candidates: Record<string, Candidate[]> = {}, proposals: Record<string, string | null> = {}, previousProposals: Record<string, string | null> = {}) {
  const previousByKey = new Map(previous.map((item) => [item.key, item]))
  return Object.fromEntries(next.map((item) => {
    const old = previousByKey.get(item.key)
    const unchanged = old && ['value', 'suggested_value', 'review_state', 'mode', 'evidence_source', 'evidence_type',
      'evidence_value', 'target_object', 'evidence_target_digest', 'evidence_target_device'].every((field) => old[field] === item[field])
    const options = candidates[item.key] ?? []
    const candidate = item.source_kind === 'interface' && item.target_field === 'target_interface'
      && options.length === 1 && options[0].available !== false && !options[0].contested ? options[0].value : ''
    const proposalChanged = proposals[item.key] !== previousProposals[item.key]
    return [item.key, !contextChanged && !proposalChanged && unchanged && current[item.key] !== undefined ? current[item.key] : proposals[item.key] ?? item.value ?? item.suggested_value ?? candidate]
  }))
}

export function decisionLabel(decision: Decision, candidates: Candidate[] = [], conflict = false) {
  if (conflict) return 'Conflict'
  if (decision.review_state === 'CONFIRMED') return 'Confirmed'
  if (decision.mode === 'UNSUPPORTED') return 'Unsupported'
  if (decision.suggested_value) return decision.evidence_source === 'DERIVED' || decision.evidence_type === 'REVIEW_DERIVED_SUGGESTION' ? 'Derived suggestion' : 'Suggested'
  return candidates.some((item) => item.available !== false && !item.contested) ? 'Candidate available' : 'Needs input'
}

export function confirmationEvidenceType(decision: Decision, value: string) {
  return value === decision.suggested_value && ['TARGET', 'DERIVED', 'SOURCE'].includes(decision.evidence_source ?? '')
    ? `ENGINEER_${decision.evidence_source}_SUGGESTION` : 'MANUAL'
}

export function interfaceMappingRows(decisions: Decision[], drafts: Record<string, string>, candidates: Record<string, Candidate[]>) {
  const rows = decisions.filter((item) => item.source_kind === 'interface' && item.target_field === 'target_interface')
    .map((decision) => {
      const value = (drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? '').trim()
      const matching = (candidates[decision.key] ?? []).filter((item) => item.value === value)
      return { decision, value, candidate: matching[0], ambiguous: matching.length > 1 }
    })
  const assignments = new Map<string, typeof rows>()
  for (const row of rows) {
    if (row.value) assignments.set(row.value, [...(assignments.get(row.value) ?? []), row])
  }
  return rows.map((row) => {
    const owners = (assignments.get(row.value) ?? []).filter((other) => other.decision.key !== row.decision.key)
    const conflict = owners.length ? `Also mapped to ${owners.map((other) => `${other.decision.source_vdom} / ${other.decision.source_name}`).join(', ')}`
      : row.candidate?.available === false ? `Already assigned to ${row.candidate.assigned_to?.map((owner) => `${owner.source_vdom} / ${owner.source_name}`).join(', ')}`
      : row.ambiguous ? 'Ambiguous target scope' : row.candidate?.contested ? 'Competing suggestions; choose manually' : ''
    const ready = Boolean(row.value && !conflict && row.candidate?.class === 'STRONG'
      && row.decision.review_state !== 'CONFIRMED' && row.decision.mode !== 'UNSUPPORTED')
    return { ...row, conflict, ready }
  })
}

export function orderInterfaceMappings<T extends { decision: Decision }>(rows: T[], context: Record<string, Record<string, unknown>>, proposals: DraftRow[] = []) {
  const byKey = new Map(proposals.map((row) => [draftRowKey(row), row]))
  const rank = (row: T) => {
    const facts = context[row.decision.key] ?? {}
    const parents = byKey.get(row.decision.key)?.dependencies ?? []
    const blocked = parents.some((key) => byKey.has(key) && byKey.get(key)?.status !== 'READY' && !byKey.get(key)?.approved)
    return [Number(blocked), facts.source_parent ? 1 : ['physical', 'ethernet', 'aggregate'].includes(String(facts.source_type)) ? 0 : 2]
  }
  return [...rows].sort((a, b) => {
    const ar = rank(a), br = rank(b)
    return ar[0] - br[0] || ar[1] - br[1] || Number(b.decision.affected_count ?? 0) - Number(a.decision.affected_count ?? 0)
      || `${a.decision.source_vdom}/${a.decision.source_name}`.localeCompare(`${b.decision.source_vdom}/${b.decision.source_name}`)
  })
}
