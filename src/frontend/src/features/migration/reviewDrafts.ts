import type { Candidate, Decision } from './reviewTypes'

export function candidateLabel(candidate: Candidate) {
  if (candidate.available === false) return `Already assigned to ${candidate.assigned_to?.map((owner) => `${owner.source_vdom} / ${owner.source_name}`).join(', ')}`
  if (candidate.contested) return 'Competing suggestion'
  if (candidate.class === 'STRONG') return 'Strong match'
  return candidate.supporting_evidence?.some((fact) => !['INTERFACE_FAMILY_MATCH', 'physical interface family'].includes(fact)) ? 'Possible match' : 'Available interface'
}

export function reconcileReviewDrafts(current: Record<string, string>, previous: Decision[], next: Decision[], contextChanged: boolean) {
  const previousByKey = new Map(previous.map((item) => [item.key, item]))
  return Object.fromEntries(next.map((item) => {
    const unchanged = JSON.stringify(previousByKey.get(item.key)) === JSON.stringify(item)
    return [item.key, !contextChanged && unchanged && current[item.key] !== undefined ? current[item.key] : item.value ?? item.suggested_value ?? '']
  }))
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
