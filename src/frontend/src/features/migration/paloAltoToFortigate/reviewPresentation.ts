import type { ConfigurationRow, EffectiveValue, FortiGateReview, Requirement } from './types'

export const isReady = (row: ConfigurationRow) => row.render_disposition !== 'BLOCK' && !row.blocking_reasons.length

export function orderPlacementRequirements(rows: Requirement[], configuration: ConfigurationRow[]) {
  const order = new Map(configuration.filter((row) => row.family === 'interface').map((row, index) => [row.source_name, index]))
  return [...rows].sort((a, b) => (order.get(a.key.slice('interfaces:'.length)) ?? Infinity)
    - (order.get(b.key.slice('interfaces:'.length)) ?? Infinity) || a.key.localeCompare(b.key, undefined, { numeric: true }))
}

export type ReviewIssueGroup = {
  key: string; category: string; source_scope: string; explanation: string
  reasons: string[]
  affected: Array<{ key: string; source_scope: string; source_name: string }>
}

export function groupReviewIssues(review: FortiGateReview): ReviewIssueGroup[] {
  const findings = new Set(review.draft.findings)
  const groups = new Map<string, ReviewIssueGroup>()
  const covered = new Set<string>()
  const add = (category: string, scope: string, explanation: string, key: string, name: string) => {
    if (findings.has(explanation)) return
    const summary = category === 'PREREQUISITE' ? 'Configuration depends on blocked prerequisites. Resolve shared blockers and direct choices first.' : explanation
    const groupKey = JSON.stringify([category, scope, summary])
    let group = groups.get(groupKey)
    if (!group) { group = { key: groupKey, category, source_scope: scope, explanation: summary, reasons: [], affected: [] }; groups.set(groupKey, group) }
    if (!group.reasons.includes(explanation)) group.reasons.push(explanation)
    if (!group.affected.some((item) => item.key === key)) group.affected.push({ key, source_scope: scope, source_name: name })
    covered.add(JSON.stringify([key, explanation]))
  }
  for (const issue of review.issues ?? []) {
    const matches = issue.item_key ? [issue.item_key] : review.draft.configuration
      .filter((row) => row.source_scope === issue.source_scope && row.source_name === issue.source_name).map((row) => row.key)
    for (const key of matches.length ? matches : [issue.id]) add(issue.category, issue.source_scope, issue.explanation, key, issue.source_name)
  }
  // Saved workspaces may lack issue links; keep every reported blocker visible.
  for (const row of review.draft.configuration) for (const reason of row.blocking_reasons) {
    if (covered.has(JSON.stringify([row.key, reason]))) continue
    const category = row.family === 'manual' ? 'MANUAL'
      : row.dependencies.some((key) => reason === `Blocked dependency: ${key}`) ? 'PREREQUISITE' : 'UNCLASSIFIED'
    add(category, row.source_scope, reason, row.key, row.source_name)
  }
  return [...groups.values()].sort((a, b) => Number(a.category === 'PREREQUISITE') - Number(b.category === 'PREREQUISITE'))
}

export function groupEffectiveValues(rows: EffectiveValue[]) {
  const groups = new Map<string, { key: string; field: string; value: string; version: string; reference: string; count: number }>()
  for (const row of rows) {
    const key = JSON.stringify([row.field, row.value, row.version, row.reference])
    const group = groups.get(key)
    if (group) group.count++
    else groups.set(key, { key, field: row.field, value: row.value, version: row.version, reference: row.reference, count: 1 })
  }
  return [...groups.values()]
}
