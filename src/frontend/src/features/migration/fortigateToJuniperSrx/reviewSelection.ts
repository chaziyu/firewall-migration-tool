import type { SrxPlanItem } from './types'

export function isReviewable(item: SrxPlanItem): boolean {
  return ['CREATE', 'REUSE'].includes(item.render_disposition) && item.blockers.length === 0
}

export function expandSelection(items: SrxPlanItem[], selected: string[]): string[] {
  const byKey = new Map(items.map((item) => [item.key, item]))
  const groups = new Map<string, string[]>()
  for (const item of items) {
    if (item.approval_group) groups.set(item.approval_group, [...(groups.get(item.approval_group) ?? []), item.key])
  }
  const expanded = new Set<string>()
  const visiting = new Set<string>()
  const expandedGroups = new Set<string>()
  const add = (keys: string[]) => {
    const pending = keys.map((key) => ({ key, complete: false }))
    while (pending.length) {
      const { key, complete } = pending.pop()!
      if (complete) { visiting.delete(key); expanded.add(key); continue }
      if (visiting.has(key)) throw new Error('A dependency cycle blocks this selection')
      if (expanded.has(key)) continue
      const item = byKey.get(key)
      if (!item || !isReviewable(item)) throw new Error('A selected item or required group is blocked')
      visiting.add(key)
      pending.push({ key, complete: true }, ...item.dependencies.map((key) => ({ key, complete: false })))
    }
  }
  add(selected)
  for (const key of expanded) {
    const group = byKey.get(key)?.approval_group
    if (group && !expandedGroups.has(group)) {
      expandedGroups.add(group)
      add(groups.get(group) ?? [])
    }
  }
  return items.filter((item) => expanded.has(item.key)).map((item) => item.key)
}
