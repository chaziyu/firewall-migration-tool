import type { ASAPlanRow } from './types'

export function approvalSelection(rows: ASAPlanRow[], selected: string[]) {
  const byKey = new Map(rows.map((row) => [row.key, row]))
  const chosen = new Set<string>()
  const pending = [...selected]
  while (pending.length) {
    const key = pending.pop()!
    if (chosen.has(key)) continue
    const row = byKey.get(key)
    if (!row || row.blockers.length) throw new Error('Selected configuration has blocked prerequisites')
    chosen.add(key)
    pending.push(...row.dependencies)
    if (row.approval_group) pending.push(...rows.filter((other) => other.approval_group === row.approval_group).map((other) => other.key))
  }
  return rows.filter((row) => chosen.has(row.key)).map((row) => row.key)
}
