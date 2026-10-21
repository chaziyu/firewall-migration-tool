import type { CPPlanRow } from './types'

export function approvalSelection(rows: CPPlanRow[], selected: string[]) {
  const byKey = new Map(rows.map((row) => [row.key, row]))
  const chosen = new Set<string>()
  const visiting = new Set<string>()
  const pending = selected.map((key): [string, boolean] => [key, false]).reverse()
  while (pending.length) {
    const [key, exit] = pending.pop()!
    if (exit) { visiting.delete(key); chosen.add(key); continue }
    if (chosen.has(key)) continue
    const row = byKey.get(key)
    if (!row || row.blockers.length || !['CREATE', 'REUSE'].includes(row.render_disposition)) throw new Error('Selection has blocked prerequisites')
    if (visiting.has(key)) throw new Error('Selection has a dependency cycle')
    visiting.add(key)
    pending.push([key, true], ...row.dependencies.map((dependency): [string, boolean] => [dependency, false]).reverse())
  }
  return rows.filter((row) => chosen.has(row.key)).map((row) => row.key)
}
