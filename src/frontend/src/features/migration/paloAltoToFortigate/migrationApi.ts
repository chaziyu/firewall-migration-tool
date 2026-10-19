import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { FortiGateArtifact, FortiGateDraft, FortiGateOptions, FortiGateReview } from './types'

const prefix = '/api/migration/palo_alto_to_fortigate'
export const prepare = (source: SourceEvidence, options: Partial<FortiGateOptions>, targetSource?: SourceEvidence | null) =>
  postJson<FortiGateReview>(`${prefix}/design/prepare`, { source, options, ...(targetSource ? { target_source: targetSource } : {}) })
export const approve = (source: SourceEvidence, options: FortiGateOptions, targetSource: SourceEvidence | null, draft: FortiGateDraft, selected: string[]) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, ...(targetSource ? { target_source: targetSource } : {}), draft, selected_items: selected })
export const build = (source: SourceEvidence, options: FortiGateOptions, targetSource: SourceEvidence | null, approval: Record<string, unknown>) =>
  postJson<{ artifact: FortiGateArtifact }>(`${prefix}/build`, { source, options, ...(targetSource ? { target_source: targetSource } : {}), approval })
export const download = (source: SourceEvidence, artifact: FortiGateArtifact, kind: 'commands' | 'bundle') =>
  postBlob(`${prefix}/${kind}`, { source, artifact })
export const exportDecisions = (source: SourceEvidence, options: FortiGateOptions, targetSource?: SourceEvidence | null) =>
  postJson<{ document: Record<string, unknown> }>(`${prefix}/decisions/export`, { source, options, ...(targetSource ? { target_source: targetSource } : {}) })
export const importDecisions = (source: SourceEvidence, document: unknown) =>
  postJson<{ options: FortiGateOptions }>(`${prefix}/decisions/import`, { source, document })

export function approvalSelection(rows: FortiGateDraft['configuration'], selected: string[]) {
  const byKey = new Map(rows.map((row) => [row.key, row]))
  const result = new Set<string>()
  const visiting = new Set<string>()
  const pending = selected.map((key): [string, boolean] => [key, false]).reverse()
  while (pending.length) {
    const [key, exit] = pending.pop()!
    if (exit) { visiting.delete(key); result.add(key); continue }
    if (visiting.has(key)) throw new Error('Dependency cycle in review')
    if (result.has(key)) continue
    const row = byKey.get(key)
    if (!row || row.render_disposition === 'BLOCK' || row.blocking_reasons.length) throw new Error('Selected configuration has blocked prerequisites')
    visiting.add(key)
    pending.push([key, true], ...row.dependencies.map((parent): [string, boolean] => [parent, false]).reverse())
  }
  return [...result]
}
