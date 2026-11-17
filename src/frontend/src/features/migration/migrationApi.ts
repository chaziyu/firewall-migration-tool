import type { SourceEvidence } from '../../storage/workspaceTypes'
import { postBlob, postJson } from '../../api/client'

export type Decision = {
  key: string
  source_vdom: string
  source_kind: string
  source_name: string
  target_field: string
  suggested_value: string | null
  value: string | null
  mode: string
  review_state: string
  reason: string
  affected_count: number
}

export type DecisionDocument = Record<string, unknown> & { decisions: Decision[] }
export type PlanArtifact = {
  artifact_id: string
  plan_status: string
  commands: string[]
  command_count: number
  artifact: { commands: string[]; command_count: number; command_sha256: string; signature: string; report: PlanArtifact['report'] & { review: { recommendations: PlanArtifact['recommendations']; support_guidance: PlanArtifact['support_guidance'] } }; decision_document: DecisionDocument; [key: string]: unknown }
  counts: Record<string, number>
  render_summary: Record<string, number>
  blocking_reasons: Array<Record<string, unknown>>
  recommendations: Array<Record<string, unknown>>
  support_guidance?: Array<Record<string, unknown>>
  report: { items?: Array<Record<string, unknown>>; export_counts?: Record<string, number>; command_sha256?: string; workflow_mode?: string; destination_verified?: boolean; deployment_eligibility?: { eligible: boolean; reason: string | null }
    coverage?: { complete: boolean; unplanned_count: number; counts: Record<string, number>; unplanned: Array<Record<string, unknown>> } }
  decision_document: DecisionDocument
}

export const buildPlan = (source: SourceEvidence, document: unknown, targetSource?: SourceEvidence | null, targetDevice?: string, workflowMode?: 'offline' | 'destination') =>
  postJson<Omit<PlanArtifact, 'commands' | 'report' | 'decision_document' | 'recommendations' | 'support_guidance'>>('/api/migrate', {
    compact_response: true,
    source,
    source_vendor: 'fortigate',
    target_vendor: 'palo_alto',
    decision_document: document,
    ...(workflowMode ? { workflow_mode: workflowMode === 'offline' ? 'OFFLINE_EXPORT' : 'DESTINATION_AWARE' } : {}),
    ...(targetSource ? { target_source: targetSource } : {}),
    ...(targetDevice ? { target_device: targetDevice } : {}),
  }).then((result): PlanArtifact => ({ ...result, commands: result.artifact.commands,
    report: result.artifact.report, decision_document: result.artifact.decision_document,
    recommendations: result.artifact.report.review.recommendations,
    support_guidance: result.artifact.report.review.support_guidance,
  }))

export const downloadBundle = (artifact: PlanArtifact, source: SourceEvidence) => postBlob('/api/migration/bundle', { artifact: artifact.artifact, source })
export const downloadCommands = (artifact: PlanArtifact) => Promise.resolve(new Blob([artifact.artifact.commands.join('\n')], { type: 'text/plain' }))

export function downloadFile(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
