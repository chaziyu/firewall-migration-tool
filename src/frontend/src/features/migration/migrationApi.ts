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
export type ReviewData = {
  decision_document: DecisionDocument
  decisions: { decisions: Decision[] }
  target_devices: string[]
  target_device: string | null
  requirements: { required: unknown[]; optional: unknown[] }
  decision_candidates: Record<string, Array<{ value: string; target_scope?: string; class?: string; strong_evidence?: string[]; supporting_evidence?: string[] }>>
  target_evidence: { device?: string; config_digest?: string } | null
}
export type AIProposal = {
  decision_key: string
  action: 'USE_EXISTING' | 'NO_SAFE_PROPOSAL'
  proposed_value: string | null
  target_scope: string | null
  rationale: string
  evidence_refs: string[]
  validation_status: string
}
export type AIDesignSession = { design_session_id: string; proposals: AIProposal[] }
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
  report: { items?: Array<Record<string, unknown>>; command_sha256?: string }
  decision_document: DecisionDocument
}

export const buildPlan = (source: SourceEvidence, document: unknown, targetSource?: SourceEvidence | null, targetDevice?: string) =>
  postJson<Omit<PlanArtifact, 'commands' | 'report' | 'decision_document' | 'recommendations' | 'support_guidance'>>('/api/migrate', {
    compact_response: true,
    source,
    source_vendor: 'fortigate',
    target_vendor: 'palo_alto',
    decision_document: document,
    ...(targetSource ? { target_source: targetSource } : {}),
    ...(targetDevice ? { target_device: targetDevice } : {}),
  }).then((result): PlanArtifact => ({ ...result, commands: result.artifact.commands,
    report: result.artifact.report, decision_document: result.artifact.decision_document,
    recommendations: result.artifact.report.review.recommendations,
    support_guidance: result.artifact.report.review.support_guidance,
  }))

export const downloadBundle = (artifact: PlanArtifact, source: SourceEvidence) => postBlob('/api/migration/bundle', { artifact: artifact.artifact, source })
export const downloadCommands = (artifact: PlanArtifact) => Promise.resolve(new Blob([artifact.artifact.commands.join('\n')], { type: 'text/plain' }))

export const deployArtifact = (artifact: PlanArtifact, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/deploy', { ...connection, artifact: artifact.artifact })
export const validateCandidate = (artifact: PlanArtifact, sessionId: string, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/validate-candidate', {
    ...connection, artifact: artifact.artifact, deployment_session_id: sessionId,
  })
export const commitCandidate = (artifact: PlanArtifact, sessionId: string, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/commit', {
    ...connection, artifact: artifact.artifact, deployment_session_id: sessionId,
  })

export function downloadFile(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
