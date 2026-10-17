import type { SourceEvidence } from '../../storage/workspaceTypes'
import { postBlob, postForm, postJson } from '../../api/client'

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
  report: { items?: Array<Record<string, unknown>>; export_counts?: Record<string, number>; command_sha256?: string; workflow_mode?: string; destination_verified?: boolean; deployment_eligibility?: { eligible: boolean; reason: string | null } }
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

export type SetReview = {
  commands: string[]; line_numbers: number[]; command_count: number; command_sha256: string; file_sha256: string
  filename: string; signature: string; expires_at: number
  context: { host: string; port: number; target_device: string; target_serial: string }
}
export type SetImportArtifact = SetReview & { artifact_id: string; envelope_type: 'panos_set_import_v1' }
type ExecutionArtifact = Pick<PlanArtifact, 'artifact'> | { artifact: SetImportArtifact }
export const prepareSetReview = (form: FormData) => postForm<{ review: SetReview | null; devices: string[] }>('/api/deployment/set/prepare-review', form)
export const approveSetReview = (review: SetReview) => postJson<{ artifact: SetImportArtifact }>('/api/deployment/set/approve', { review, command_sha256: review.command_sha256 })

export const deployArtifact = (artifact: ExecutionArtifact, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/deploy', { ...connection, artifact: artifact.artifact })
export const validateCandidate = (artifact: ExecutionArtifact, sessionId: string, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/validate-candidate', {
    ...connection, artifact: artifact.artifact, deployment_session_id: sessionId,
  })
export const commitCandidate = (artifact: ExecutionArtifact, sessionId: string, connection: Record<string, unknown>) =>
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

export type CandidateRecovery = {
  state: string; artifact_id?: string; commands_attempted?: number | null; commands_succeeded?: number | null
  failed_command_index?: number | null; explanation?: string
}
export const inspectCandidate = (artifact: ExecutionArtifact, connection: Record<string, unknown>) =>
  postJson<{ inspection: { state: string; device_serial: string | null; baseline_matches: boolean; candidate_clean: boolean }; recovery: CandidateRecovery }>('/api/inspect-candidate', { ...connection, artifact: artifact.artifact })
