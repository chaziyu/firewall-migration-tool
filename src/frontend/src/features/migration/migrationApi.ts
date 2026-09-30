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
  commands: number
  counts: Record<string, number>
  render_summary: Record<string, number>
  blocking_reasons: Array<Record<string, unknown>>
  recommendations: Array<Record<string, unknown>>
  support_guidance?: Array<Record<string, unknown>>
  report: { items?: Array<Record<string, unknown>>; command_sha256?: string }
  decision_document: DecisionDocument
}

export const loadRequirements = (previewId: string, document?: unknown, targetPreviewId?: string, targetDevice?: string) =>
  postJson<ReviewData>('/api/migration/requirements', {
    preview_id: previewId,
    ...(document ? { decision_document: document } : {}),
    ...(targetPreviewId ? { target_preview_id: targetPreviewId } : {}),
    ...(targetDevice ? { target_device: targetDevice } : {}),
  })

export const importTargetIntent = (previewId: string, document: DecisionDocument, yaml: string, targetPreviewId?: string, targetDevice?: string) =>
  postJson<{ decision_document: DecisionDocument }>('/api/migration/target-intent/import', {
    preview_id: previewId,
    decision_document: document,
    yaml,
    ...(targetPreviewId ? { target_preview_id: targetPreviewId, target_device: targetDevice } : {}),
  })

export const exportTargetIntent = (previewId: string, document: DecisionDocument) =>
  postJson<{ yaml: string }>('/api/migration/target-intent/export', { preview_id: previewId, decision_document: document })

export const buildAIDesign = (previewId: string, document: DecisionDocument, targetPreviewId: string, targetDevice: string) =>
  postJson<{ design_session: AIDesignSession }>('/api/migration/ai/design', {
    preview_id: previewId,
    decision_document: document,
    target_preview_id: targetPreviewId,
    target_device: targetDevice,
  })

export const approveAIProposal = (sessionId: string, previewId: string, document: DecisionDocument, targetPreviewId: string, targetDevice: string, decisionKey: string) =>
  postJson<{ decision_document: DecisionDocument }>(`/api/migration/ai/design/${encodeURIComponent(sessionId)}/approve`, {
    preview_id: previewId,
    decision_document: document,
    target_preview_id: targetPreviewId,
    target_device: targetDevice,
    decision_keys: [decisionKey],
  })

export const buildPlan = (previewId: string, document: unknown, targetPreviewId?: string, targetDevice?: string) =>
  postJson<PlanArtifact>('/api/migrate', {
    preview_id: previewId,
    source_vendor: 'fortigate',
    target_vendor: 'palo_alto',
    decision_document: document,
    ...(targetPreviewId ? { target_preview_id: targetPreviewId } : {}),
    ...(targetDevice ? { target_device: targetDevice } : {}),
  })

export const loadCommandPreview = (artifactId: string) =>
  postJson<{ command_text: string; command_count: number; command_sha256: string; review_summary: Record<string, number> }>(
    '/api/migration/command-preview', { artifact_id: artifactId },
  )

export const downloadBundle = (artifactId: string) => postBlob('/api/migration/bundle', { artifact_id: artifactId })
export const downloadCommands = (artifactId: string) => postBlob('/api/migration/download', { artifact_id: artifactId })

export const deployArtifact = (artifactId: string, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/deploy', { ...connection, artifact_id: artifactId })
export const validateCandidate = (artifactId: string, sessionId: string, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/validate-candidate', {
    ...connection, artifact_id: artifactId, deployment_session_id: sessionId,
  })
export const commitCandidate = (artifactId: string, sessionId: string, connection: Record<string, unknown>) =>
  postJson<Record<string, unknown>>('/api/commit', {
    ...connection, artifact_id: artifactId, deployment_session_id: sessionId,
  })

export function downloadFile(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
