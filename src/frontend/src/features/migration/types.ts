export type DecisionMode = 'AUTO' | 'SUGGESTED' | 'REQUIRED' | 'UNSUPPORTED'
export type DecisionReviewState = 'PENDING' | 'CONFIRMED'

export type ReferenceRole = 'DESTINATION' | 'TEMPLATE'
export type DraftRow = {
  decision_key?: string
  group_key?: string
  item_key?: string
  source_vdom: string
  source_kind: string
  source_name: string
  target_field?: string
  family?: string
  proposed_value?: string | null
  target_name?: string | null
  target_scope: string | null
  operation: 'CREATE' | 'CONFIGURE' | 'REUSE' | null
  status: 'READY' | 'NEEDS_INPUT' | 'CONFLICT' | 'UNSUPPORTED'
  dependencies: string[]
  evidence?: string[]
  blocking_reasons: string[]
  approved?: boolean
  configuration?: Record<string, unknown>
}
export type MigrationDraft = {
  digest: string
  signature: string
  context: { reference_role: ReferenceRole | null; overrides: Record<string, string> }
  destination_verified: boolean
  decisions: DraftRow[]
  configuration: DraftRow[]
  findings: Array<{ code: string; message: string }>
}

export interface MigrationDecision {
  key: string
  source_vdom: string
  source_kind: string
  source_name: string
  target_field: string
  suggested_value: string | null
  value: string | null
  mode: DecisionMode
  review_state: DecisionReviewState
  reason: string
  affected_count: number
  affected_by: Record<string, number>
  evidence_source: string | null
  evidence_type: string | null
  evidence_value: unknown
  target_object: string | null
  evidence_target_digest: string | null
  evidence_target_device: string | null
}

export interface MigrationCandidate {
  value: string
  available?: boolean
  contested?: boolean
  assigned_to?: Array<{ source_vdom: string; source_name: string }>
  [key: string]: unknown
}

export interface MigrationReviewGroup {
  source_vdom: string
  source_kind: string
  source_name: string
  decision_keys: string[]
  decisions: MigrationDecision[]
  suggestions: Record<string, string>
  candidates: Record<string, MigrationCandidate[]>
  source_evidence: Record<string, unknown>
  affected_count: number
  dependent_decision_count: number
  next_action: string | null
  conflicts?: Array<{ decision_key: string; code: string; message: string }>
  queue: 'READY_TO_CONFIRM' | 'CHOOSE_CANDIDATE' | 'NEEDS_INPUT' | 'CONFLICT' | 'COMPLETE'
}

export interface MigrationDecisionDocument {
  format_version: number
  source_digest: string
  decisions: MigrationDecision[]
  [key: string]: unknown
}

export interface MigrationRequirementsResponse {
  success: true
  preview_id: string
  requirements: Record<string, unknown>
  decisions: { decisions: MigrationDecision[] }
  decision_document: MigrationDecisionDocument
  design_session: Record<string, unknown>
  target_devices: string[]
  target_device: string | null
  target_device_metadata: Record<string, unknown>[]
  decision_context: Record<string, Record<string, unknown>>
  decision_candidates: Record<string, MigrationCandidate[]>
  review_summary: Record<string, number>
  review_groups: MigrationReviewGroup[]
  architecture_questions: Record<string, unknown>[]
  rule_suggestions: Record<string, unknown>[]
  target_warnings: Record<string, unknown>
  target_findings: Record<string, unknown>[]
  decision_evidence: Record<string, string>
  auto_decisions: Record<string, Record<string, unknown>>
  evidence_summary: Record<string, number>
  target_evidence: Record<string, unknown> | null
  target_evidence_changed: boolean
  invalidated_target_decisions: string[]
  recommendations: Record<string, unknown>[]
}
