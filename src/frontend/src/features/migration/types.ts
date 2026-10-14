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
  target_comparison?: { status: string; target_scope?: string; evidence?: string[] }
}
export type MigrationDraft = {
  digest: string
  signature: string
  context: { reference_role: ReferenceRole | null; overrides: Record<string, string>; service_names?: Record<string, Record<string, string>> }
  destination_verified: boolean
  decisions: DraftRow[]
  configuration: DraftRow[]
  issues?: MigrationIssue[]
  readiness?: { coverage: { supported: number; manual: number }; deployment: { eligible: false; missing_prerequisites: string[] } }
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

export interface MigrationDecisionDocument {
  format_version: number
  source_digest: string
  decisions: MigrationDecision[]
  [key: string]: unknown
}

export type MigrationStage = 'load' | 'place' | 'exceptions' | 'review' | 'export'
export type MigrationIssue = {
  id: string; code: string; category: 'CHOICE' | 'PREREQUISITE' | 'CONFLICT' | 'MANUAL'
  source_vdom: string; source_kind: string; source_name: string
  explanation: string; explanations?: string[]; resolution_kind: string; affected_keys: string[]
  affected_sources: Array<{ source_vdom: string; source_kind: string; source_name: string }>
  prerequisite_keys: string[]; action: { kind: 'EDIT_MAPPING'; decision_key: string } | null
}
