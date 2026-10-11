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

export interface MigrationDecisionDocument {
  format_version: number
  source_digest: string
  decisions: MigrationDecision[]
  [key: string]: unknown
}
