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
export type VPNParameters = { lifetime_seconds?: number; dh_group?: string; pfs?: 'enable' | 'disable'; ike_version?: '1' | '2' }
export type ConversionSettings = { target_model?: string; panos_version?: string; excluded_interfaces?: string[]; management_profiles?: Record<string, string>; generated_management_profiles?: Record<string, { permitted_ips: string[] }>; existing_vpns?: string[]; vpn_parameters?: Record<string, VPNParameters>; security_profiles?: Record<string, string>; identity_mappings?: Record<string, Record<string, string>>; identity_prerequisites?: string[]; vip_external_zones?: Record<string, Record<string, string>> }
export type MigrationDraft = {
  source_issues?: Array<{ code: string; message: string; source_vdom: string; source_name: string; affected_keys: string[] }>
  task_summary?: { choices: number; prerequisites: number; conflicts: number; manual_items: number; manual_issues: number }
  digest: string
  signature: string
  context: { reference_role: ReferenceRole | null; workflow_mode?: 'OFFLINE_EXPORT' | 'DESTINATION_AWARE'; overrides: Record<string, string>; service_names?: Record<string, Record<string, string>>; conversion_settings?: ConversionSettings }
  destination_verified: boolean
  decisions: DraftRow[]
  configuration: DraftRow[]
  issues?: MigrationIssue[]
  readiness?: { coverage: { supported: number; manual: number }; deployment: { eligible: false; missing_prerequisites: string[] } }
  findings: Array<{ code: string; message?: string; identity?: string; source_name?: string; proposed_value?: string; automation_category?: string; fields?: Array<keyof VPNParameters>; member_keys?: string[]; source_vdom?: string; source_kind?: string; [key: string]: unknown }>
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

export type MigrationStage = 'load' | 'place' | 'review' | 'export'
export type MigrationReviewTab = 'changes' | 'decisions' | 'manual'
export type MigrationIssue = {
  id: string; code: string; category: 'CHOICE' | 'PREREQUISITE' | 'CONFLICT' | 'MANUAL'
  source_vdom: string; source_kind: string; source_name: string
  explanation: string; explanations?: string[]; resolution_kind: string; affected_keys: string[]
  affected_sources: Array<{ source_vdom: string; source_kind: string; source_name: string }>
  prerequisite_keys: string[]; action: { kind: 'EDIT_MAPPING'; decision_key: string }
    | { kind: 'EDIT_SETTINGS'; section: 'management' | 'vpn' | 'policy'; finding_code: string; source_vdom?: string; source_kind?: string; identity?: string; member_keys: string[] }
    | { kind: 'REVIEW_SOURCE' } | null
}
