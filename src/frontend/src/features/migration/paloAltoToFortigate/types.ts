import type { SourceEvidence } from '../../../storage/workspaceTypes'

export type FortiGateOptions = {
  source_scope: string; vdom: string; interfaces: Record<string, string>; zones: Record<string, string>
  routers: Record<string, number>; profile: Record<string, string | string[]>; timezone: string
  policy_settings: Record<string, Record<string, string>>
}
export type Requirement = { key: string; label: string; value?: string | number | null; choices?: string[]; policy_key?: string; field?: string }
export type ConfigurationRow = {
  key: string; family: string; source_scope: string; source_name: string; target_name: string; target_vdom: string
  settings: Array<[string, string[]]>; dependencies: string[]; render_disposition: string; blocking_reasons: string[]
}
export type FortiGateDraft = {
  digest: string; signature: string; context: Record<string, unknown>; configuration: ConfigurationRow[]
  findings: string[]; [key: string]: unknown
}
export type FortiGateArtifact = {
  envelope_type: 'fg_migration_artifact_v1'; artifact_id: string; signature: string; commands: string[]
  command_count: number; command_sha256: string; report: {
    plan_status: string; items: ConfigurationRow[]; render_summary: Record<string, number>; verification: string
    deployment_eligibility: { eligible: false; reason: string }
  }
}
export type FortiGateReview = {
  draft: FortiGateDraft; requirements: { source_scopes: string[]; decisions: Requirement[]; findings: string[]; has_schedules?: boolean; has_dnat?: boolean; has_pool_snat?: boolean }
  issues: Array<{ id: string; category: string; source_scope: string; source_name: string; explanation: string }>
}
export type FortiGateWorkspace = {
  sourceKey: string; options: FortiGateOptions; targetSource: SourceEvidence | null
  review: FortiGateReview | null; approval: Record<string, unknown> | null; artifact: FortiGateArtifact | null
  stage: 'load' | 'place' | 'review' | 'export'
}
