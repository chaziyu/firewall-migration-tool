import type { MigrationCoverageReport } from '../components/MigrationCoverage'
import type { DestinationEvidence } from '../components/DestinationSnapshot'

export type AsaInterfaceMapping = { interface?: string; nameif?: string; security_level?: number }
export type AsaOptions = {
  source_vdom: string
  target_context: string
  target_version: string
  target_mode: string
  interfaces: Record<string, Record<string, AsaInterfaceMapping>>
  source_timezone: string
  target_timezone: string
  nat_evidence: Record<string, Record<string, boolean>>
  target_platform?: string
  vlan_interfaces_available?: boolean
}
export type AsaRequirement = {
  key: string
  source_vdom: string | null
  source_kind: string
  source_name: string
  target_field: string
  label: string
  value: unknown
  choices: string[]
}
export type AsaPlanItem = {
  key: string
  family: string
  source_vdom: string
  source_name: string
  target_name: string
  settings: Record<string, unknown>
  dependencies: string[]
  blockers: string[]
  approval_group?: string | null
  render_disposition: string
}
export type AsaReport = {
  coverage?: MigrationCoverageReport
  plan_status: string
  items: AsaPlanItem[]
  findings: Array<Record<string, unknown>>
  deployment_available?: false
  destination_verified?: false
  [key: string]: unknown
}
export type AsaReview = {
  draft: Record<string, unknown>
  requirements: AsaRequirement[]
  report: AsaReport
}
export type AsaArtifact = {
  artifact_id: string
  envelope_type: 'fortigate_to_cisco_asa_artifact_v1'
  command_text?: string
  command_count: number
  command_sha256: string
  expires_at: number
  report: AsaReport
  [key: string]: unknown
}
export type CiscoAsaWorkspace = {
  pairId: 'fortigate_to_cisco_asa'
  sourceKey: string
  destination?: DestinationEvidence | null
  options: AsaOptions
  requirements: AsaRequirement[]
  review: AsaReview | null
  approval: Record<string, unknown> | null
  artifact: AsaArtifact | null
  previewText: string | null
}
