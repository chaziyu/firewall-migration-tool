import type { MigrationCoverageReport } from '../components/MigrationCoverage'
import type { DestinationEvidence } from '../components/DestinationSnapshot'

export type SrxInterfaceMapping = { target_interface?: string; unit?: number }
export type SrxOptions = {
  source_vdom: string
  target_context: string
  target_version: string
  target_mode: string
  routing_table: string
  timezone: string
  nat_return_routing_confirmed?: boolean
  target_platform?: string
  vlan_interfaces_available?: boolean
  interfaces: Record<string, Record<string, SrxInterfaceMapping>>
  zones: Record<string, Record<string, string>>
  interface_zones?: Record<string, Record<string, string>>
}
export type SrxRequirement = {
  key: string
  source_vdom: string | null
  source_kind: string
  source_name: string
  target_field: string
  label: string
  value: unknown
  choices: string[]
}
export type SrxPlanItem = {
  key: string
  family: string
  source_vdom: string
  source_name: string
  target_name: string
  settings: Record<string, unknown>
  dependencies: string[]
  decision_keys: string[]
  blockers: string[]
  guidance: Array<Record<string, unknown>>
  render_disposition: string
  approval_group?: string | null
}
export type SrxReview = {
  draft: Record<string, unknown>
  requirements: SrxRequirement[]
  report: {
  coverage?: MigrationCoverageReport
    plan_status: string
    items: SrxPlanItem[]
    findings: Array<Record<string, unknown>>
    deployment_available: false
    destination_verified: false
    [key: string]: unknown
  }
}
export type SrxArtifact = {
  artifact_id: string
  envelope_type: 'fortigate_to_juniper_srx_artifact_v1'
  command_text: string
  command_count: number
  command_sha256: string
  expires_at: number
  report: SrxReview['report'] & Record<string, unknown>
  [key: string]: unknown
}
export type JuniperSrxWorkspace = {
  pairId: 'fortigate_to_juniper_srx'
  sourceKey: string
  destination?: DestinationEvidence | null
  options: SrxOptions
  requirements: SrxRequirement[]
  review: SrxReview | null
  approval: Record<string, unknown> | null
  artifact: SrxArtifact | null
  previewText: string | null
}
