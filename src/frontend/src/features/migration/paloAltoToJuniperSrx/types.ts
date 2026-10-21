import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { DestinationEvidence } from '../components/DestinationSnapshot'

export type SRXOptions = {
  source_scope: string | null
  target_context: string
  target_version: string
  target_mode: 'standalone'
  interfaces: Record<string, { target_interface: string; unit: number; tag?: number | null }>
  zones: Record<string, string>
  interface_zones: Record<string, string>
  routing_table: string
  vlan_interfaces_available: boolean
}
export type SRXPlanRow = {
  key: string; family: string; source_scope: string; source_name: string; source_path: string
  target_name: string; settings: Record<string, unknown>; dependencies: string[]; blockers: string[]
  source_order: number; target_disposition?: string | null
}
export type SRXReview = {
  draft: { digest: string; context_digest: string; items: SRXPlanRow[]; [key: string]: unknown }
  requirements: { source_scopes: string[]; decisions: Array<{ key: string; family: string; source_name: string; value: unknown; mode: string }> }
  report: { items: Array<SRXPlanRow & { render_disposition: string; guidance?: string[] }>; coverage?: { manual_records?: number }; verification: string; plan_status: string; findings: string[] }
  options: SRXOptions
}
export type SRXArtifact = {
  envelope_type: string; artifact_id: string; signature?: string; command_text: string; command_count: number
  command_sha256: string; report: SRXReview['report'] & { verification: string; [key: string]: unknown }
}
export type SRXWorkspace = {
  pairId: 'palo_alto_to_juniper_srx'; sourceKey: string; options: SRXOptions
  targetSource?: DestinationEvidence | null
  review: SRXReview | null; approval: Record<string, unknown> | null; artifact: SRXArtifact | null
  stage: 'load' | 'place' | 'review' | 'export'
}
export type SRXApiReview = SRXReview
export type SRXSource = SourceEvidence
