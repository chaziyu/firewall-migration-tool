import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { DestinationEvidence } from '../components/DestinationSnapshot'

export type ASAOptions = {
  source_scope: string | null
  target_context: string
  target_version: string
  target_mode: 'routed'
  interfaces: Record<string, { target_interface: string; nameif: string; security_level: number }>
  new_target_confirmed: boolean
  routing_complete: boolean
  permit_inter_interface: boolean
  permit_intra_interface: boolean
  ace_limit: number
}
export type ASAPlanRow = {
  key: string; family: string; source_scope: string; source_name: string; source_path: string
  target_name: string; settings: Record<string, unknown>; dependencies: string[]; blockers: string[]
  source_order: number; target_disposition?: string | null; approval_group?: string | null
}
export type ASAReview = {
  draft: { digest: string; context_digest: string; items: ASAPlanRow[]; [key: string]: unknown }
  requirements: { source_scopes: string[]; decisions: Array<{ key: string; family: string; source_name: string; value: unknown; mode: string }> }
  report: { items: Array<ASAPlanRow & { render_disposition: string; guidance?: string[] }>; coverage?: { manual_records?: number }; verification: string; plan_status: string; findings: string[] }
  options: ASAOptions
}
export type ASAArtifact = {
  envelope_type: string; artifact_id: string; signature?: string; command_text: string; command_count: number
  command_sha256: string; report: ASAReview['report'] & { verification: string; [key: string]: unknown }
}
export type ASAWorkspace = {
  pairId: 'palo_alto_to_cisco_asa'; sourceKey: string; options: ASAOptions
  targetSource?: DestinationEvidence | null
  review: ASAReview | null; approval: Record<string, unknown> | null; artifact: ASAArtifact | null
  stage: 'load' | 'place' | 'review' | 'export'
}
export type ASAApiReview = ASAReview
export type ASASource = SourceEvidence
