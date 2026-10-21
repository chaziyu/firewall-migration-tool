import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import type { MigrationStage } from '../types'

export type CPOptions = {
  source_scope: string; target_mode: 'new' | 'existing'; management_target: string; management_domain: string
  management_api_version: string; gaia_target: string; policy_package: string; access_layer: string; install_on: string[]
  insertion_anchor: string; insertion_relation: string; target_cleanup_action: string
}
export type CPPlanRow = {
  key: string; family: string; source_scope: string; source_name: string; target_name: string
  settings: Record<string, unknown>; dependencies: string[]; blockers: string[]; render_disposition: string
}
export type CPRequirement = { key: string; label: string; value: unknown; choices: string[] }
export type CPReport = { items: CPPlanRow[]; verification: string; plan_status: string; findings: Array<{ code: string; message: string }>; [key: string]: unknown }
export type CPReview = { options: CPOptions; source_scopes: string[]; draft: Record<string, unknown>; requirements: CPRequirement[]; report: CPReport }
export type CPArtifact = { artifact_id: string; files: Record<string, { content: string; sha256: string; byte_count: number }>; report: CPReport; [key: string]: unknown }
export type CPWorkspace = {
  pairId: 'palo_alto_to_checkpoint'; sourceKey: string; options: CPOptions; targetSource?: DestinationEvidence | null
  review: CPReview | null; approval: Record<string, unknown> | null; artifact: CPArtifact | null; stage: MigrationStage
}
export type CPSource = SourceEvidence
