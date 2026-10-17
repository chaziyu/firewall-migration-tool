import type { SourceEvidence } from '../../../storage/workspaceTypes'

export type CheckPointOptions = {
  source_vdom: string
  management_target: string
  management_domain: string
  management_api_version: string
  gaia_target: string
  policy_package: string
  access_layer: string
  install_on: string[]
  insertion_anchor: string
  insertion_relation: string
  target_cleanup_action: string
}

export type CheckPointRequirement = {
  key: string
  source_vdom: string | null
  source_kind: string
  source_name: string
  target_field: string
  label: string
  value: unknown
  choices: string[]
}

export type CheckPointPlanItem = {
  key: string
  family: string
  source_vdom: string
  source_name: string
  target_name: string
  settings: Record<string, unknown>
  dependencies: string[]
  blockers: string[]
  render_disposition: string
}

export type CheckPointReport = {
  plan_status: string
  items: CheckPointPlanItem[]
  findings: Array<Record<string, unknown>>
  file_sha256?: Record<string, string>
  destination_snapshot_compared?: false
  deployment_available?: false
  [key: string]: unknown
}

export type CheckPointReview = {
  draft: Record<string, unknown>
  requirements: CheckPointRequirement[]
  report: CheckPointReport
}

export type CheckPointArtifact = {
  artifact_id: string
  envelope_type: 'fortigate_to_checkpoint_artifact_v1'
  files: Record<string, { content: string; byte_count: number; sha256: string }>
  file_sha256: Record<string, string>
  report: CheckPointReport
  expires_at: number
  [key: string]: unknown
}

export type CheckPointFilePreview = {
  text: string
  sha256: string
  byte_count: number
}

export type CheckPointWorkspace = {
  pairId: 'fortigate_to_checkpoint'
  sourceKey: string
  options: CheckPointOptions
  requirements: CheckPointRequirement[]
  review: CheckPointReview | null
  approval: Record<string, unknown> | null
  artifact: CheckPointArtifact | null
  preview: Record<string, CheckPointFilePreview> | null
}

export type CheckPointSource = SourceEvidence
