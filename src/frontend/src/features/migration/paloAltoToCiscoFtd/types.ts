import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import type { MigrationStage } from '../types'

export type FTDOptions = {
  source_scope: string
  target_mode: 'new' | 'existing'
  manager_target: string
  domain_id: string
  domain_name: string
  fmc_api_version: string
  policy_name: string
  target_device_id: string
  target_device_name: string
}
export type FTDPlanRow = {
  key: string
  family: string
  source_scope: string
  source_name: string
  target_name: string
  settings: Record<string, unknown>
  dependencies: string[]
  blockers: string[]
  render_disposition: string
}
export type FTDRequirement = { key: string; label: string; value: unknown; choices: string[] }
export type FTDReport = {
  items: FTDPlanRow[]
  verification: string
  plan_status: string
  findings: Array<{ code: string; message: string }>
  [key: string]: unknown
}
export type FTDReview = {
  options: FTDOptions
  source_scopes: string[]
  draft: Record<string, unknown>
  requirements: FTDRequirement[]
  report: FTDReport
}
export type FTDArtifact = {
  artifact_id: string
  files: Record<string, { content: string; sha256: string; byte_count: number }>
  report: FTDReport
  [key: string]: unknown
}
export type FTDWorkspace = {
  pairId: 'palo_alto_to_cisco_ftd'
  sourceKey: string
  options: FTDOptions
  targetSource?: DestinationEvidence | null
  review: FTDReview | null
  approval: Record<string, unknown> | null
  artifact: FTDArtifact | null
  stage: MigrationStage
}
export type FTDSource = SourceEvidence
