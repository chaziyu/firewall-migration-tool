import type { SourcePreviewData } from '../features/source/types'
import type { MigrationDecisionDocument } from '../features/migration/types'
import type { PlanArtifact } from '../features/migration/migrationApi'

export type SourceEvidence = { vendor?: string; source_text: string; source_name?: string; [key: string]: unknown }
export type Workspace = {
  updatedAt: number
  preview: SourcePreviewData | null
  targetSource: SourceEvidence | null
  targetDevice: string
  decisionDocument: MigrationDecisionDocument | null
  designSession: Record<string, unknown> | null
  artifact: PlanArtifact | null
}
