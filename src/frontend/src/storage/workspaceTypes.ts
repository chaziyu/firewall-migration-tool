import type { SourcePreviewData } from '../features/source/types'
import type { MigrationDecisionDocument } from '../features/migration/types'
import type { MigrationDraft, ReferenceRole } from '../features/migration/types'
import type { PlanArtifact } from '../features/migration/migrationApi'
import type { FortiGateWorkspace } from '../features/migration/paloAltoToFortigate/types'
import type { JuniperSrxWorkspace } from '../features/migration/fortigateToJuniperSrx/types'
import type { CiscoAsaWorkspace } from '../features/migration/fortigateToCiscoAsa/types'
import type { CheckPointWorkspace } from '../features/migration/fortigateToCheckPoint/types'

export type NewPairMigrationWorkspace = JuniperSrxWorkspace | CiscoAsaWorkspace | CheckPointWorkspace

export type SourceEvidence = { vendor?: string; source_text: string; source_name?: string; [key: string]: unknown }
export type Workspace = {
  fortigateMigration?: FortiGateWorkspace | null
  newPairMigration?: NewPairMigrationWorkspace | null
  migrationPairId?: string
  proposals?: Record<string, string>
  serviceNames?: Record<string, Record<string, string>>
  workflowMode?: 'offline' | 'destination'
  updatedAt: number
  preview: SourcePreviewData | null
  targetSource: SourceEvidence | null
  targetDevice: string
  decisionDocument: MigrationDecisionDocument | null
  deterministicDraft: MigrationDraft | null
  referenceRole: ReferenceRole
  artifact: PlanArtifact | null
}
