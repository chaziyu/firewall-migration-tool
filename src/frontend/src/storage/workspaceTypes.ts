import type { SourcePreviewData } from '../features/source/types'
import type { MigrationDecisionDocument } from '../features/migration/types'
import type { MigrationDraft, ReferenceRole } from '../features/migration/types'
import type { PlanArtifact } from '../features/migration/migrationApi'
import type { FortiGateWorkspace } from '../features/migration/paloAltoToFortigate/types'
import type { JuniperSrxWorkspace } from '../features/migration/fortigateToJuniperSrx/types'
import type { CiscoAsaWorkspace } from '../features/migration/fortigateToCiscoAsa/types'
import type { CheckPointWorkspace } from '../features/migration/fortigateToCheckPoint/types'
import type { SRXWorkspace } from '../features/migration/paloAltoToJuniperSrx/types'
import type { ASAWorkspace } from '../features/migration/paloAltoToCiscoAsa/types'
import type { CPWorkspace } from '../features/migration/paloAltoToCheckPoint/types'
import type { FTDWorkspace } from '../features/migration/paloAltoToCiscoFtd/types'

export type PanosMigrationWorkspace = FortiGateWorkspace | JuniperSrxWorkspace | CiscoAsaWorkspace | CheckPointWorkspace | SRXWorkspace | ASAWorkspace | CPWorkspace | FTDWorkspace

export type SourceEvidence = { vendor?: string; source_text: string; source_name?: string; [key: string]: unknown }
export type Workspace = {
  panosMigration?: PanosMigrationWorkspace | null
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
