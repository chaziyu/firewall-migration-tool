import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { MigrationStage } from './types'
import { JuniperSRXMigrationWorkflow } from './fortigateToJuniperSrx/MigrationWorkflow'
import { CiscoAsaMigrationWorkflow } from './fortigateToCiscoAsa/MigrationWorkflow'
import { CheckPointMigrationWorkflow } from './fortigateToCheckPoint/MigrationWorkflow'

type Props = {
  pairId: string
  source: SourceEvidence
  sourceKey: string
  stage: MigrationStage
  onStageChange: (stage: MigrationStage) => void
}

export function MigrationPairWorkflow({ pairId, source, sourceKey, stage, onStageChange }: Props) {
  const key = `${pairId}:${sourceKey}`
  switch (pairId) {
    case 'fortigate_to_juniper_srx':
      return <JuniperSRXMigrationWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
    case 'fortigate_to_cisco_asa':
      return <CiscoAsaMigrationWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
    case 'fortigate_to_checkpoint':
      return <CheckPointMigrationWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
    default:
      return <section className="panel" role="status"><h2>Migration target unavailable</h2><p>This migration pair has no enabled offline export workflow.</p></section>
  }
}
