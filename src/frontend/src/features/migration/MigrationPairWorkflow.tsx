import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { MigrationStage } from './types'
import { FortiGateMigrationWorkflow } from './paloAltoToFortigate/MigrationWorkflow'
import { JuniperSRXMigrationWorkflow } from './fortigateToJuniperSrx/MigrationWorkflow'
import { CiscoAsaMigrationWorkflow } from './fortigateToCiscoAsa/MigrationWorkflow'
import { CheckPointMigrationWorkflow } from './fortigateToCheckPoint/MigrationWorkflow'
import { PaloAltoToJuniperSrxWorkflow } from './paloAltoToJuniperSrx/MigrationWorkflow'
import { PaloAltoToCiscoAsaWorkflow } from './paloAltoToCiscoAsa/MigrationWorkflow'
import { PaloAltoToCheckPointWorkflow } from './paloAltoToCheckPoint/MigrationWorkflow'
import { PaloAltoToCiscoFtdWorkflow } from './paloAltoToCiscoFtd/MigrationWorkflow'

type Props = {
  pairId: string
  source: SourceEvidence
  sourceKey: string
  stage: MigrationStage
  onStageChange: (stage: MigrationStage) => void
  onReviewSource?: () => void
}

export function MigrationPairWorkflow({ pairId, source, sourceKey, stage, onStageChange, onReviewSource }: Props) {
  const key = `${pairId}:${sourceKey}`
  switch (pairId) {
    case 'palo_alto_to_cisco_ftd':
      return <PaloAltoToCiscoFtdWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
    case 'palo_alto_to_checkpoint':
      return <PaloAltoToCheckPointWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
    case 'palo_alto_to_cisco_asa':
      return <PaloAltoToCiscoAsaWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
    case 'palo_alto_to_fortigate':
      return <FortiGateMigrationWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} onReviewSource={onReviewSource} />
    case 'palo_alto_to_juniper_srx':
      return <PaloAltoToJuniperSrxWorkflow key={key} source={source} sourceKey={sourceKey} stage={stage} onStageChange={onStageChange} />
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
