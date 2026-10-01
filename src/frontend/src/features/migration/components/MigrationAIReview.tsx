import { workspace } from '../../../storage/workspaceStore'
import { download } from '../download'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { Dispatch, SetStateAction } from 'react'
import type { Proposal } from '../reviewTypes'

type RunAction = (action: () => Promise<void>, done?: string) => Promise<void>

export function MigrationAIReview({
  advisorStatus,
  busy,
  targetSource,
  targetDevice,
  designSessionId,
  validProposalKeys,
  proposals,
  run,
  testAdvisor,
  buildProposals,
  approveProposals,
  approveProposal,
  rejectProposals,
  setDrafts,
}: {
  advisorStatus: string
  busy: boolean
  targetSource: SourceEvidence | null
  targetDevice: string
  designSessionId: string
  validProposalKeys: string[]
  proposals: Proposal[]
  run: RunAction
  testAdvisor: () => Promise<void>
  buildProposals: (retry?: boolean) => Promise<void>
  approveProposals: (keys: string[]) => Promise<void>
  approveProposal: (proposal: Proposal) => Promise<void>
  rejectProposals: (keys: string[]) => Promise<void>
  setDrafts: Dispatch<SetStateAction<Record<string, string>>>
}) {
  return (
    <>
          <details className="ai-review-controls"><summary>AI-assisted review (optional)</summary>
            <h3>AI-assisted review</h3>
            <p>AI suggestions remain provisional. Approving a validated proposal records an engineer-confirmed decision.</p>
            <p role="status" aria-live="polite">{advisorStatus}</p>
            <div className="migration-toolbar">
              <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(testAdvisor)}>Test advisor</button>
              {targetSource && targetDevice && <>
                <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => buildProposals(Boolean(designSessionId)), 'Ready proposals refreshed.')}>{designSessionId ? 'Retry ready proposals' : 'Propose ready mappings'}</button>
                <button className="secondary-button" type="button" disabled={busy || !validProposalKeys.length} onClick={() => void run(() => approveProposals(validProposalKeys), 'Valid proposals approved by engineer.')}>Approve valid proposals ({validProposalKeys.length})</button>
              </>}
              <button className="secondary-button" type="button" onClick={() => download(JSON.stringify(workspace().designSession?.audit ?? [], null, 2), 'migration-ai-audit.json', 'application/json')}>Download AI review audit</button>
            </div>
            {proposals.map((proposal) => <article className="ai-proposal" key={proposal.decision_key}>
              <strong>{proposal.proposed_value ?? 'No safe proposal'}</strong><p>{proposal.target_scope || proposal.action} · {proposal.rationale || proposal.validation_status}</p>
              {proposal.evidence_refs?.length ? <small>Evidence: {proposal.evidence_refs.join(', ')}</small> : null}
              {proposal.validation_status === 'VALID' && proposal.proposed_value && <button type="button" className="text-button" disabled={busy} onClick={() => void run(() => approveProposal(proposal), 'Proposal approved by engineer.')}>Approve proposal</button>}
              {proposal.proposed_value && <button type="button" className="text-button" disabled={busy} onClick={() => setDrafts((current) => ({ ...current, [proposal.decision_key]: proposal.proposed_value ?? '' }))}>Use value to edit</button>}
              <button type="button" className="text-button" disabled={busy} onClick={() => void run(() => rejectProposals([proposal.decision_key]), 'Proposal dismissed.')}>Dismiss</button>
            </article>)}
          </details>

    </>
  )
}
