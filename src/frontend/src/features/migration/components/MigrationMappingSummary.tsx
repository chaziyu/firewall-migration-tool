import type { ReactNode } from 'react'
import type { mappingSummary } from '../reviewPresentation'

export function MigrationMappingSummary({ counts, pending = false, compact = false, sourceIssues = 0, children }: {
  counts: ReturnType<typeof mappingSummary>
  pending?: boolean
  compact?: boolean
  sourceIssues?: number
  children?: ReactNode
}) {
  if (compact) return <section className="target-setup-status" aria-label="Mapping status">
    {sourceIssues > 0 && <span>{sourceIssues} source {sourceIssues === 1 ? 'issue' : 'issues'} · affected items blocked</span>}
    {counts.needsInput > 0 && <span>Input needed: {counts.needsInput}</span>}
    {counts.conflicts > 0 && <span>Conflicts: {counts.conflicts}</span>}
    {counts.blocked > 0 && <span>Blocked: {counts.blocked}</span>}
    {pending && <span role="status">Changes not validated</span>}
    <details><summary>Details</summary>
      <p>{counts.ready} ready for review · {counts.approved} approved · {counts.unsupported} unsupported fields · {counts.excluded} excluded fields</p>
      {pending && <p>Counts reflect the last validation.</p>}
      <p>Proposals require final approval. Validation does not approve changes.</p>
      <p>Physical ports use proposed ethernet1/N allocations. Check target hardware and cabling. Edit shared zones once; member overrides remain separate.</p>
      {children}
    </details>
  </section>
  return <section aria-label="Mapping fields"><h3>Mapping fields</h3>
    <div className="migration-summary" aria-label="Mapping task dashboard">
      <p><strong>{counts.needsInput}</strong> need input</p>
      <p><strong>{counts.conflicts}</strong> conflicts</p>
      <p><strong>{counts.blocked}</strong> waiting for dependencies</p>
    </div>
    <details><summary>Mapping progress and exclusions</summary>
      <p>{counts.ready} ready for review · {counts.approved} approved · {counts.unsupported} unsupported fields · {counts.excluded} explicitly excluded fields</p>
    </details>
    {pending && <p role="status">Counts describe the last validated draft. Pending edits require validation.</p>}
  </section>
}
