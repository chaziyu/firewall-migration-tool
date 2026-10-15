import type { mappingSummary } from '../reviewPresentation'

export function MigrationMappingSummary({ counts, pending = false }: {
  counts: ReturnType<typeof mappingSummary>
  pending?: boolean
}) {
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
