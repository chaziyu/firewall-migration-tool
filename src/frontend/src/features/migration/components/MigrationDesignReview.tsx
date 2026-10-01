import { useState } from 'react'
import type { DraftRow, MigrationDraft } from '../types'
import { draftDependencies, draftRowKey, portExceptionGroups } from '../reviewDrafts'

export function MigrationDesignReview({ draft, busy, approvedItems, onPrepare, onApprove }: {
  draft: MigrationDraft
  busy: boolean
  approvedItems: string[]
  onPrepare: (overrides: Record<string, string>) => void
  onApprove: (groups: string[]) => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [filter, setFilter] = useState('all')
  const [page, setPage] = useState(1)
  const keyFor = draftRowKey
  const isApproved = (row: DraftRow) => row.approved || Boolean(row.item_key && approvedItems.includes(row.item_key))
  const rows = [...draft.decisions, ...draft.configuration]
  const ready = rows.filter((row) => row.status === 'READY' && !isApproved(row))
  const portGroups = portExceptionGroups(rows)
  const grouped = new Set([...portGroups.values()].flat().map(keyFor))
  const filtered = rows.filter((row) => !grouped.has(keyFor(row)) && (filter === 'all' || row.status === filter))
  return <section aria-label="Deterministic design review" className="review-work-card">
    <h3>Proposed configuration</h3>
    <p>{draft.destination_verified ? 'Checked against the uploaded destination configuration.' : 'Destination unverified. Hardware capacity, licensing and collisions need destination evidence.'}</p>
    <p>{(['CREATE', 'CONFIGURE', 'REUSE'] as const).map((operation) => `${operation.toLowerCase()}: ${draft.configuration.filter((row) => row.operation === operation).length}`).join(' · ')} · needs decision: {rows.filter((row) => row.status === 'NEEDS_INPUT').length} · conflict: {rows.filter((row) => row.status === 'CONFLICT').length} · unsupported: {rows.filter((row) => row.status === 'UNSUPPORTED').length}</p>
    <div className="migration-toolbar">
      <button type="button" className="primary-button" disabled={busy || !ready.length} onClick={() => onApprove(ready.map(keyFor))}>Approve ready groups ({ready.length})</button>
      <button type="button" disabled={busy || !selected.length} onClick={() => onApprove(draftDependencies(rows, selected, approvedItems))}>Approve selected groups and prerequisites</button>
      <label className="field">Show proposals<select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(1) }}>
        <option value="all">All configuration</option><option value="NEEDS_INPUT">Needs decision</option><option value="CONFLICT">Conflicts</option><option value="UNSUPPORTED">Unsupported</option><option value="READY">Ready for review</option>
      </select></label>
    </div>
    <p className="report-count-note">Approval includes the shown values, operations, configuration and prerequisites. Unresolved groups stay blocked.</p>
    {filtered.slice((page - 1) * 30, page * 30).map((row) => <article key={keyFor(row)} className="review-work-card">
      <label><input type="checkbox" checked={selected.includes(keyFor(row))} disabled={busy || row.status !== 'READY' || isApproved(row)}
        onChange={(event) => setSelected((keys) => event.target.checked ? [...keys, keyFor(row)] : keys.filter((key) => key !== keyFor(row)))} /> {row.source_vdom} / {row.source_name} · {row.target_field || row.family}</label>
      <p><strong>{row.proposed_value || row.target_name || 'Needs input'}</strong> · {row.target_scope || 'Scope unresolved'} · {row.operation || row.status} {isApproved(row) ? '· Approved' : ''}</p>
      {!!row.evidence?.length && <p>{row.evidence.join('; ')}</p>}
      {!!row.blocking_reasons.length && <p role="status">{row.blocking_reasons.map((reason) => reason.startsWith('Unresolved prerequisite:') ? 'Resolve the prerequisites shown below.' : reason).join('; ')}</p>}
      {!!portGroups.get(keyFor(row))?.length && <details open><summary>Affected by this port allocation ({portGroups.get(keyFor(row))!.length})</summary><ul>{portGroups.get(keyFor(row))!.map((affected) => <li key={keyFor(affected)}>{affected.source_vdom} / {affected.source_name} · {affected.target_field || affected.family}{affected.configuration && <details><summary>Affected configuration</summary><pre>{JSON.stringify(affected.configuration, null, 2)}</pre></details>}</li>)}</ul></details>}
      {row.decision_key && <details><summary>{row.proposed_value ? 'Edit proposal' : 'Set target value'}</summary>
        <form onSubmit={(event) => { event.preventDefault(); const value = new FormData(event.currentTarget).get('value')?.toString().trim(); if (value) onPrepare({ ...draft.context.overrides, [row.decision_key!]: value }) }}>
          <label className="field">{row.source_vdom} / {row.source_name} · {row.target_field}<input name="value" defaultValue={row.proposed_value || ''} required disabled={busy} /></label>
          <button type="submit" disabled={busy}>Update draft and dependents</button>
        </form>
      </details>}
      {row.configuration && <details><summary>Affected configuration</summary><pre>{JSON.stringify(row.configuration, null, 2)}</pre></details>}
      {!!row.dependencies.length && <details><summary>Prerequisites ({row.dependencies.length})</summary><ul>{row.dependencies.map((key) => { const parent = rows.find((entry) => keyFor(entry) === key); return <li key={key}>{parent ? `${parent.source_vdom} / ${parent.source_name} · ${parent.target_field || parent.family}` : key}</li> })}</ul></details>}
    </article>)}
    {filtered.length > 30 && <div className="report-pager"><button type="button" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous proposals</button><span>Page {page} of {Math.ceil(filtered.length / 30)}</span><button type="button" disabled={page * 30 >= filtered.length} onClick={() => setPage((value) => value + 1)}>Next proposals</button></div>}
    {!!draft.findings.length && <details><summary>Coverage and findings ({draft.findings.length})</summary><ul>{draft.findings.map((row, index) => <li key={index}>{row.code}: {row.message}</li>)}</ul></details>}
  </section>
}
