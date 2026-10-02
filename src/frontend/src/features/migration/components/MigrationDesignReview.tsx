import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
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
  const approved = useMemo(() => new Set(approvedItems), [approvedItems])
  const isApproved = (row: DraftRow) => row.approved || Boolean(row.item_key && approved.has(row.item_key))
  const rows = useMemo(() => [...draft.decisions, ...draft.configuration], [draft])
  const byKey = useMemo(() => new Map(rows.map((row) => [draftRowKey(row), row])), [rows])
  const ready = useMemo(() => rows.filter((row) => row.status === 'READY' && !row.approved && !(row.item_key && approved.has(row.item_key))), [rows, approved])
  const portGroups = useMemo(() => portExceptionGroups(rows), [rows])
  const grouped = useMemo(() => new Set([...portGroups.values()].flat().map(draftRowKey)), [portGroups])
  const filtered = useMemo(() => rows.filter((row) => !grouped.has(draftRowKey(row)) && (filter === 'all' || row.status === filter)), [rows, grouped, filter])
  return <section aria-label="Deterministic design review" className="review-work-card">
    <h3>Proposed configuration</h3>
    <p>{draft.destination_verified ? 'Checked against the uploaded destination configuration.' : 'Destination unverified. Hardware capacity, licensing and collisions need destination evidence.'}</p>
    <p>{(['CREATE', 'CONFIGURE', 'REUSE'] as const).map((operation) => `${operation.toLowerCase()}: ${draft.configuration.filter((row) => row.operation === operation).length}`).join(' · ')} · needs decision: {rows.filter((row) => row.status === 'NEEDS_INPUT').length} · conflict: {rows.filter((row) => row.status === 'CONFLICT').length} · unsupported: {rows.filter((row) => row.status === 'UNSUPPORTED').length}</p>
    <div className="migration-toolbar">
      <button type="button" className="primary-button" disabled={busy || !ready.length} onClick={() => onApprove(ready.map(keyFor))}>Approve ready groups ({ready.length})</button>
      <button type="button" disabled={busy || !selected.length} onClick={() => onApprove(draftDependencies(byKey, selected, approvedItems))}>Approve selected groups and prerequisites</button>
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
      {!!portGroups.get(keyFor(row))?.length && <LazyDetails summary={`Affected by this port allocation (${portGroups.get(keyFor(row))!.length})`}>
        {() => <PagedList items={portGroups.get(keyFor(row))!} render={(affected) => <>{affected.source_vdom} / {affected.source_name} · {affected.target_field || affected.family}{affected.configuration && <LazyDetails summary="Affected configuration">{() => <pre>{JSON.stringify(affected.configuration, null, 2)}</pre>}</LazyDetails>}</>} />}
      </LazyDetails>}
      {row.decision_key && <LazyDetails summary={row.proposed_value ? 'Edit proposal' : 'Set target value'}>
        {() => <form onSubmit={(event) => { event.preventDefault(); const value = new FormData(event.currentTarget).get('value')?.toString().trim(); if (value) onPrepare({ ...draft.context.overrides, [row.decision_key!]: value }) }}>
          <label className="field">{row.source_vdom} / {row.source_name} · {row.target_field}<input name="value" defaultValue={row.proposed_value || ''} required disabled={busy} /></label>
          <button type="submit" disabled={busy}>Update draft and dependents</button>
        </form>}
      </LazyDetails>}
      {row.configuration && <LazyDetails summary="Affected configuration">{() => <pre>{JSON.stringify(row.configuration, null, 2)}</pre>}</LazyDetails>}
      {!!row.dependencies.length && <LazyDetails summary={`Prerequisites (${row.dependencies.length})`}>{() => <PagedList items={row.dependencies} render={(key) => { const parent = byKey.get(key); return parent ? `${parent.source_vdom} / ${parent.source_name} · ${parent.target_field || parent.family}` : key }} />}</LazyDetails>}
    </article>)}
    {filtered.length > 30 && <div className="report-pager"><button type="button" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous proposals</button><span>Page {page} of {Math.ceil(filtered.length / 30)}</span><button type="button" disabled={page * 30 >= filtered.length} onClick={() => setPage((value) => value + 1)}>Next proposals</button></div>}
    {!!draft.findings.length && <LazyDetails summary={`Coverage and findings (${draft.findings.length})`}>{() => <PagedList items={draft.findings} render={(row) => `${row.code}: ${row.message}`} />}</LazyDetails>}
  </section>
}

function LazyDetails({ summary, children }: { summary: string; children: () => ReactNode }) {
  const [open, setOpen] = useState(false)
  return <details onToggle={(event) => setOpen(event.currentTarget.open)}><summary>{summary}</summary>{open && children()}</details>
}

function PagedList<T>({ items, render }: { items: T[]; render: (item: T) => ReactNode }) {
  const [page, setPage] = useState(1)
  return <><ul>{items.slice((page - 1) * 30, page * 30).map((item, index) => <li key={(page - 1) * 30 + index}>{render(item)}</li>)}</ul>
    {items.length > 30 && <div className="report-pager"><button type="button" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous details</button><span>Page {page} of {Math.ceil(items.length / 30)}</span><button type="button" disabled={page * 30 >= items.length} onClick={() => setPage((value) => value + 1)}>Next details</button></div>}</>
}
