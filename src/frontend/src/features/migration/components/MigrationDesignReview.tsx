import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { DraftRow, MigrationDraft } from '../types'
import { draftDependencies, draftRowKey, portExceptionGroups } from '../reviewDrafts'
import { draftReviewRows, draftStatusCounts } from '../reviewPresentation'

export function MigrationDesignReview({ draft, busy, approvedItems, onPrepare, onApprove, onRenameService }: {
  draft: MigrationDraft
  busy: boolean
  approvedItems: string[]
  onPrepare: (overrides: Record<string, string>) => void
  onApprove: (groups: string[]) => void
  onRenameService?: (row: DraftRow, name: string) => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [filter, setFilter] = useState('ACTIONABLE')
  const [family, setFamily] = useState('all')
  const [search, setSearch] = useState('')
  const [detailsKey, setDetailsKey] = useState('')
  const [approvalPreview, setApprovalPreview] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const keyFor = draftRowKey
  const approved = useMemo(() => new Set(approvedItems), [approvedItems])
  const isApproved = (row: DraftRow) => row.approved || Boolean(row.item_key && approved.has(row.item_key))
  const rows = useMemo(() => [...draft.decisions, ...draft.configuration], [draft])
  const byKey = useMemo(() => new Map(rows.map((row) => [draftRowKey(row), row])), [rows])
  const ready = useMemo(() => rows.filter((row) => row.status === 'READY' && !row.approved && !(row.item_key && approved.has(row.item_key))), [rows, approved])
  const portGroups = useMemo(() => portExceptionGroups(rows), [rows])
  const grouped = useMemo(() => new Set([...portGroups.values()].flat().map(draftRowKey)), [portGroups])
  const filtered = useMemo(() => draftReviewRows(rows, filter, family, search, grouped), [rows, grouped, filter, family, search])
  const mappingCounts = draftStatusCounts(draft.decisions)
  const configurationCounts = draftStatusCounts(draft.configuration)
  const families = [...new Set(rows.map((row) => row.family || row.source_kind))].sort()
  const pages = Math.max(1, Math.ceil(filtered.length / 30))
  const currentPage = Math.min(page, pages)
  const preview = (keys: string[]) => setApprovalPreview(draftDependencies(byKey, keys, approvedItems))
  const approvalBlocked = approvalPreview.some((key) => !byKey.has(key) || (byKey.get(key)?.status !== 'READY' && !isApproved(byKey.get(key)!)))
  return <section aria-label="Deterministic design review" className="review-work-card">
    <h3>Proposed configuration</h3>
    <p>{draft.destination_verified ? 'Checked against the uploaded destination configuration.' : 'Destination unverified. Hardware capacity, licensing and collisions need destination evidence.'}</p>
    <div className="migration-summary">
      <p><strong>Mappings</strong><br />{mappingCounts.READY || 0} ready · {mappingCounts.NEEDS_INPUT || 0} need input · {mappingCounts.CONFLICT || 0} conflicts</p>
      <p><strong>Configuration items</strong><br />{configurationCounts.READY || 0} ready · {configurationCounts.NEEDS_INPUT || 0} blocked · {configurationCounts.CONFLICT || 0} conflicts · {configurationCounts.UNSUPPORTED || 0} manual</p>
    </div>
    <div className="migration-toolbar">
      <button type="button" className="primary-button" disabled={busy || !ready.length} onClick={() => preview(ready.map(keyFor))}>Review ready selection ({ready.length})</button>
      <button type="button" disabled={busy || !selected.length} onClick={() => preview(selected)}>Review selected items and prerequisites</button>
      <label className="field">Show proposals<select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(1) }}>
        <option value="ACTIONABLE">Resolve exceptions first</option><option value="all">All proposals</option><option value="NEEDS_INPUT">Needs decision</option><option value="CONFLICT">Conflicts</option><option value="UNSUPPORTED">Manual work</option><option value="READY">Ready for review</option>
      </select></label>
      <label className="field">Family<select value={family} onChange={(event) => { setFamily(event.target.value); setPage(1) }}><option value="all">All families</option>{families.map((value) => <option key={value}>{value}</option>)}</select></label>
      <label className="field">Search proposals<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Source or target name" /></label>
    </div>
    {!!approvalPreview.length && <section className="migration-approval-preview" aria-label="Approval preview">
      <h4>Review {approvalPreview.length} exact proposal groups</h4>
      <p>{approvalPreview.filter((key) => byKey.get(key)?.decision_key).length} mapping decisions · {approvalPreview.filter((key) => !byKey.get(key)?.decision_key).length} configuration items. Prerequisites are included.</p>
      <PagedList items={approvalPreview} render={(key) => { const row = byKey.get(key); return row ? `${row.source_vdom} / ${row.source_name} · ${row.target_field || row.family} → ${row.proposed_value || row.target_name || 'Unresolved'} · ${row.operation || row.status}` : key }} />
      {approvalBlocked && <p role="alert">This selection contains unresolved prerequisites. Resolve them before approval.</p>}
      <button type="button" className="primary-button" disabled={busy || approvalBlocked} onClick={() => { onApprove(approvalPreview); setApprovalPreview([]) }}>Approve reviewed selection</button>
      <button type="button" onClick={() => setApprovalPreview([])}>Cancel approval</button>
    </section>}
    <p className="report-count-note">Approval includes the shown values, operations, configuration and prerequisites. Unresolved groups stay blocked.</p>
    {rows.some((row) => row.status === 'UNSUPPORTED') && <p role="status">Unsupported work requires manual implementation. Approving ready groups leaves a partial migration.</p>}
    {!filtered.length && <p>No proposals match these filters. Ready configuration and manual work are available in Show proposals.</p>}
    {filtered.slice((currentPage - 1) * 30, currentPage * 30).map((row) => <article key={keyFor(row)} className="migration-proposal-row">
      <label><input type="checkbox" checked={selected.includes(keyFor(row))} disabled={busy || row.status !== 'READY' || isApproved(row)}
        onChange={(event) => setSelected((keys) => event.target.checked ? [...keys, keyFor(row)] : keys.filter((key) => key !== keyFor(row)))} /> {row.source_vdom} / {row.source_name} · {row.target_field || row.family}</label>
      <p><strong>{row.proposed_value || row.target_name || 'Needs input'}</strong> · {row.target_scope || 'Scope unresolved'} · {row.operation || row.status} {isApproved(row) ? '· Approved' : ''}</p>
      <button type="button" className="text-button" aria-expanded={detailsKey === keyFor(row)} onClick={() => setDetailsKey(detailsKey === keyFor(row) ? '' : keyFor(row))}>{detailsKey === keyFor(row) ? 'Close details' : 'Review details'}</button>
      {detailsKey === keyFor(row) && <div className="migration-proposal-detail">
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
      {row.family === 'service' && row.configuration?.status === 'SUPPORTED' && onRenameService && <form onSubmit={(event) => { event.preventDefault(); const name = new FormData(event.currentTarget).get('service-name')?.toString().trim(); if (name) onRenameService(row, name) }}>
        <p>Planned service: {String(row.configuration.protocol ?? 'Protocol not explicit')} · destination port {String(row.configuration.destination_port ?? 'Not explicit')}{row.configuration.source_port != null ? ` · source port ${row.configuration.source_port}` : ''}</p>
        {row.target_comparison && <p>Destination comparison: {row.target_comparison.status} · {row.target_comparison.target_scope || 'Scope unresolved'}. {row.target_comparison.evidence?.join('; ')}</p>}
        <p>Create under a distinct name. Existing destination services are preserved; dependent references will be rebuilt.</p>
        <label className="field">Target service name<input name="service-name" defaultValue={row.target_name || row.source_name} required maxLength={63} disabled={busy} /></label>
        <button type="submit" disabled={busy}>Propose service name</button>
      </form>}
      {row.configuration && <LazyDetails summary="Affected configuration">{() => <pre>{JSON.stringify(row.configuration, null, 2)}</pre>}</LazyDetails>}
      {!!row.dependencies.length && <LazyDetails summary={`Prerequisites (${row.dependencies.length})`}>{() => <PagedList items={row.dependencies} render={(key) => { const parent = byKey.get(key); return parent ? `${parent.source_vdom} / ${parent.source_name} · ${parent.target_field || parent.family}` : key }} />}</LazyDetails>}
      </div>}
    </article>)}
    {filtered.length > 30 && <div className="report-pager"><button type="button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous proposals</button><span>Page {currentPage} of {pages} · {filtered.length} proposals</span><button type="button" disabled={currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next proposals</button></div>}
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
