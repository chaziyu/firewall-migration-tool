import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { DraftRow, MigrationDraft } from '../types'
import { draftDependencies, draftRowKey } from '../reviewDrafts'
import { draftReviewRows, draftStatusCounts, taskCategory } from '../reviewPresentation'
import { Button } from '../../../components/common/Button'

const CHANGES_PER_PAGE = 10

export function MigrationDesignReview({ draft, busy, approvedItems, onApprove, onRenameService, onSelectIssue }: {
  draft: MigrationDraft
  busy: boolean
  approvedItems: string[]
  onApprove: (groups: string[]) => void
  onRenameService?: (row: DraftRow, name: string) => void
  onSelectIssue?: (issueId: string) => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [filter, setFilter] = useState('READY')
  const [family, setFamily] = useState('all')
  const [search, setSearch] = useState('')
  const [detailsKey, setDetailsKey] = useState('')
  const [approvalPreview, setApprovalPreview] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const focusPreview = useCallback((element: HTMLElement | null) => element?.focus(), [])
  const keyFor = draftRowKey
  const approved = useMemo(() => new Set(approvedItems), [approvedItems])
  const isApproved = (row: DraftRow) => row.approved || approved.has(row.item_key || row.decision_key || '')
  const rows = useMemo(() => [...draft.decisions, ...draft.configuration], [draft])
  const byKey = useMemo(() => new Map(rows.map((row) => [draftRowKey(row), row])), [rows])
  const ready = useMemo(() => rows.filter((row) => row.status === 'READY' && !row.approved && !approved.has(row.item_key || row.decision_key || '')), [rows, approved])
  const filtered = useMemo(() => draftReviewRows(rows, filter, family, search, new Set(), approved)
    .filter((row) => !row.decision_key)
    .sort((a, b) => (a.operation || '').localeCompare(b.operation || '') || (a.family || a.source_kind || '').localeCompare(b.family || b.source_kind || '')), [rows, filter, family, search, approved])
  const pendingSelection = selected.filter((key) => byKey.has(key) && !isApproved(byKey.get(key)!))
  const previewPending = approvalPreview.some((key) => !byKey.has(key) || !isApproved(byKey.get(key)!))
  const families = [...new Set(draft.configuration.map((row) => row.family || row.source_kind))].sort()
  const pages = Math.max(1, Math.ceil(filtered.length / CHANGES_PER_PAGE))
  const currentPage = Math.min(page, pages)
  const preview = (keys: string[]) => setApprovalPreview(draftDependencies(byKey, keys, approvedItems))
  const previewKeys = useMemo(() => new Set(approvalPreview), [approvalPreview])
  const approvalBlocked = approvalPreview.some((key) => !byKey.has(key) || (byKey.get(key)?.status !== 'READY' && !isApproved(byKey.get(key)!)))
  const showPreview = approvalPreview.length > 0 && previewPending
  return <section aria-label="Deterministic design review" className="migration-changes">
    {rows.some((row) => row.status === 'UNSUPPORTED') && <p role="status">Manual items are excluded.</p>}
    {!showPreview && <>
    <div className="action-row">
      <Button id="review-ready" disabled={busy || !ready.length} onClick={() => preview(ready.map(keyFor))}>Review ready ({ready.filter((row) => !row.decision_key).length})</Button>
      {!!pendingSelection.length && <Button className="secondary-button" disabled={busy} onClick={() => preview(pendingSelection)}>Review selected ({pendingSelection.length})</Button>}
    </div>
    <div className="migration-toolbar">
      <label className="field">Status<select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(1) }}>
        <option value="READY">Ready</option><option value="APPROVED">Approved</option><option value="BLOCKED">Blocked</option><option value="all">All</option><option value="NEEDS_INPUT">Needs input</option><option value="CONFLICT">Conflicts</option><option value="UNSUPPORTED">Manual</option>
      </select></label>
      <label className="field">Type<select value={family} onChange={(event) => { setFamily(event.target.value); setPage(1) }}><option value="all">All</option>{families.map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select></label>
      <label className="field">Search<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Source or target name" /></label>
    </div>
    </>}
    {showPreview && <section className="migration-approval-preview" aria-label="Approval preview" tabIndex={-1} ref={focusPreview}>
      <h3>Review selection</h3>
      <p>Configuration: {approvalPreview.filter((key) => !byKey.get(key)?.decision_key).length} · Mappings: {approvalPreview.filter((key) => byKey.get(key)?.decision_key).length}. Prerequisites included.</p>
      <p>{ready.filter((row) => !previewKeys.has(keyFor(row)) && !row.decision_key).length} ready items not selected · {draft.configuration.filter((row) => row.status !== 'READY' && !isApproved(row)).length} items need attention.</p>
      {approvalPreview.filter((key) => !byKey.get(key)?.decision_key).length === 1 && <p role="status">One item selected. Go back to review all ready items.</p>}
      <ul aria-label="Selected configuration families">{families.map((name) => {
        const count = draft.configuration.filter((row) => (row.family || row.source_kind) === name && previewKeys.has(keyFor(row))).length
        return count ? <li key={name}>{name.replaceAll('_', ' ')}: {count}</li> : null
      })}</ul>
      <PagedList items={approvalPreview} render={(key) => { const row = byKey.get(key); return row ? <div><p>{row.source_vdom} / {row.source_name} · {row.target_field || row.family} → <strong>{row.proposed_value || row.target_name || 'Unresolved'}</strong> · {row.target_scope || 'Scope unresolved'} · {row.operation || row.status}</p>
        {row.configuration && <><p>{Object.entries(row.configuration).filter(([field, value]) => !['warnings', 'status', 'source_vdom', 'source_kind', 'source_name', 'source_object_type', 'target_vsys', 'target_name'].includes(field) && value != null).map(([field, value]) => `${field.replaceAll('_', ' ')}: ${Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : String(value)}`).join(' · ')}</p><LazyDetails summary="Exact configuration values">{() => <pre>{JSON.stringify(row.configuration, null, 2)}</pre>}</LazyDetails></>}
        <p>Prerequisites: {row.dependencies.map((key) => { const dependency = byKey.get(key); return dependency ? `${dependency.source_vdom} / ${dependency.source_name} · ${dependency.target_field || dependency.family}` : 'Unresolved prerequisite' }).join('; ') || 'None'}</p>
      </div> : 'Unresolved prerequisite'  }} />
      {approvalBlocked && <p role="alert">Resolve prerequisites before approval.</p>}
      <div className="action-row"><Button disabled={busy || approvalBlocked} onClick={() => onApprove(approvalPreview)}>Approve selection</Button>
      <Button className="secondary-button" onClick={() => { setApprovalPreview([]); requestAnimationFrame(() => document.getElementById('review-ready')?.focus()) }}>Back</Button></div>
    </section>}
    {!showPreview && <>
    {!filtered.length && <p>No matching changes.</p>}
    {filtered.slice((currentPage - 1) * CHANGES_PER_PAGE, currentPage * CHANGES_PER_PAGE).map((row) => <article key={keyFor(row)} className="migration-proposal-row">
      <label><input type="checkbox" checked={!isApproved(row) && selected.includes(keyFor(row))} disabled={busy || row.status !== 'READY' || isApproved(row)}
        onChange={(event) => setSelected((keys) => event.target.checked ? [...keys, keyFor(row)] : keys.filter((key) => key !== keyFor(row)))} /> {row.source_vdom} / {row.source_name} · {row.target_field || row.family}</label>
      <p><strong>{row.proposed_value || row.target_name || 'Needs input'}</strong> · {row.target_scope || 'Scope unresolved'} · {row.operation || row.status} {isApproved(row) ? '· Approved' : ''}</p>
      <button type="button" className="text-button" aria-expanded={detailsKey === keyFor(row)} onClick={() => setDetailsKey(detailsKey === keyFor(row) ? '' : keyFor(row))}>{detailsKey === keyFor(row) ? 'Close' : 'Details'}</button>
      {detailsKey === keyFor(row) && <div className="migration-proposal-detail">
      {!!row.evidence?.length && <p>{row.evidence.join('; ')}</p>}
      {!!row.blocking_reasons.length && <p role="status">{row.blocking_reasons.map((reason) => reason.startsWith('Unresolved prerequisite:') ? 'Resolve the prerequisites shown below.' : reason).join('; ')}</p>}
      {row.family === 'service' && row.configuration?.status === 'SUPPORTED' && onRenameService && <form onSubmit={(event) => { event.preventDefault(); const name = new FormData(event.currentTarget).get('service-name')?.toString().trim(); if (name) onRenameService(row, name) }}>
        <p>Planned service: {String(row.configuration.protocol ?? 'Protocol not explicit')} · destination port {String(row.configuration.destination_port ?? 'Not explicit')}{row.configuration.source_port != null ? ` · source port ${row.configuration.source_port}` : ''}</p>
        {row.target_comparison && <p>Destination comparison: {row.target_comparison.status} · {row.target_comparison.target_scope || 'Scope unresolved'}. {row.target_comparison.evidence?.join('; ')}</p>}
        <p>Create under a distinct name. Existing destination services are preserved; dependent references will be rebuilt.</p>
        <label className="field">Target service name<input name="service-name" defaultValue={row.target_name || row.source_name} required maxLength={63} disabled={busy} /></label>
        <button type="submit" disabled={busy}>Propose service name</button>
      </form>}
      {row.configuration && <dl className="configuration-comparison">{Object.entries(row.configuration).filter(([field, value]) => ['from_zones', 'to_zones', 'sources', 'destinations', 'services', 'applications', 'action', 'source_policy_id', 'translated_address', 'translated_port', 'destination', 'nexthop', 'ip', 'interface', 'members'].includes(field) && value != null).map(([field, value]) => <div key={field}><dt>{field.replaceAll('_', ' ')}</dt><dd>{Array.isArray(value) ? value.join(', ') : String(value)}</dd></div>)}</dl>}
      {row.configuration && <LazyDetails summary="Affected configuration">{() => <pre>{JSON.stringify(row.configuration, null, 2)}</pre>}</LazyDetails>}
      {!!row.dependencies.length && <LazyDetails summary={`Prerequisites (${row.dependencies.length})`}>{() => <PagedList items={row.dependencies} render={(key) => { const parent = byKey.get(key); return parent ? `${parent.source_vdom} / ${parent.source_name} · ${parent.target_field || parent.family}` : key }} />}</LazyDetails>}
      </div>}
    </article>)}
    {filtered.length > CHANGES_PER_PAGE && <div className="report-pager"><button type="button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous</button><span>Page {currentPage} of {pages} · {filtered.length} changes</span><button type="button" disabled={currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next</button></div>}
    </>}
    <LazyDetails summary="By type">{() => <div className="report-table-wrap"><table className="report-table"><caption>Configuration by type</caption>
      <thead><tr><th>Type</th><th>Ready</th><th>Blocked</th><th>Manual</th><th>Approved</th></tr></thead>
      <tbody>{families.map((name) => { const items = draft.configuration.filter((row) => (row.family || row.source_kind) === name)
        return <tr key={name}><td>{name.replaceAll('_', ' ')}</td>{['Ready for review', 'Blocked', 'Manual work', 'Approved'].map((category) =>
          <td key={category}>{items.filter((row) => { const state = taskCategory(row, byKey, approved); return category === 'Blocked' ? state === 'Blocked' || state === 'Needs decision' : state === category }).length}</td>)}</tr>
      })}</tbody>
    </table></div>}</LazyDetails>
    {!!draft.issues?.some((issue) => issue.action?.kind === 'EDIT_SETTINGS') && <details><summary>Decisions related to these changes</summary>
      <ul>{draft.issues.filter((issue) => issue.action?.kind === 'EDIT_SETTINGS').map((issue) => <li key={issue.id}>
        {issue.source_vdom} / {issue.source_name}: {issue.explanation} {onSelectIssue && <Button className="text-button" onClick={() => onSelectIssue(issue.id)}>Open decision</Button>}
      </li>)}</ul>
    </details>}
    {!!draft.findings.length && <LazyDetails summary={`Technical findings (${draft.findings.length})`}>{() => <PagedList items={draft.findings} render={(row) => `${row.code}: ${row.message}`} />}</LazyDetails>}
  </section>
}

export function MigrationDesignSummary({ draft, approvedItems }: { draft: MigrationDraft; approvedItems: string[] }) {
  const rows = [...draft.decisions, ...draft.configuration]
  const byKey = new Map(rows.map((row) => [draftRowKey(row), row]))
  const approved = new Set(approvedItems)
  const isApproved = (row: DraftRow) => row.approved || approved.has(row.item_key || row.decision_key || '')
  const excludedInterfaces = draft.context.conversion_settings?.excluded_interfaces ?? []
  const counts = { ready: 0, blocked: 0, excluded: 0, approved: 0 }
  for (const row of draft.configuration) {
    if (row.source_kind === 'interface' && excludedInterfaces.includes(`${row.source_vdom}/${row.source_name}`)) { counts.excluded++; continue }
    if (isApproved(row)) { counts.approved++; continue }
    const category = taskCategory(row, byKey, approved)
    if (category === 'Ready for review') counts.ready++
    else if (category === 'Manual work') counts.excluded++
    else counts.blocked++
  }
  const mappingCounts = draftStatusCounts(draft.decisions)
  return <div className="conversion-status" aria-label="Migration status">
    <span>Ready {counts.ready}</span><span>Blocked {counts.blocked}</span><span>Excluded {counts.excluded}</span><span>Approved {counts.approved}</span>
    <details><summary>Details</summary>
      <p>{draft.destination_verified ? 'Destination checked against uploaded configuration.' : 'Destination collisions, hardware capacity and licensing remain unverified.'}</p>
      <p>Mappings: {mappingCounts.READY || 0} ready · {mappingCounts.NEEDS_INPUT || 0} need input · {mappingCounts.CONFLICT || 0} conflicts · {draft.decisions.filter(isApproved).length} approved</p>
      <p>Excluded items include unsupported features and explicitly excluded interfaces. Approval includes exact values, operations and prerequisites.</p>
    </details>
  </div>
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
