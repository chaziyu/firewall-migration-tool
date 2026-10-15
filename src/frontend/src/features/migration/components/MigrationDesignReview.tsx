import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { DraftRow, MigrationDraft } from '../types'
import { draftDependencies, draftRowKey } from '../reviewDrafts'
import { draftReviewRows, draftStatusCounts, taskCategory } from '../reviewPresentation'
import { Button } from '../../../components/common/Button'

export function MigrationDesignReview({ draft, busy, approvedItems, onApprove, onRenameService, onResolveSettings }: {
  draft: MigrationDraft
  busy: boolean
  approvedItems: string[]
  onApprove: (groups: string[]) => void
  onRenameService?: (row: DraftRow, name: string) => void
  onResolveSettings?: (group: 'management' | 'vpn' | 'policy') => void
}) {
  const [selected, setSelected] = useState<string[]>([])
  const [filter, setFilter] = useState('READY')
  const [family, setFamily] = useState('all')
  const [search, setSearch] = useState('')
  const [detailsKey, setDetailsKey] = useState('')
  const [approvalPreview, setApprovalPreview] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const keyFor = draftRowKey
  const approved = useMemo(() => new Set(approvedItems), [approvedItems])
  const isApproved = (row: DraftRow) => row.approved || approved.has(row.item_key || row.decision_key || '')
  const rows = useMemo(() => [...draft.decisions, ...draft.configuration], [draft])
  const byKey = useMemo(() => new Map(rows.map((row) => [draftRowKey(row), row])), [rows])
  const ready = useMemo(() => rows.filter((row) => row.status === 'READY' && !row.approved && !approved.has(row.item_key || row.decision_key || '')), [rows, approved])
  const filtered = useMemo(() => draftReviewRows(rows, filter, family, search, new Set(), approved)
    .filter((row) => !row.decision_key)
    .sort((a, b) => (a.operation || '').localeCompare(b.operation || '') || (a.family || a.source_kind || '').localeCompare(b.family || b.source_kind || '')), [rows, filter, family, search, approved])
  const mappingCounts = draftStatusCounts(draft.decisions.filter((row) => !isApproved(row)))
  const configurationCounts = draftStatusCounts(draft.configuration.filter((row) => !isApproved(row)))
  const pendingSelection = selected.filter((key) => byKey.has(key) && !isApproved(byKey.get(key)!))
  const previewPending = approvalPreview.some((key) => !byKey.has(key) || !isApproved(byKey.get(key)!))
  const families = [...new Set(draft.configuration.map((row) => row.family || row.source_kind))].sort()
  const pages = Math.max(1, Math.ceil(filtered.length / 30))
  const currentPage = Math.min(page, pages)
  const preview = (keys: string[]) => setApprovalPreview(draftDependencies(byKey, keys, approvedItems))
  const previewKeys = useMemo(() => new Set(approvalPreview), [approvalPreview])
  const approvalBlocked = approvalPreview.some((key) => !byKey.has(key) || (byKey.get(key)?.status !== 'READY' && !isApproved(byKey.get(key)!)))
  return <section aria-label="Deterministic design review" className="review-work-card">
    <h3>Conversion coverage</h3>
    <p>Review the included configuration and exclusions. Final approval includes the required mappings and their exact proposed values.</p>
    <p>{draft.destination_verified ? 'Checked against the uploaded destination configuration.' : 'Offline export: destination collisions, hardware capacity and licensing remain unverified.'}</p>
    <div className="migration-summary">
      <p><strong>Mappings</strong><br />{mappingCounts.READY || 0} ready · {mappingCounts.NEEDS_INPUT || 0} need input · {mappingCounts.CONFLICT || 0} conflicts · {draft.decisions.filter(isApproved).length} approved</p>
      <p><strong>Configuration items</strong><br />{configurationCounts.READY || 0} ready · {configurationCounts.NEEDS_INPUT || 0} blocked · {configurationCounts.CONFLICT || 0} conflicts · {configurationCounts.UNSUPPORTED || 0} manual · {draft.configuration.filter(isApproved).length} approved</p>
    </div>
    {!!draft.findings.some((row) => row.code === 'SHARED_ACTION') && <details><summary>Shared actions for remaining configuration</summary>
      <p>Resolve these shared causes once, then apply settings and review the rebuilt configuration. Counts overlap.</p>
      {onResolveSettings && <div className="action-row">
        {draft.findings.some((row) => row.code === 'MANAGEMENT_PROFILE_GROUP') && <Button className="secondary-button" onClick={() => onResolveSettings('management')}>Review management access</Button>}
        {draft.findings.some((row) => ['VPN_PREREQUISITE', 'VPN_PARAMETERS_REQUIRED'].includes(row.code)) && <Button className="secondary-button" onClick={() => onResolveSettings('vpn')}>Review VPN decisions</Button>}
        {draft.findings.some((row) => ['IDENTITY_MAPPING_REQUIRED', 'SECURITY_PROFILE_REQUIRED'].includes(row.code)) && <Button className="secondary-button" onClick={() => onResolveSettings('policy')}>Review policy decisions</Button>}
      </div>}
      <ul>{draft.findings.filter((row) => row.code === 'SHARED_ACTION').map((row) => <li key={row.identity}>
        <strong>{row.source_vdom} · {row.automation_category?.replaceAll('_', ' ').toLowerCase()}</strong>: {row.message} ({row.member_keys?.length} configuration items)
      </li>)}</ul>
    </details>}
    <div className="report-table-wrap"><table className="report-table"><caption>Conversion coverage by configuration family</caption>
      <thead><tr><th>Configuration</th><th>Ready for review</th><th>Blocked</th><th>Manual work</th><th>Approved</th></tr></thead>
      <tbody>{families.map((name) => { const items = draft.configuration.filter((row) => (row.family || row.source_kind) === name)
        return <tr key={name}><td>{name.replaceAll('_', ' ')}</td>{['Ready for review', 'Blocked', 'Manual work', 'Approved'].map((category) =>
          <td key={category}>{items.filter((row) => { const state = taskCategory(row, byKey, approved); return category === 'Blocked' ? state === 'Blocked' || state === 'Needs decision' : state === category }).length}</td>)}</tr>
      })}</tbody>
    </table></div>
    <div className="migration-toolbar">
      <Button className={approvalPreview.length ? 'secondary-button' : ''} disabled={busy || !ready.length} onClick={() => preview(ready.map(keyFor))}>Review all ready changes ({ready.filter((row) => !row.decision_key).length} configuration items)</Button>
      <Button className="secondary-button" disabled={busy || !pendingSelection.length} onClick={() => preview(pendingSelection)}>Review selected items and prerequisites</Button>
      <label className="field">Show proposals<select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(1) }}>
        <option value="READY">Ready for review</option><option value="APPROVED">Approved</option><option value="BLOCKED">Blocked by prerequisites</option><option value="all">All proposals</option><option value="NEEDS_INPUT">Needs decision</option><option value="CONFLICT">Conflicts</option><option value="UNSUPPORTED">Manual work</option>
      </select></label>
      <label className="field">Family<select value={family} onChange={(event) => { setFamily(event.target.value); setPage(1) }}><option value="all">All families</option>{families.map((value) => <option key={value}>{value}</option>)}</select></label>
      <label className="field">Search proposals<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Source or target name" /></label>
    </div>
    {!!approvalPreview.length && previewPending && <section className="migration-approval-preview" aria-label="Approval preview">
      <h4>Review {approvalPreview.length} exact proposal groups</h4>
      <p>{approvalPreview.filter((key) => byKey.get(key)?.decision_key).length} mapping decisions · {approvalPreview.filter((key) => !byKey.get(key)?.decision_key).length} configuration items. Prerequisites are included.</p>
      <p>{ready.filter((row) => !previewKeys.has(keyFor(row)) && !row.decision_key).length} ready configuration items are not selected. {draft.configuration.filter((row) => row.status !== 'READY' && !isApproved(row)).length} configuration items still need attention.</p>
      {approvalPreview.filter((key) => !byKey.get(key)?.decision_key).length === 1 && <p role="status">Only one configuration item is selected. Use Review all ready changes to include the rest of the ready configuration.</p>}
      <ul aria-label="Selected configuration families">{families.map((name) => {
        const count = draft.configuration.filter((row) => (row.family || row.source_kind) === name && previewKeys.has(keyFor(row))).length
        return count ? <li key={name}>{name.replaceAll('_', ' ')}: {count}</li> : null
      })}</ul>
      <PagedList items={approvalPreview} render={(key) => { const row = byKey.get(key); return row ? <div><p>{row.source_vdom} / {row.source_name} · {row.target_field || row.family} → <strong>{row.proposed_value || row.target_name || 'Unresolved'}</strong> · {row.target_scope || 'Scope unresolved'} · {row.operation || row.status}</p>
        {row.configuration && <><p>{Object.entries(row.configuration).filter(([field, value]) => !['warnings', 'status', 'source_vdom', 'source_kind', 'source_name', 'source_object_type', 'target_vsys', 'target_name'].includes(field) && value != null).map(([field, value]) => `${field.replaceAll('_', ' ')}: ${Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : String(value)}`).join(' · ')}</p><LazyDetails summary="Exact configuration values">{() => <pre>{JSON.stringify(row.configuration, null, 2)}</pre>}</LazyDetails></>}
        <p>Prerequisites: {row.dependencies.map((key) => { const dependency = byKey.get(key); return dependency ? `${dependency.source_vdom} / ${dependency.source_name} · ${dependency.target_field || dependency.family}` : 'Unresolved prerequisite' }).join('; ') || 'None'}</p>
      </div> : 'Unresolved prerequisite'  }} />
      {approvalBlocked && <p role="alert">This selection contains unresolved prerequisites. Resolve them before approval.</p>}
      <div className="action-row"><Button disabled={busy || approvalBlocked} onClick={() => onApprove(approvalPreview)}>Approve selected changes</Button>
      <Button className="secondary-button" onClick={() => setApprovalPreview([])}>Cancel approval</Button></div>
    </section>}
    <p className="report-count-note">Approval includes the shown values, operations, configuration and prerequisites. Unresolved groups stay blocked.</p>
    {rows.some((row) => row.status === 'UNSUPPORTED') && <p role="status">Unsupported work requires manual implementation. Approving ready groups leaves a partial migration.</p>}
    {!filtered.length && <p>No proposals match these filters. Ready configuration and manual work are available in Show proposals.</p>}
    {filtered.slice((currentPage - 1) * 30, currentPage * 30).map((row) => <article key={keyFor(row)} className="migration-proposal-row">
      <label><input type="checkbox" checked={!isApproved(row) && selected.includes(keyFor(row))} disabled={busy || row.status !== 'READY' || isApproved(row)}
        onChange={(event) => setSelected((keys) => event.target.checked ? [...keys, keyFor(row)] : keys.filter((key) => key !== keyFor(row)))} /> {row.source_vdom} / {row.source_name} · {row.target_field || row.family}</label>
      <p><strong>{row.proposed_value || row.target_name || 'Needs input'}</strong> · {row.target_scope || 'Scope unresolved'} · {row.operation || row.status} {isApproved(row) ? '· Approved' : ''}</p>
      <button type="button" className="text-button" aria-expanded={detailsKey === keyFor(row)} onClick={() => setDetailsKey(detailsKey === keyFor(row) ? '' : keyFor(row))}>{detailsKey === keyFor(row) ? 'Close details' : 'Review details'}</button>
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
