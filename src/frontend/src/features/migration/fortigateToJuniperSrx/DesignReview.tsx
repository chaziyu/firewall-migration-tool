import { useCallback, useMemo, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { isReviewable } from './reviewSelection'
import type { SrxPlanItem } from './types'

export function SrxDesignReview({ items, busy, selected, onSelect, approvalKeys, onPreview, onApprove, onCancel, onSetup }: {
  items: SrxPlanItem[]
  busy: boolean
  selected: string[]
  onSelect: (keys: string[]) => void
  approvalKeys: string[] | null
  onPreview: (keys: string[]) => void
  onApprove: () => void
  onCancel: () => void
  onSetup: () => void
}) {
  const [status, setStatus] = useState('ready')
  const [family, setFamily] = useState('all')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [detailsKey, setDetailsKey] = useState('')
  const [approvalPage, setApprovalPage] = useState(1)
  const focusPreview = useCallback((element: HTMLElement | null) => element?.focus(), [])
  const byKey = useMemo(() => new Map(items.map((item) => [item.key, item])), [items])
  const selectedKeys = new Set(selected)
  const ready = items.filter(isReviewable)
  const families = [...new Set(items.map((item) => item.family))].sort()
  const filtered = items.filter((item) => (status === 'all' || (status === 'ready' ? isReviewable(item) : !isReviewable(item)))
    && (family === 'all' || item.family === family)
    && `${item.source_vdom} ${item.source_name} ${item.target_name} ${item.blockers.join(' ')}`.toLowerCase().includes(search.trim().toLowerCase()))
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const currentPage = Math.min(page, pages)
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize)
  const matchingReady = filtered.filter(isReviewable)
  const previewItems = (approvalKeys ?? []).map((key) => byKey.get(key)).filter((item): item is SrxPlanItem => !!item)
  const approvalPages = Math.max(1, Math.ceil(previewItems.length / pageSize))
  const currentApprovalPage = Math.min(approvalPage, approvalPages)
  const previewBlocked = previewItems.length !== approvalKeys?.length || previewItems.some((item) => !isReviewable(item))
  const preview = (keys: string[]) => { setApprovalPage(1); onPreview(keys) }
  const prerequisites = (item: SrxPlanItem) => item.dependencies.map((key) => {
    const parent = byKey.get(key)
    return parent ? `${parent.source_vdom} / ${parent.source_name} · ${parent.family}` : key
  })
  return <section className="migration-changes" aria-label="Juniper SRX design review">
    <div className="conversion-status" aria-label="Migration status"><span>Ready {ready.length.toLocaleString()}</span><span>Blocked / manual {(items.length - ready.length).toLocaleString()}</span></div>
    {approvalKeys ? <section className="migration-approval-preview" aria-label="SRX approval preview" tabIndex={-1} ref={focusPreview}>
      <h3>Review selection</h3>
      <p>{approvalKeys.length.toLocaleString()} items, including required dependencies and atomic groups. Approval includes exact values and operations.</p>
      <p>{ready.length - previewItems.length} ready items not selected · {items.length - ready.length} items need attention.</p>
      <ul aria-label="Selected configuration families">{families.map((name) => {
        const count = previewItems.filter((item) => item.family === name).length
        return count ? <li key={name}>{name.replaceAll('_', ' ')}: {count}</li> : null
      })}</ul>
      {previewItems.slice((currentApprovalPage - 1) * pageSize, currentApprovalPage * pageSize).map((item) => <article className="migration-proposal-row" key={item.key}>
        <p>{item.source_vdom} / {item.source_name} → <strong>{item.target_name}</strong> · {item.render_disposition}</p>
        <p>Included in this approval</p>
        <p>{Object.entries(item.settings).map(([field, value]) => `${field.replaceAll('_', ' ')}: ${value == null ? 'Not explicitly configured' : Array.isArray(value) ? `${value.length} values (see exact settings)` : typeof value === 'object' ? JSON.stringify(value) : String(value)}`).join(' · ')}</p>
        <details><summary>Exact settings and prerequisites</summary><pre>{JSON.stringify({ settings: item.settings, dependencies: prerequisites(item), approval_group: item.approval_group }, null, 2)}</pre></details>
      </article>)}
      <div className="report-pager"><Button disabled={busy || currentApprovalPage <= 1} onClick={() => setApprovalPage(currentApprovalPage - 1)}>Previous approval page</Button><span>Page {currentApprovalPage} of {approvalPages}</span><Button disabled={busy || currentApprovalPage >= approvalPages} onClick={() => setApprovalPage(currentApprovalPage + 1)}>Next approval page</Button></div>
      {previewBlocked && <p role="alert">Resolve blocked or missing prerequisites before approval.</p>}
      <div className="action-row"><Button disabled={busy || !approvalKeys.length || previewBlocked} onClick={onApprove}>Approve selection and generate commands</Button><Button className="secondary-button" disabled={busy} onClick={onCancel}>Back to changes</Button></div>
    </section> : <>
      <div className="action-row"><Button disabled={busy || !ready.length} onClick={() => preview(ready.map((item) => item.key))}>Review all ready changes ({ready.length.toLocaleString()})</Button>
        {(status !== 'ready' || family !== 'all' || search.trim()) && <Button className="secondary-button" disabled={busy || !matchingReady.length} onClick={() => preview(matchingReady.map((item) => item.key))}>Review matching changes ({matchingReady.length.toLocaleString()})</Button>}
        {!!selected.length && <Button className="secondary-button" disabled={busy} onClick={() => preview(selected)}>Review selected ({selected.length})</Button>}
        <Button className="secondary-button" disabled={busy} onClick={onSetup}>Resolve target inputs</Button></div>
      {!!selected.length && <p role="status">{selected.length} selected across all pages and filters · {selected.filter((key) => !visible.some((item) => item.key === key)).length} outside this page.</p>}
      <details className="migration-type-summary"><summary>Configuration by type</summary><div className="report-table-wrap"><table className="report-table"><caption>Configuration by type</caption><thead><tr><th>Type</th><th>Ready</th><th>Blocked / manual</th></tr></thead><tbody>{families.map((name) => {
        const rows = items.filter((item) => item.family === name)
        const count = rows.filter(isReviewable).length
        return <tr key={name}><td><button type="button" className="text-button" aria-pressed={family === name} onClick={() => { setFamily(name); setPage(1) }}>{name.replaceAll('_', ' ')}</button></td><td>{count}</td><td>{rows.length - count}</td></tr>
      })}</tbody></table></div></details>
      <div className="migration-toolbar">
        <label className="field">Status<select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1) }}><option value="ready">Ready</option><option value="blocked">Blocked / manual</option><option value="all">All</option></select></label>
        <label className="field">Type<select value={family} onChange={(event) => { setFamily(event.target.value); setPage(1) }}><option value="all">All</option>{families.map((name) => <option key={name} value={name}>{name.replaceAll('_', ' ')}</option>)}</select></label>
        <label className="field">Search<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} placeholder="Source or target name, or blocker" /></label>
      </div>
      {!filtered.length && <p>No matching changes.</p>}
      {visible.map((item) => <article className="migration-proposal-row" key={item.key}>
        <label><input type="checkbox" aria-label={`Select ${item.source_vdom} ${item.source_name}`} disabled={busy || !isReviewable(item)} checked={selectedKeys.has(item.key)} onChange={(event) => onSelect(event.target.checked ? [...selected, item.key] : selected.filter((key) => key !== item.key))} /> {item.source_vdom} / {item.source_name} · {item.family.replaceAll('_', ' ')}</label>
        <p><strong>{item.target_name}</strong> · {item.render_disposition}</p>
        <button type="button" className="text-button" aria-expanded={detailsKey === item.key} onClick={() => setDetailsKey(detailsKey === item.key ? '' : item.key)}>{detailsKey === item.key ? 'Close' : 'Details'}</button>
        {detailsKey === item.key && <div className="migration-proposal-detail">
          {!!item.blockers.length && <ul>{item.blockers.map((code) => <li key={code}>{code.toLowerCase().replaceAll('_', ' ')}</li>)}</ul>}
          {!!item.guidance.length && <pre>{JSON.stringify(item.guidance, null, 2)}</pre>}
          <details><summary>Exact configuration values</summary><pre>{JSON.stringify(item.settings, null, 2)}</pre></details>
          <details><summary>Prerequisites ({item.dependencies.length})</summary><ul>{prerequisites(item).map((label, index) => <li key={index}>{label}</li>)}</ul><p>Atomic group: {item.approval_group ?? 'None'}</p></details>
        </div>}
      </article>)}
      <div className="report-pager migration-changes-pager"><label>Rows per page <select aria-label="Changes per page" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1) }}>{[25, 50, 100].map((size) => <option key={size} value={size}>{size}</option>)}</select></label>
        <Button disabled={busy || currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous</Button><span>Page {currentPage} of {pages} · {filtered.length.toLocaleString()} changes</span><Button disabled={busy || currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next</Button>
        <label>Go to page <input aria-label="Changes page" type="number" min={1} max={pages} value={currentPage} onChange={(event) => { const value = Number(event.target.value); if (Number.isInteger(value) && value >= 1) setPage(Math.min(value, pages)) }} /></label>
      </div>
    </>}
  </section>
}
