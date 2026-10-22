import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Button } from '../../../components/common/Button'
import { tabKeyboard } from '../../../components/common/tabKeyboard'

// Display values only. Pair controllers retain decisions and dependency expansion.
export type OfflineReviewRow = {
  key: string; family: string; sourceScope: string; sourceName: string; target: string
  operation: string; settings: unknown; dependencies: readonly string[]; reasons: readonly string[]; ready: boolean
}
export type OfflineReviewTab = 'changes' | 'decisions' | 'manual'

export function OfflineMigrationReview({ id, title, rows, busy, tab, onTabChange, inputCount, manualCount, issueContent,
  selected, onSelect, approvalKeys, onPreview, onApprove, onCancel, approvalContext, onSetup, approveLabel, findings = [] }: {
  id: string; title: string; rows: readonly OfflineReviewRow[]; busy: boolean
  tab: OfflineReviewTab; onTabChange: (tab: OfflineReviewTab) => void; inputCount: number; manualCount: number; issueContent: ReactNode
  selected: string[]; onSelect: (keys: string[]) => void; approvalKeys: string[] | null
  onPreview: (keys: string[]) => void; onApprove: () => void; onCancel: () => void; approvalContext: ReactNode
  onSetup: () => void; approveLabel: string
  findings?: readonly unknown[]
}) {
  const [status, setStatus] = useState('all')
  const [family, setFamily] = useState('all')
  const [scope, setScope] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [previewPage, setPreviewPage] = useState(1)
  const [findingPage, setFindingPage] = useState(1)
  const [focusRequested, setFocusRequested] = useState(false)
  const focusPreview = useCallback((node: HTMLElement | null) => { if (focusRequested) node?.focus() }, [focusRequested])
  const byKey = new Map(rows.map((row) => [row.key, row]))
  const ready = rows.filter((row) => row.ready)
  const defaults = useRef('')
  const readyKeys = JSON.stringify(ready.map((row) => row.key))
  useEffect(() => {
    if (busy || defaults.current === readyKeys) return
    defaults.current = readyKeys
    const keys: string[] = JSON.parse(readyKeys)
    onSelect(keys)
    if (keys.length) onPreview(keys)
  }, [busy, readyKeys, onSelect, onPreview])
  const selectedSet = new Set(selected)
  const previewSet = new Set(approvalKeys ?? [])
  const preview = (approvalKeys ?? []).flatMap((key) => byKey.get(key) ? [byKey.get(key)!] : [])
  const approvalBlocked = preview.length !== approvalKeys?.length
    || preview.some((row) => !row.ready || row.dependencies.some((key) => !previewSet.has(key)))
  const families = [...new Set(rows.map((row) => row.family))].sort()
  const scopes = [...new Set(rows.map((row) => row.sourceScope))].sort()
  const filtered = rows.filter((row) => (status === 'all' || row.ready === (status === 'ready'))
    && (family === 'all' || row.family === family)
    && (!scope || row.sourceScope === scope)
    && `${row.sourceScope} ${row.sourceName} ${row.target} ${row.family} ${row.reasons.join(' ')}`.toLowerCase().includes(search.trim().toLowerCase()))
  const pages = Math.max(1, Math.ceil(filtered.length / 25))
  const currentPage = Math.min(page, pages)
  const visible = filtered.slice((currentPage - 1) * 25, currentPage * 25)
  const previewPages = Math.max(1, Math.ceil(preview.length / 25))
  const currentPreviewPage = Math.min(previewPage, previewPages)
  const showPreview = (keys: string[], focus = true) => { setPreviewPage(1); setFocusRequested(focus); if (keys.length) onPreview(keys); else onCancel() }
  return <section className="offline-migration-review" aria-label={`${title} design review`}>
    <p>{preview.filter((row) => row.operation !== 'REUSE').length} included · {preview.filter((row) => row.operation === 'REUSE').length} reused · {ready.filter((row) => !previewSet.has(row.key)).length} excluded · {rows.length - ready.length} blocked or manual.</p>
    {!ready.length && <p role="status">No changes are ready to approve. Review shared blockers and the issue groups below.</p>}
    <Button className="secondary-button" disabled={busy} onClick={onSetup}>Edit target setup</Button>
    {!!findings.length && <details><summary>Technical findings ({findings.length})</summary>
      {findings.slice((findingPage - 1) * 25, findingPage * 25).map((finding, index) => <pre className="set-command-preview" key={index}>{JSON.stringify(finding, null, 2)}</pre>)}
      <div className="action-row"><Button disabled={findingPage <= 1} onClick={() => setFindingPage(findingPage - 1)}>Previous findings</Button><span>Page {findingPage} of {Math.ceil(findings.length / 25)}</span><Button disabled={findingPage * 25 >= findings.length} onClick={() => setFindingPage(findingPage + 1)}>Next findings</Button></div>
    </details>}
    <div role="tablist" aria-label={`${title} migration review`} className="migration-review-tabs" onKeyDown={tabKeyboard}>
      {([['changes', 'Changes', rows.length], ['decisions', 'Needs your input', inputCount], ['manual', 'Work outside this tool', manualCount]] as const).map(([value, label, count]) =>
        <button key={value} id={`${id}-tab-${value}`} role="tab" type="button" aria-selected={tab === value} aria-controls={`${id}-panel-${value}`} tabIndex={tab === value ? 0 : -1} onClick={() => onTabChange(value)}>{label} <span>{count}</span></button>)}
    </div>
    {tab !== 'changes' ? <section id={`${id}-panel-${tab}`} role="tabpanel" aria-labelledby={`${id}-tab-${tab}`}>{issueContent}</section> :
      <section id={`${id}-panel-changes`} role="tabpanel" aria-labelledby={`${id}-tab-changes`}>
        <div className="migration-toolbar">
          <label className="field">Find a configuration item<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} /></label>
          <label className="field">Review status<select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1) }}><option value="all">All</option><option value="ready">Ready</option><option value="blocked">Blocked and manual</option></select></label>
          <label className="field">Configuration type<select value={family} onChange={(event) => { setFamily(event.target.value); setPage(1) }}><option value="all">All types</option>{families.map((name) => <option key={name} value={name}>{name.replaceAll('_', ' ')}</option>)}</select></label>
          <label className="field">Source scope<select value={scope} onChange={(event) => { setScope(event.target.value); setPage(1) }}><option value="">All scopes</option>{scopes.map((name) => <option key={name} value={name}>{name}</option>)}</select></label>
        </div>
        <div className="action-row">
          <label><input type="checkbox" aria-label="Select all ready changes" disabled={busy || !ready.length} checked={ready.length > 0 && ready.every((row) => selectedSet.has(row.key))} onChange={(event) => { const keys = event.target.checked ? ready.map((row) => row.key) : []; onSelect(keys); showPreview(keys, false) }} /> Select all ready changes ({ready.length})</label>
          <Button disabled={busy || !ready.length} onClick={() => { onSelect(ready.map((row) => row.key)); showPreview(ready.map((row) => row.key)) }}>Review all ready changes</Button>
          <Button disabled={busy || !selected.length} onClick={() => showPreview(selected)}>Review selected changes</Button>
        </div>
        {!!selected.length && <p role="status">{selected.length} selected across all pages and filters.</p>}
        {approvalKeys !== null && <section className="review-work-card" aria-label={`${title} approval preview`} tabIndex={-1} ref={focusPreview}>
          <h3>Approve exact changes and prerequisites</h3>
          <p>{approvalKeys.length} items, including required supporting configuration and preceding policies.</p>
          <p>{preview.filter((row) => !selectedSet.has(row.key)).length} prerequisites added to your selection. Approval includes the target profile and proposed placement.</p>
          {approvalContext}
          {approvalBlocked && <p role="alert">Resolve blocked or missing prerequisites before approval.</p>}
          {preview.slice((currentPreviewPage - 1) * 25, currentPreviewPage * 25).map((row) => <details key={row.key}>
            <summary>{selectedSet.has(row.key) ? 'Selected' : 'Added prerequisite'} · {row.operation}: {row.sourceScope} / {row.sourceName} → {row.target}</summary>
            <pre className="set-command-preview">{JSON.stringify(row.settings, null, 2)}</pre>
            <details><summary>Required configuration ({row.dependencies.length})</summary><ul>{row.dependencies.map((key) => <li key={key}>{byKey.get(key)?.sourceName ?? key}{!previewSet.has(key) && ' — missing from selection'}</li>)}</ul></details>
          </details>)}
          {previewPages > 1 && <div className="action-row"><Button disabled={currentPreviewPage === 1} onClick={() => setPreviewPage(currentPreviewPage - 1)}>Previous approval details</Button><span>Page {currentPreviewPage} of {previewPages}</span><Button disabled={currentPreviewPage === previewPages} onClick={() => setPreviewPage(currentPreviewPage + 1)}>Next approval details</Button></div>}
          <div className="action-row"><Button disabled={busy || !approvalKeys.length || approvalBlocked} onClick={onApprove}>{approveLabel}</Button><Button disabled={busy} className="secondary-button" onClick={onCancel}>Cancel approval preview</Button></div>
        </section>}
        {!filtered.length && <p>No configuration items match these filters.</p>}
        <div className="report-table-wrap"><table className="report-table"><caption>Planned {title} configuration</caption><thead><tr><th>Select</th><th>Source scope / name</th><th>Target</th><th>Operation</th><th>Reason</th></tr></thead><tbody>{visible.map((row) => <tr key={row.key}>
          <td><input aria-label={`Select ${row.sourceScope} ${row.sourceName}`} type="checkbox" disabled={busy || !row.ready} checked={selectedSet.has(row.key)} onChange={(event) => { const keys = event.target.checked ? [...selected, row.key] : selected.filter((key) => key !== row.key); onSelect(keys); showPreview(keys, false) }} /></td>
          <td>{row.sourceScope} / {row.sourceName}<small>{row.family}</small><details><summary>Settings</summary><pre className="set-command-preview">{JSON.stringify(row.settings, null, 2)}</pre></details></td>
          <td>{row.target}</td><td>{row.operation}</td><td>{row.ready ? 'Ready for review' : <details><summary>{row.reasons.length} blocking reasons</summary><ul>{row.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></details>}</td>
        </tr>)}</tbody></table></div>
        {pages > 1 && <div className="action-row"><Button disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous changes</Button><span>Page {currentPage} of {pages}</span><Button disabled={currentPage === pages} onClick={() => setPage(currentPage + 1)}>Next changes</Button></div>}
      </section>}
  </section>
}
