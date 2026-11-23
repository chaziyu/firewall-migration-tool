import { useEffect, useRef, useState } from 'react'
import { cellBadgeVariant, compactValue, detailGroups, fieldLabel, isMonoColumn, safeValue, type ReportRow } from './reportPresentation'

function ReportValue({ value, fieldKey = '' }: { value: unknown; fieldKey?: string }) {
  if (Array.isArray(value) && value.length && value.every((item) => item === null || typeof item !== 'object')) {
    return <ul className="report-value-list">{value.map((item, index) => <li key={index} className={isMonoColumn(fieldKey) ? 'fw-cell-mono' : undefined}>{compactValue(item)}</li>)}</ul>
  }
  if (value !== null && typeof value === 'object' && Object.keys(value).length) {
    return <details className="report-nested fw-expander"><summary>{compactValue(value)}</summary><dl className="finding-nested">{Object.entries(value).map(([key, item]) => <div key={key}><dt>{Array.isArray(value) ? `Entry ${Number(key) + 1}` : fieldLabel(key)}</dt><dd><ReportValue value={item} fieldKey={key} /></dd></div>)}</dl></details>
  }
  const badge = fieldKey ? cellBadgeVariant(fieldKey, value) : null
  if (badge) {
    return <span className={`report-detail-value fw-badge fw-badge-${badge}`}>{compactValue(value)}</span>
  }
  return <span className={`report-detail-value${isMonoColumn(fieldKey) ? ' fw-cell-mono' : ''}`}>{compactValue(value)}</span>
}

export function ReportDetails({ row, subsection = '', vendor = '', finding = false, target, onNavigate, onClose, previous, next }: {
  row: ReportRow; subsection?: string; vendor?: string; finding?: boolean
  target?: { label: string; rows: unknown[] } | null
  onNavigate?: () => void; onClose: () => void; previous?: () => void; next?: () => void
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 760px)').matches)
  useEffect(() => {
    const media = window.matchMedia('(max-width: 760px)')
    const update = () => setMobile(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  useEffect(() => {
    const dialog = ref.current!
    const trigger = document.activeElement as HTMLElement | null
    if (mobile) dialog.showModal()
    else dialog.show()
    dialog.querySelector<HTMLButtonElement>('[data-close]')?.focus()
    return () => { dialog.close(); if (trigger?.isConnected) trigger.focus() }
  }, [mobile])
  const scope = row.scope ?? row.vdom
  const identity = row.object_name ?? row.name ?? row.policy_name ?? row.display_name ?? row.policy_id ?? row.route_id
  const title = `${finding ? 'Finding' : fieldLabel(subsection) || 'Object'}: ${identity == null || identity === '' ? 'Details' : String(identity)}${scope == null ? '' : ` · ${String(scope)}`}`
  const groups = detailGroups(row, subsection, vendor)
  return <dialog ref={ref} className={`report-details fw-inspector-drawer${mobile ? ' report-details-mobile' : ''}`} aria-label={title} onCancel={(event) => { event.preventDefault(); onClose() }} onKeyDown={(event) => {
    if (event.key === 'Escape') { event.preventDefault(); onClose() }
    if (event.key !== 'Tab' || !mobile) return
    const controls = [...event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), summary, [tabindex="0"]')].filter((element) => element.getClientRects().length)
    const first = controls[0], last = controls.at(-1)
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
  }}>
    <div className="finding-inspector-header">
      <div>
        <div className="fw-inspector-eyebrow">{finding ? 'Validation Inspector' : fieldLabel(subsection) || 'Object Inspector'}</div>
        <h3>{title}</h3>
      </div>
      <button data-close type="button" onClick={onClose} aria-label="Close details">×</button>
    </div>
    {!finding && <div className="report-detail-navigation"><button type="button" className="secondary-button button-compact" disabled={!previous} onClick={previous}>← Previous object</button><button type="button" className="secondary-button button-compact" disabled={!next} onClick={next}>Next object →</button></div>}
    <div className="finding-inspector-content" tabIndex={0}>
      {target && <button type="button" className="finding-object-link" onClick={onNavigate}>View {target.label.toLowerCase()} object →</button>}
      {groups.map((group) => {
        const fields = <dl className="finding-details">{group.fields.map(([key, value]) => <div key={key} className="fw-kv-row"><dt className="fw-kv-row-label">{fieldLabel(key)}</dt><dd className="fw-kv-row-val"><ReportValue value={value} fieldKey={key} /></dd></div>)}</dl>
        return group.title === 'Empty / not reported fields' ? <details className="report-detail-group fw-expander" key={group.title}><summary>{group.title} ({group.fields.length})</summary><div className="fw-expander-body">{fields}</div></details> : <section className="report-detail-group fw-card" key={group.title}><h4>{group.title}</h4>{fields}</section>
      })}
      {target && <section className="finding-object-target fw-card"><h4>{target.label} object</h4>{target.rows.length ? target.rows.map((value, index) => <ReportValue key={index} value={safeValue(value)} />) : <p>No matching object was included in this report.</p>}</section>}
    </div>
  </dialog>
}

