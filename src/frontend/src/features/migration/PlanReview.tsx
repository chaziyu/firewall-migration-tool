import { useMemo, useState } from 'react'
import type { PlanArtifact } from './migrationApi'
import { exportCategoryLabels, groupPlanBlockers, mappingIdentityLabel } from './reviewPresentation'
import { asRecord, compactValue, safeValue } from '../report/reportPresentation'

function PlanRows({ rows, kind, onReviewDecision }: { rows: Array<Record<string, unknown>>; kind: 'items' | 'blockers' | 'recommendations' | 'affected items'; onReviewDecision: (key: string) => void }) {
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const safeRows = useMemo(() => rows.map((row) => asRecord(safeValue(row))), [rows])
  const statuses = [...new Set(safeRows.map((row) => String(row.status ?? '')).filter(Boolean))]
  const filtered = safeRows.filter((row) => (!status || row.status === status) && (!search || JSON.stringify(row).toLowerCase().includes(search.toLowerCase())))
  const pageCount = Math.max(1, Math.ceil(filtered.length / 50))
  const currentPage = Math.min(page, pageCount)
  return <>
    <div className="migration-toolbar">
      <label className="field">Search {kind}<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} /></label>
      {!!statuses.length && <label className="field">Support status<select value={status} onChange={(event) => { setStatus(event.target.value); setPage(1) }}><option value="">All statuses</option>{statuses.map((value) => <option key={value}>{value}</option>)}</select></label>}
      <button type="button" className="filter-clear" disabled={!search && !status} onClick={() => { setSearch(''); setStatus(''); setPage(1) }}>Clear filters</button>
    </div>
    {!filtered.length && <p>No {kind} match the current filters.</p>}
    {filtered.slice((currentPage - 1) * 50, currentPage * 50).map((row, index) => {
      const keys = [...new Set([row.decision_key, ...(Array.isArray(row.decision_keys) ? row.decision_keys : [])].filter((key): key is string => typeof key === 'string' && !!key))]
      return <article className="review-work-card plan-item" key={String(row.item_key ?? index)}>
        <strong>{String(row.source_name ?? row.title ?? row.message ?? row.code ?? 'Plan finding')}</strong>
        {kind === 'items' ? <>
          <p>Source: {String(row.source_vdom ?? 'Unknown scope')} · {String(row.source_kind ?? row.source_object_type ?? 'Unknown kind')} · {String(row.source_name ?? row.source_policy_id ?? 'Unknown identity')}</p>
          <p>Target: {String(row.target_vsys ?? 'Not specified')} · {String(row.target_name ?? 'Not specified')}</p>
          <p>Support: {String(row.status ?? 'Unknown')} · Disposition: {String(row.render_disposition ?? 'Unknown')} · Rendered: {compactValue(row.rendered)}</p>
          {row.export_category != null && <p>Export: {exportCategoryLabels[String(row.export_category)] ?? String(row.export_category)}</p>}
          <p>Command renderable: {compactValue(row.command_renderable)} · Satisfied: {compactValue(row.satisfied)}</p>
          <details><summary>Blockers and warnings</summary><pre>{JSON.stringify({ render_blockers: row.render_blockers, warnings: row.warnings }, null, 2)}</pre></details>
          <details><summary>Rendered commands ({Array.isArray(row.commands) ? row.commands.length : 0})</summary><pre>{Array.isArray(row.commands) ? row.commands.join('\n') : 'No commands reported'}</pre></details>
        </> : <>
          {row.count != null && <p>{String(row.count)} occurrences</p>}
          <p>{String(row.why ?? row.message ?? row.reason ?? '')}</p>
          <p>{String(row.next_action ?? row.becomes_supported_when ?? '')}</p>
          {row.source_vdom != null && <p>{String(row.source_vdom)} · {String(row.source_kind ?? '')} · {String(row.source_name ?? row.source_policy_id ?? '')}</p>}
          {Array.isArray(row.affected) && <details><summary>Affected items ({row.affected.length})</summary><PlanRows rows={row.affected as Array<Record<string, unknown>>} kind="affected items" onReviewDecision={onReviewDecision} /></details>}
          {!keys.length && <p>Manual action: {String(row.next_action ?? 'Review the source evidence and support guidance. Mapping approval alone cannot resolve this finding.')}</p>}
        </>}
        {keys.map((key) => <button type="button" className="finding-inline-link" key={key} onClick={() => onReviewDecision(key)}>Resolve {mappingIdentityLabel(key)}</button>)}
      </article>
    })}
    <div className="report-pager"><button type="button" className="secondary-button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous {kind}</button><span role="status">Page {currentPage} of {pageCount} · {filtered.length} {kind}</span><button type="button" className="secondary-button" disabled={currentPage >= pageCount} onClick={() => setPage(currentPage + 1)}>Next {kind}</button></div>
  </>
}

export function PlanReview({ artifact, onReviewDecision }: { artifact: PlanArtifact; onReviewDecision: (key: string) => void }) {
  const blockers = useMemo(() => groupPlanBlockers([...artifact.blocking_reasons, ...(artifact.support_guidance ?? [])]), [artifact])
  return <div className="plan-review">
    <details><summary>Blockers and support guidance ({blockers.length} groups)</summary><PlanRows rows={blockers} kind="blockers" onReviewDecision={onReviewDecision} /></details>
    <details><summary>Recommendations ({artifact.recommendations.length})</summary><PlanRows rows={artifact.recommendations} kind="recommendations" onReviewDecision={onReviewDecision} /></details>
    <details><summary>Plan items ({artifact.report.items?.length ?? 0})</summary><PlanRows rows={artifact.report.items ?? []} kind="items" onReviewDecision={onReviewDecision} /></details>
  </div>
}
