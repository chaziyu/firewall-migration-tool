import { useState } from 'react'
import type { Decision, ReviewData } from '../reviewTypes'
import { interfaceMappingRows } from '../reviewDrafts'

export function MigrationInterfaceMappings({ review, drafts, setDraft, selectedKeys, setSelectedKeys, busy, reviewSelected, openDetails }: {
  review: ReviewData
  drafts: Record<string, string>
  setDraft: (key: string, value: string) => void
  selectedKeys: string[]
  setSelectedKeys: (keys: string[]) => void
  busy: boolean
  reviewSelected: (keys: string[], valueFor: (decision: Decision) => string) => void
  openDetails: (key: string) => void
}) {
  const [page, setPage] = useState(1)
  const rows = interfaceMappingRows(review.decisions.decisions, drafts, review.decision_candidates)
  const selected = rows.filter((row) => selectedKeys.includes(row.decision.key))
  const pages = Math.max(1, Math.ceil(rows.length / 25))
  const currentPage = Math.min(page, pages)
  if (!rows.length) return null
  return <section className="review-work-card" aria-label="Interface mappings">
    <h3>Interface mappings</h3>
    <p>{rows.length} mappings · {rows.filter((row) => row.decision.review_state === 'CONFIRMED').length} confirmed · {rows.filter((row) => row.conflict).length} conflicts · {selected.length} selected</p>
    <div className="migration-toolbar">
      <button className="secondary-button" type="button" disabled={busy} onClick={() => setSelectedKeys(rows.filter((row) => row.ready).map((row) => row.decision.key))}>Select non-conflicting suggestions</button>
      <button className="primary-button" type="button" disabled={busy || !selected.length || selected.some((row) => !row.value || row.conflict)} onClick={() => reviewSelected(selected.map((row) => row.decision.key), (decision) => rows.find((row) => row.decision.key === decision.key)?.value ?? '')}>Review selected mappings</button>
    </div>
    <div className="report-table-wrap"><table className="report-table migration-decision-table">
      <thead><tr><th>Select</th><th>Source interface</th><th>Target interface</th><th>Evidence</th><th>Status</th><th>Details</th></tr></thead>
      <tbody>{rows.slice((currentPage - 1) * 25, currentPage * 25).map(({ decision, value, candidate, conflict }) => <tr key={decision.key}>
        <td><input type="checkbox" aria-label={`Select ${decision.source_vdom} / ${decision.source_name}`} disabled={busy || decision.mode === 'UNSUPPORTED'} checked={selectedKeys.includes(decision.key)} onChange={(event) => setSelectedKeys(event.target.checked ? [...selectedKeys, decision.key] : selectedKeys.filter((key) => key !== decision.key))} /></td>
        <td>{decision.source_vdom} / {decision.source_name}</td>
        <td><input aria-label={`Target interface for ${decision.source_vdom} / ${decision.source_name}`} value={value} disabled={busy || decision.mode === 'UNSUPPORTED'} onChange={(event) => setDraft(decision.key, event.target.value)} /></td>
        <td>{candidate?.class === 'STRONG' ? 'Strong' : candidate ? (candidate.supporting_evidence?.some((fact) => !['INTERFACE_FAMILY_MATCH', 'physical interface family'].includes(fact)) ? 'Possible match' : 'Available interface') : 'Manual'}</td>
        <td>{conflict || review.review_groups.find((group) => group.decision_keys.includes(decision.key))?.conflicts?.find((finding) => finding.decision_key === decision.key)?.message
          || (decision.review_state === 'CONFIRMED' && value !== decision.value ? `Draft · confirmed mapping: ${decision.value}` : decision.review_state)}</td>
        <td><details><summary>Evidence</summary><ul>{[...(candidate?.strong_evidence ?? []), ...(candidate?.supporting_evidence ?? [])].map((fact) => <li key={fact}>{fact}</li>)}</ul><p>{decision.reason}</p></details><button className="text-button" type="button" onClick={() => openDetails(decision.key)}>Edit details</button></td>
      </tr>)}</tbody>
    </table></div>
    <div className="report-pager"><button type="button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous interfaces</button><span>Page {currentPage} of {pages}</span><button type="button" disabled={currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next interfaces</button></div>
  </section>
}
