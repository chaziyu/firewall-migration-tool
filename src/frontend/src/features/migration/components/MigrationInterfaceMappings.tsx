import { useState } from 'react'
import type { Decision, ReviewData } from '../reviewTypes'
import { candidateLabel, decisionLabel, interfaceMappingRows, orderInterfaceMappings } from '../reviewDrafts'
import type { DraftRow } from '../types'

export function MigrationInterfaceMappings({ review, drafts, setDraft, selectedKeys, setSelectedKeys, busy, reviewSelected, openDetails, proposals = [] }: {
  review: ReviewData
  drafts: Record<string, string>
  setDraft: (key: string, value: string) => void
  selectedKeys: string[]
  setSelectedKeys: (keys: string[]) => void
  busy: boolean
  reviewSelected: (keys: string[], valueFor: (decision: Decision) => string) => void
  openDetails: (key: string) => void
  proposals?: DraftRow[]
}) {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [pendingOnly, setPendingOnly] = useState(true)
  const context = review.decision_context ?? {}
  const rows = orderInterfaceMappings(interfaceMappingRows(review.decisions.decisions, drafts, review.decision_candidates), context, proposals)
  const filtered = rows.filter((row) => (!pendingOnly || row.decision.review_state !== 'CONFIRMED' || row.value !== row.decision.value)
    && `${row.decision.source_vdom} ${row.decision.source_name} ${row.value}`.toLowerCase().includes(search.toLowerCase()))
  const selected = rows.filter((row) => selectedKeys.includes(row.decision.key))
  const pages = Math.max(1, Math.ceil(filtered.length / 25))
  const currentPage = Math.min(page, pages)
  if (!rows.length) return null
  return <section className="review-work-card" aria-label="Interface mappings">
    <h3>Interface mappings</h3>
    <p>Allocate physical parents first. Explicit VLAN tags can then produce child proposals. Tunnel and other unsupported families still require manual design.</p>
    <p>{rows.length} mappings · {rows.filter((row) => row.decision.review_state === 'CONFIRMED').length} confirmed · {rows.filter((row) => row.conflict).length} conflicts · {selected.length} selected</p>
    <div className="migration-toolbar">
      <label className="field">Search interfaces<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} /></label>
      <label><input type="checkbox" checked={pendingOnly} onChange={(event) => { setPendingOnly(event.target.checked); setPage(1) }} /> Unconfirmed mappings only</label>
      <button className="secondary-button" type="button" disabled={busy} onClick={() => setSelectedKeys(rows.filter((row) => row.ready).map((row) => row.decision.key))}>Select strong interface suggestions</button>
      <button className="primary-button" type="button" disabled={busy || !selected.length || selected.some((row) => !row.value || row.conflict)} onClick={() => reviewSelected(selected.map((row) => row.decision.key), (decision) => rows.find((row) => row.decision.key === decision.key)?.value ?? '')}>Review selected mappings</button>
    </div>
    <div className="report-table-wrap"><table className="report-table migration-decision-table">
      <thead><tr><th>Select</th><th>Source / topology</th><th>Target interface</th><th>Evidence</th><th>Status</th><th>Details</th></tr></thead>
      <tbody>{filtered.slice((currentPage - 1) * 25, currentPage * 25).map(({ decision, value, candidate, conflict }) => <tr key={decision.key}>
        <td><input type="checkbox" aria-label={`Select ${decision.source_vdom} / ${decision.source_name}`} disabled={busy || decision.mode === 'UNSUPPORTED'} checked={selectedKeys.includes(decision.key)} onChange={(event) => setSelectedKeys(event.target.checked ? [...selectedKeys, decision.key] : selectedKeys.filter((key) => key !== decision.key))} /></td>
        <td>{decision.source_vdom} / {decision.source_name}<small className="mapping-topology">{String(context[decision.key]?.source_type ?? 'Type not explicit')}{context[decision.key]?.source_parent ? ` · parent ${context[decision.key].source_parent}` : ''}{context[decision.key]?.source_vlan != null ? ` · VLAN ${context[decision.key].source_vlan}` : ''}</small></td>
        <td><select aria-label={`Candidate interface for ${decision.source_vdom} / ${decision.source_name}`} value={(review.decision_candidates[decision.key] ?? []).some((option) => option.value === value) ? value : ''} disabled={busy || decision.mode === 'UNSUPPORTED'} onChange={(event) => setDraft(decision.key, event.target.value)}>
          <option value="">Choose a candidate or enter custom value below</option>{(review.decision_candidates[decision.key] ?? []).map((option) => <option key={`${option.target_scope}:${option.value}`} value={option.value} disabled={option.available === false || option.contested}>{option.value} · {candidateLabel(option)}</option>)}
        </select><input aria-label={`Target interface for ${decision.source_vdom} / ${decision.source_name}`} value={value} placeholder="Custom target interface" disabled={busy || decision.mode === 'UNSUPPORTED'} onChange={(event) => setDraft(decision.key, event.target.value)} /></td>
        <td>{decision.evidence_source ?? (candidate ? candidateLabel(candidate) : 'Needs input')}{decision.evidence_type && <small> · {decision.evidence_type}</small>}</td>
        <td>{conflict || review.review_groups.find((group) => group.decision_keys.includes(decision.key))?.conflicts?.find((finding) => finding.decision_key === decision.key)?.message
          || (decision.review_state === 'CONFIRMED' && value !== decision.value ? `Draft · confirmed mapping: ${decision.value}` : decisionLabel(decision, review.decision_candidates[decision.key]))}</td>
        <td><details><summary>Evidence</summary>{decision.suggested_value && <p>Suggested: {decision.suggested_value} · requires confirmation</p>}<ul>{[...(candidate?.strong_evidence ?? []), ...(candidate?.supporting_evidence ?? [])].map((fact) => <li key={fact}>{fact}</li>)}</ul><p>{decision.reason}</p>{review.review_groups.filter((group) => group.decision_keys.includes(decision.key)).map((group) => <p key={group.decision_keys[0]}>{group.affected_count} affected objects · {group.dependent_decision_count} dependent mappings</p>)}</details><button className="text-button" type="button" onClick={() => openDetails(decision.key)}>Edit details</button></td>
      </tr>)}</tbody>
    </table></div>
    <div className="report-pager"><button type="button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous interfaces</button><span>Page {currentPage} of {pages}</span><button type="button" disabled={currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next interfaces</button></div>
  </section>
}
