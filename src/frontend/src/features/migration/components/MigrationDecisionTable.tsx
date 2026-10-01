import { candidateLabel } from '../reviewDrafts'
import type { Dispatch, SetStateAction } from 'react'
import type { Decision, ReviewData } from '../reviewTypes'

type RunAction = (action: () => Promise<void>, done?: string) => Promise<void>

export function MigrationDecisionTable({
  decisionFilter,
  setDecisionFilter,
  evidenceFilter,
  setEvidenceFilter,
  pendingOnly,
  setPendingOnly,
  decisionPage,
  setDecisionPage,
  visibleDecisions,
  selectedKeys,
  setSelectedKeys,
  busy,
  bulkConfirm,
  suggestions,
  drafts,
  decisions,
  bulkValue,
  setBulkValue,
  setError,
  clearSelected,
  review,
  setDrafts,
  run,
  confirmDecision,
}: {
  decisionFilter: string
  setDecisionFilter: Dispatch<SetStateAction<string>>
  evidenceFilter: string
  setEvidenceFilter: Dispatch<SetStateAction<string>>
  pendingOnly: boolean
  setPendingOnly: Dispatch<SetStateAction<boolean>>
  decisionPage: number
  setDecisionPage: Dispatch<SetStateAction<number>>
  visibleDecisions: Decision[]
  selectedKeys: string[]
  setSelectedKeys: Dispatch<SetStateAction<string[]>>
  busy: boolean
  bulkConfirm: (keys: string[], valueFor: (decision: Decision) => string) => void
  suggestions: Decision[]
  drafts: Record<string, string>
  decisions: Decision[]
  bulkValue: string
  setBulkValue: Dispatch<SetStateAction<string>>
  setError: Dispatch<SetStateAction<string>>
  clearSelected: () => void
  review: ReviewData
  setDrafts: Dispatch<SetStateAction<Record<string, string>>>
  run: RunAction
  confirmDecision: (decision: Decision, value: string) => Promise<void>
}) {
  return (
    <>
        <details className="migration-review-tools"><summary>Advanced decision view</summary>
        <div className="migration-toolbar">
          <label className="field">Show<select value={decisionFilter} onChange={(event) => { setDecisionFilter(event.target.value); setDecisionPage(1) }}><option value="all">All decisions</option><option value="zones">Zones</option><option value="interfaces">Interfaces</option><option value="route-nat">Route/NAT impact</option></select></label>
          <label className="field">Evidence<select value={evidenceFilter} onChange={(event) => { setEvidenceFilter(event.target.value); setDecisionPage(1) }}><option value="all">All evidence</option><option value="target">Target-backed</option><option value="source">Source-only</option><option value="conflict">Conflicts</option><option value="required">Required</option><option value="confirmed">Confirmed</option></select></label>
          <label><input type="checkbox" checked={pendingOnly} onChange={(event) => { setPendingOnly(event.target.checked); setDecisionPage(1) }} /> Show pending only</label>
          <button className="secondary-button" type="button" onClick={() => setSelectedKeys(visibleDecisions.slice((decisionPage - 1) * 50, decisionPage * 50).filter((item) => item.mode !== 'UNSUPPORTED').map((item) => item.key))}>Select all visible</button>
          <button className="secondary-button" type="button" onClick={() => setSelectedKeys([])}>Clear selection</button>
          <span aria-live="polite">Selected: {selectedKeys.length}</span>
          <button className="primary-button" type="button" disabled={busy || !selectedKeys.length} onClick={() => bulkConfirm(selectedKeys, (item) => drafts[item.key] ?? item.value ?? item.suggested_value ?? '')}>Confirm selected</button>
          <button className="secondary-button" type="button" disabled={busy || !suggestions.length} onClick={() => bulkConfirm(suggestions.map((item) => item.key), (item) => item.suggested_value ?? '')}>Confirm all mapping suggestions</button>
        </div>
        <div className="migration-toolbar"><label className="field">Final value for selected<input value={bulkValue} onChange={(event) => setBulkValue(event.target.value)} /></label>
          <button className="secondary-button" type="button" disabled={busy || !selectedKeys.length || !bulkValue.trim()} onClick={() => {
            const selected = decisions.filter((item) => selectedKeys.includes(item.key))
            if (new Set(selected.map((item) => item.target_field)).size > 1) { setError('Select decisions with one target field before setting a shared value.'); return }
            bulkConfirm(selectedKeys, () => bulkValue)
          }}>Set selected value</button>
          <button className="secondary-button" type="button" disabled={busy || !selectedKeys.length} onClick={() => bulkConfirm(selectedKeys, (item) => item.suggested_value ?? '')}>Use suggestion</button>
          <button className="secondary-button" type="button" disabled={busy || !selectedKeys.length} onClick={clearSelected}>Clear selected values</button>
        </div>
        <p className="migration-counts" aria-live="polite">{decisions.filter((item) => item.review_state === 'CONFIRMED' || item.mode === 'AUTO').length} confirmed · {suggestions.length} suggestions · {decisions.filter((item) => item.mode === 'REQUIRED' && item.review_state !== 'CONFIRMED').length} required</p>
        <div className="report-table-wrap">
          <table className="report-table migration-decision-table">
            <thead><tr><th>Source</th><th>Target field</th><th>Suggestion and candidates</th><th>Final value</th><th>Review</th></tr></thead>
            <tbody>{visibleDecisions.slice((decisionPage - 1) * 50, decisionPage * 50).map((decision) => {
              const candidates = review.decision_candidates[decision.key] ?? []
              const value = drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? ''
              return <tr key={decision.key}>
                <td><input aria-label={`Select ${decision.source_name}`} type="checkbox" checked={selectedKeys.includes(decision.key)} onChange={(event) => setSelectedKeys((keys) => event.target.checked ? [...keys, decision.key] : keys.filter((key) => key !== decision.key))} /> {decision.source_vdom} · {decision.source_kind} · {decision.source_name}<small className="decision-reason">{decision.reason}</small></td>
                <td>{decision.target_field}</td>
                <td>{decision.suggested_value || '—'}{candidates.length > 0 && <details><summary>{candidates.length} target candidates</summary><ul>{candidates.map((candidate) => <li key={`${decision.key}:${candidate.target_scope}:${candidate.value}`}>
                  <span>{candidateLabel(candidate)}: {candidate.value}{candidate.target_scope ? ` · ${candidate.target_scope}` : ''}{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].length ? ` · ${[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].join(', ')}` : ''}</span>
                  <button type="button" className="text-button" disabled={busy || candidate.available === false} onClick={() => setDrafts((current) => ({ ...current, [decision.key]: candidate.value }))}>Use candidate</button>
                </li>)}</ul></details>}</td>
                <td><input aria-label={`${decision.target_field} for ${decision.source_name}`} value={value} disabled={decision.mode === 'UNSUPPORTED'} onChange={(event) => setDrafts((current) => ({ ...current, [decision.key]: event.target.value }))} /></td>
                <td>{decision.review_state === 'CONFIRMED' || decision.mode === 'AUTO' ? 'Confirmed' : 'Pending'}{decision.mode !== 'UNSUPPORTED' && decision.review_state !== 'CONFIRMED' && decision.mode !== 'AUTO' && <button className="text-button" type="button" disabled={busy || !value.trim()} onClick={() => void run(() => confirmDecision(decision, value))}>Confirm</button>}</td>
              </tr>
            })}</tbody>
          </table>
        </div>
          <div className="report-pager"><button type="button" disabled={decisionPage <= 1} onClick={() => setDecisionPage((page) => page - 1)}>Previous decisions</button><span>Page {decisionPage} of {Math.max(1, Math.ceil(visibleDecisions.length / 50))}</span><button type="button" disabled={decisionPage * 50 >= visibleDecisions.length} onClick={() => setDecisionPage((page) => page + 1)}>Next decisions</button></div>
        </details>

    </>
  )
}
