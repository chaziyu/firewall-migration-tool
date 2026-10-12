import { candidateLabel, decisionLabel } from '../reviewDrafts'
import type { Dispatch, SetStateAction } from 'react'
import { useState } from 'react'
import { tabKeyboard } from '../../../components/common/tabKeyboard'
import type { Decision, ReviewData, ReviewGroup, RuleSuggestion } from '../reviewTypes'
import type { DraftRow } from '../types'

type RunAction = (action: () => Promise<void>, done?: string) => Promise<void>

export function MigrationReviewQueues({
  review,
  selectedGroupKey,
  setSelectedGroupKey,
  reviewGroups,
  queueNames,
  activeQueue,
  setActiveQueue,
  search,
  setSearch,
  vdomFilter,
  setVdomFilter,
  vdoms,
  visibleGroups,
  setDecisionPage,
  drafts,
  setDrafts,
  decisions,
  proposals = [],
  busy,
  run,
  applyRuleSuggestion,
  applyGroupAction,
  updateGroup,
}: {
  review: ReviewData
  selectedGroupKey: string
  setSelectedGroupKey: Dispatch<SetStateAction<string>>
  reviewGroups: ReviewGroup[]
  queueNames: string[]
  activeQueue: string
  setActiveQueue: Dispatch<SetStateAction<string>>
  search: string
  setSearch: Dispatch<SetStateAction<string>>
  vdomFilter: string
  setVdomFilter: Dispatch<SetStateAction<string>>
  vdoms: string[]
  visibleGroups: ReviewGroup[]
  setDecisionPage: Dispatch<SetStateAction<number>>
  drafts: Record<string, string>
  setDrafts: Dispatch<SetStateAction<Record<string, string>>>
  decisions: Decision[]
  proposals?: DraftRow[]
  busy: boolean
  run: RunAction
  applyRuleSuggestion: (suggestion: RuleSuggestion) => Promise<void>
  applyGroupAction: (action: NonNullable<ReviewGroup['actions']>[number]) => Promise<void>
  updateGroup: (group: ReviewGroup) => Promise<void>
}) {
  const [groupPage, setGroupPage] = useState(1)
  const pages = Math.max(1, Math.ceil(visibleGroups.length / 20))
  const selectedIndex = visibleGroups.findIndex((group) => group.decision_keys[0] === selectedGroupKey)
  const currentPage = selectedIndex >= 0 ? Math.floor(selectedIndex / 20) + 1 : Math.min(groupPage, pages)
  const queueLabel = (queue: string) => ({ READY_TO_CONFIRM: 'Review suggestions', CHOOSE_CANDIDATE: 'Assign target', NEEDS_INPUT: 'Needs input', CONFLICT: 'Conflicts', COMPLETE: 'Completed' } as Record<string, string>)[queue] ?? queue
  const rowsByKey = new Map(proposals.map((row) => [row.decision_key || row.group_key!, row]))
  const changePage = (page: number) => {
    setGroupPage(page)
    setSelectedGroupKey(visibleGroups[(page - 1) * 20]?.decision_keys[0] ?? '')
  }
  return (
    <>
        <section className="review-workflow" aria-label="Migration review queues">
          <nav className="review-queues" role="tablist" aria-label="Migration review work queues" onKeyDown={tabKeyboard}>
            {queueNames.filter((queue) => queue === activeQueue || reviewGroups.some((group) => group.queue === queue)).map((queue) => <button type="button" role="tab" key={queue} id={`queue-tab-${queue}`} aria-controls={`queue-panel-${queue}`} tabIndex={activeQueue === queue ? 0 : -1} aria-selected={activeQueue === queue} onClick={() => { setActiveQueue(queue); setSelectedGroupKey(''); setGroupPage(1) }}>
              {queueLabel(queue)} <span>{reviewGroups.filter((group) => group.queue === queue).length} groups</span>
            </button>)}
          </nav>
          {queueNames.filter((queue) => queue !== activeQueue && reviewGroups.some((group) => group.queue === queue)).map((queue) => <div key={queue} hidden role="tabpanel" id={`queue-panel-${queue}`} aria-labelledby={`queue-tab-${queue}`} />)}
          <div role="tabpanel" id={`queue-panel-${activeQueue}`} aria-labelledby={`queue-tab-${activeQueue}`} tabIndex={0}>
          <div className="migration-toolbar">
            <label className="field">Search review groups<input value={search} onChange={(event) => { setSearch(event.target.value); setSelectedGroupKey(''); setGroupPage(1) }} placeholder="Search source mappings" /></label>
            <label className="field">VDOM<select value={vdomFilter} onChange={(event) => { setVdomFilter(event.target.value); setSelectedGroupKey(''); setGroupPage(1); setDecisionPage(1) }}><option value="all">All VDOMs</option>{vdoms.map((item) => <option key={item}>{item}</option>)}</select></label>
          </div>
          {!visibleGroups.length && <p>{reviewGroups.length ? 'Nothing in this queue.' : 'No migration decisions are required.'}</p>}
          {review.rule_suggestions.map((suggestion) => <article className="review-work-card architecture-question" key={`${suggestion.source_vdom}:${suggestion.source_zone}`}>
            <h3>Apply {suggestion.target_zone} to {suggestion.affected.length} other interfaces in {suggestion.source_zone}?</h3>
            <p>Based on {suggestion.confirmed_count} engineer-confirmed mappings for explicit zone members.</p>
            <details><summary>Review affected mappings</summary><ul>{suggestion.affected.map((name) => <li key={name}>{name}</li>)}</ul></details>
            <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyRuleSuggestion(suggestion))}>Apply to {suggestion.affected.length} mappings</button>
          </article>)}
          <div className="mapping-workspace">
            <nav className="mapping-list" aria-label="Source mappings">
              {visibleGroups.slice((currentPage - 1) * 20, currentPage * 20).map((group) => <button type="button" key={group.decision_keys[0]} aria-current={selectedGroupKey === group.decision_keys[0] || (!visibleGroups.some((item) => item.decision_keys[0] === selectedGroupKey) && group === visibleGroups[0]) ? 'true' : undefined} onClick={() => setSelectedGroupKey(group.decision_keys[0])}>
                <strong>{group.source_name}</strong><span>{group.source_vdom} · {group.source_kind}</span><span>{queueLabel(group.queue)}</span>
              </button>)}
              {pages > 1 && <div className="report-pager"><button type="button" disabled={currentPage <= 1} onClick={() => changePage(currentPage - 1)}>Previous mappings</button><span>{currentPage} / {pages}</span><button type="button" disabled={currentPage >= pages} onClick={() => changePage(currentPage + 1)}>Next mappings</button></div>}
            </nav>
            <div className="mapping-editor">
          {visibleGroups.filter((group) => group === (visibleGroups.find((item) => item.decision_keys[0] === selectedGroupKey) ?? visibleGroups[0])).map((group) => <article className={`review-work-card queue-${group.queue.toLowerCase()}`} key={`${group.source_vdom}:${group.source_kind}:${group.source_name}`}>
            {(() => {
              const taskKeys = new Set(group.decision_keys)
              const dependencies = [...new Set(group.decision_keys.flatMap((key) => rowsByKey.get(key)?.dependencies ?? []).filter((key) => !taskKeys.has(key)))]
              const missingDependencyData = group.decision_keys.some((key) => !rowsByKey.has(key)) || dependencies.some((key) => !rowsByKey.has(key))
              const blockers = dependencies.map((key) => rowsByKey.get(key)).filter((row) => row && row.status !== 'READY' && !row.approved)
              const waiting = blockers.length > 0 || missingDependencyData
              return <p className="review-task-state">{waiting ? 'Waiting · prerequisite work remains' : 'Actionable'}{missingDependencyData && ' · prerequisite details unavailable'}</p>
            })()}
            <div className="review-work-heading"><div><h3 id={`review-group-heading-${group.decision_keys[0]}`} tabIndex={-1}>{group.source_kind === 'vdom' ? `${group.source_name} VDOM` : group.source_name}</h3><p>{group.source_vdom} · {group.source_kind}{typeof group.source_evidence.source_type === 'string' ? ` · ${group.source_evidence.source_type}` : ''}</p></div><span className="review-work-badge">{queueLabel(group.queue)}</span></div>
            {[...new Set(group.decision_keys.flatMap((key) => rowsByKey.get(key)?.dependencies ?? []))].map((key) => {
              const prerequisite = rowsByKey.get(key)
              if (!prerequisite || prerequisite.status === 'READY' || prerequisite.approved) return null
              const prerequisiteGroup = reviewGroups.find((item) => item.decision_keys.includes(key))
              const source = decisions.find((item) => item.key === key)
              return prerequisiteGroup && source ? <button key={key} className="text-button review-prerequisite" type="button" onClick={() => { setSearch(''); setVdomFilter('all'); setActiveQueue(prerequisiteGroup.queue); setSelectedGroupKey(prerequisiteGroup.decision_keys[0]); requestAnimationFrame(() => { const input = document.getElementById(`decision-${key}`); if (input) { const details = input.closest('details'); if (details) details.open = true; input.scrollIntoView({ block: 'center' }); input.focus() } }) }}>Resolve prerequisite {source.source_name} · {source.target_field} first</button> : <p key={key}>Prerequisite details unavailable for {key}.</p>
            })}
            {group.decisions.some((decision) => decision.mode !== 'UNSUPPORTED') && <div className="review-source-summary"><strong>Source configuration</strong><p>{[['IP address', group.source_evidence.source_ip ?? group.source_evidence.source_ip_address], ['Type', group.source_evidence.source_type], ['Parent', group.source_evidence.source_parent], ['VLAN', group.source_evidence.source_vlan]].filter(([, value]) => value !== undefined && value !== null && value !== '').map(([label, value]) => `${label}: ${String(value)}`).join(' · ') || 'IP address, type, parent and VLAN are not explicit in available source evidence.'}</p></div>}
            {(review.architecture_questions ?? []).filter((question) => question.source_vdom === group.source_vdom && question.source_name === group.source_name).map((question) => <div className="review-work-suggestion" key={`${question.type}:${question.source_name}`}>
              <p>{question.type === 'AGGREGATE_MAPPING' ? `Architecture question: Which PAN aggregate replaces this interface? ${question.affected_count ?? 0} VLAN mappings will be re-evaluated.` : question.type === 'VDOM_CONTEXT' ? 'Architecture question: Choose the target VSYS and virtual router for this VDOM.' : 'Architecture question: Choose the PAN zone for this source zone.'}</p>
              {question.type === 'VDOM_CONTEXT' ? question.fields?.filter((item) => item.suggested_value).map((item) => <button className="secondary-button" type="button" key={item.key} onClick={() => setDrafts((current) => ({ ...current, [item.key]: item.suggested_value ?? '' }))}>{item.target_field === 'vsys' ? 'VSYS' : 'VR'}: {item.suggested_value}</button>) : (question.candidates ?? []).map((value) => <button className="secondary-button" type="button" key={value} onClick={() => question.decision_key && setDrafts((current) => ({ ...current, [question.decision_key as string]: value }))}>Use {value}</button>)}
            </div>)}
            {group.decisions.filter((item) => item.mode !== 'UNSUPPORTED').map((decision) => {
              const value = drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? ''
              const candidates = group.candidates[decision.key] ?? review.decision_candidates[decision.key] ?? []
              return <div className="review-work-field" key={decision.key}>
                {candidates.length > 0 && <fieldset className="review-candidate-options"><legend>{decision.target_field === 'target_zone' ? 'Target zone' : `Available ${decision.target_field.replaceAll('_', ' ')}`}</legend>{candidates.map((candidate) => {
                  const sameValue = candidates.filter((item) => item.value === candidate.value)
                  const unavailable = candidate.available === false || candidate.contested || sameValue.length > 1
                  const status = candidateLabel(candidate, decision.target_field)
                  return <label className="review-candidate-option" key={`${candidate.target_scope}:${candidate.value}`}><input type="radio" name={`candidate-${decision.key}`} value={candidate.value} aria-label={`${candidate.value}, ${status}, ${candidate.target_scope || 'target scope not returned'}`} checked={sameValue.length === 1 && value === candidate.value} disabled={busy || unavailable} onChange={() => setDrafts((current) => ({ ...current, [decision.key]: candidate.value }))} /><span><strong>{decision.target_field === 'target_zone' ? 'Use existing zone' : candidate.value}</strong><small>{status}{candidate.reason ? ` · ${candidate.reason}` : ''}{sameValue.length > 1 ? ' · same target value appears in multiple scopes' : ''}</small></span></label>
                })}</fieldset>}
                {candidates.some((candidate) => candidates.filter((item) => item.value === candidate.value).length > 1) && <p>These candidate values appear in multiple target scopes. The decision stores the target value only, so it cannot select between those scopes.</p>}
                {decision.target_field === 'target_zone' && <p className="review-work-suggestion">{candidates.some((candidate) => candidate.value === value) ? 'Intent: use the selected existing zone.' : 'Intent: propose a new zone. This remains provisional until validation and design approval.'}</p>}
                <p className="review-work-suggestion">{decisionLabel(decision, candidates, group.conflicts?.some((finding) => finding.decision_key === decision.key))}{decision.suggested_value && decision.review_state !== 'CONFIRMED' ? `: ${decision.suggested_value} · requires design approval` : ''}</p>
                <p>{decision.reason}{decision.evidence_source ? ` · ${decision.evidence_source}` : ''}{decision.evidence_type ? ` · ${decision.evidence_type}` : ''}</p>
                <details className="review-custom-target" open={!candidates.length || !candidates.some((candidate) => candidate.value === value)}><summary>{candidates.some((candidate) => candidate.value === value) ? 'Technical details and custom target' : 'Enter another target'}</summary><label>{decision.target_field.replaceAll('_', ' ')}<input id={`decision-${decision.key}`} disabled={busy} aria-label={`${decision.target_field} for ${group.source_vdom} / ${group.source_name}`} value={value} onChange={(event) => setDrafts((current) => ({ ...current, [decision.key]: event.target.value }))} placeholder={decision.suggested_value ? `Suggested: ${decision.suggested_value}` : 'Enter mapping'} /></label>{candidates.some((candidate) => candidates.filter((item) => item.value === candidate.value).length > 1) && <p>These options share a value across target scopes. This decision stores the target value only, so it cannot select between those scopes.</p>}{candidates.length > 0 && <ul>{candidates.map((candidate) => <li key={`${candidate.target_scope}:${candidate.value}`}>{candidate.target_scope || 'Target scope not returned'} · {candidate.value} · {candidateLabel(candidate, decision.target_field)}{candidate.reason ? ` · ${candidate.reason}` : ''}{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].map((fact) => ` · ${fact}`)}</li>)}</ul>}</details>
              </div>
            })}
            <div className="review-work-impact"><p>{group.affected_count} affected-object impact estimate · {group.dependent_decision_count} dependent mappings will be re-evaluated</p>{group.next_action && <p>Next action: {group.next_action}</p>}
              {Object.keys(group.source_evidence).length > 0 && <details><summary>Source facts</summary><ul>{Object.entries(group.source_evidence).map(([key, value]) => <li key={key}>{key.replace(/^source_/, '').replaceAll('_', ' ')}: {Array.isArray(value) ? value.join(', ') || '(explicitly empty)' : String(value)}</li>)}</ul></details>}
            </div>
            {group.decisions.filter((item) => item.mode === 'UNSUPPORTED').map((item) => <p key={item.key}>Unsupported: {item.target_field} · {item.reason}</p>)}
            {group.actions?.map((action) => <div key={`${action.type}:${action.source_key}`}><details><summary>Review member decision scope</summary><p>{group.source_vdom} · {action.source_key} → {action.value}</p><ul>{action.apply_to.map((key) => <li key={key}>{key}</li>)}</ul></details><button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyGroupAction(action))}>Apply {action.value} to {action.apply_to.length} member decisions</button></div>)}
            {(() => {
              const required = group.decisions.filter((item) => item.mode !== 'UNSUPPORTED' && item.mode !== 'AUTO')
              const incomplete = required.some((item) => !(drafts[item.key] ?? item.value ?? item.suggested_value ?? '').trim())
              return required.length > 0 && <><p>Saving asks the server to validate required fields, dependencies and conflicts before moving on.</p><button className="primary-button" type="button" disabled={busy} onClick={() => void run(() => updateGroup(group))}>{incomplete ? 'Save incomplete proposal' : 'Save proposal and continue'}</button></>
            })()}
          </article>)}
          </div></div>
          </div>
        </section>

    </>
  )
}
