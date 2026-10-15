import { candidateLabel, decisionLabel } from '../reviewDrafts'
import type { Dispatch, SetStateAction } from 'react'
import { useState } from 'react'
import { tabKeyboard } from '../../../components/common/tabKeyboard'
import type { Decision, ReviewData, ReviewGroup, RuleSuggestion } from '../reviewTypes'
import type { DraftRow } from '../types'
import { orderedCandidates, reviewSourceSummary } from '../reviewPresentation'

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
  const [customFields, setCustomFields] = useState<Record<string, boolean>>({})
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
              if (group.decision_keys.includes(key)) return <p key={key}>Choose {decisions.find((item) => item.key === key)?.target_field.replaceAll('_', ' ') || 'the required value'} below before completing this mapping.</p>
              const prerequisiteGroup = reviewGroups.find((item) => item.decision_keys.includes(key))
              const source = decisions.find((item) => item.key === key)
              return prerequisiteGroup && source ? <button key={key} className="text-button review-prerequisite" type="button" onClick={() => { setSearch(''); setVdomFilter('all'); setActiveQueue(prerequisiteGroup.queue); setSelectedGroupKey(prerequisiteGroup.decision_keys[0]); requestAnimationFrame(() => { const input = document.getElementById(`decision-${key}`); if (input) { const details = input.closest('details'); if (details) details.open = true; input.scrollIntoView({ block: 'center' }); input.focus() } }) }}>Resolve prerequisite {source.source_name} · {source.target_field} first</button> : <p key={key}>Prerequisite details unavailable for {key}.</p>
            })}
            {group.decisions.some((decision) => decision.mode !== 'UNSUPPORTED') && <div className="review-source-summary"><strong>Source configuration</strong><p>{reviewSourceSummary(group)}</p></div>}
            {(review.architecture_questions ?? []).filter((question) => question.source_vdom === group.source_vdom && question.source_name === group.source_name).map((question) => <div className="review-work-suggestion" key={`${question.type}:${question.source_name}`}>
              <p>{question.type === 'AGGREGATE_MAPPING' ? `Architecture question: Which PAN aggregate replaces this interface? ${question.affected_count ?? 0} VLAN mappings will be re-evaluated.` : question.type === 'VDOM_CONTEXT' ? 'Architecture question: Choose the target VSYS and virtual router for this VDOM.' : 'Architecture question: Choose the PAN zone for this source zone.'}</p>
              {question.type === 'VDOM_CONTEXT' ? question.fields?.filter((item) => item.suggested_value).map((item) => <button className="secondary-button" type="button" disabled={busy} key={item.key} onClick={() => setDrafts((current) => ({ ...current, [item.key]: item.suggested_value ?? '' }))}>{item.target_field === 'vsys' ? 'VSYS' : 'VR'}: {item.suggested_value}</button>) : (question.candidates ?? []).map((value) => <button className="secondary-button" type="button" disabled={busy} key={value} onClick={() => question.decision_key && setDrafts((current) => ({ ...current, [question.decision_key as string]: value }))}>Use {value}</button>)}
            </div>)}
            {group.decisions.filter((item) => item.mode !== 'UNSUPPORTED').map((decision) => {
              const value = drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? ''
              const proposal = rowsByKey.get(decision.key)
              const unchanged = value.trim() === (proposal?.proposed_value ?? '')
              const candidates = orderedCandidates(group.candidates[decision.key] ?? review.decision_candidates[decision.key] ?? [])
              return <div className="review-work-field" key={decision.key}>
                <label className="field">{decision.target_field.replaceAll('_', ' ')}
                  <select id={`decision-${decision.key}`} aria-label={`${decision.target_field} for ${group.source_vdom} / ${group.source_name}`} disabled={busy} value={customFields[decision.key] ? '__custom__' : value && candidates.filter((candidate) => candidate.value === value).length === 1 ? value : value ? '__custom__' : ''} onChange={(event) => {
                    const next = event.target.value
                    setDrafts((current) => ({ ...current, [decision.key]: next === '__custom__' ? value && !candidates.some((candidate) => candidate.value === value) ? value : '' : next }))
                    setCustomFields((current) => ({ ...current, [decision.key]: next === '__custom__' }))
                  }}>
                    <option value="">Select {decision.target_field.replaceAll('_', ' ')}</option>
                    {candidates.map((candidate) => <option key={`${candidate.target_scope}:${candidate.value}`} value={candidate.value} disabled={candidate.available === false || candidate.contested || candidates.filter((item) => item.value === candidate.value).length > 1}>{candidate.value} · {candidateLabel(candidate, decision.target_field)}{candidates.filter((item) => item.value === candidate.value).length > 1 ? ` · ${candidate.target_scope} · ambiguous scope` : ''}</option>)}
                    <option value="__custom__">{decision.target_field === 'target_zone' ? 'Propose a new zone…' : 'Enter a custom target…'}</option>
                  </select>
                </label>
                {(customFields[decision.key] || !candidates.length || (value && !candidates.some((candidate) => candidate.value === value))) && <label className="field">{decision.target_field === 'target_zone' ? 'Proposed zone name' : 'Custom target value'}<input disabled={busy} aria-label={`Custom ${decision.target_field} for ${group.source_vdom} / ${group.source_name}`} value={value} onChange={(event) => setDrafts((current) => ({ ...current, [decision.key]: event.target.value }))} placeholder="Enter target value" /></label>}
                {decision.target_field === 'target_zone' && value && <p>{candidates.some((candidate) => candidate.value === value) ? 'Use existing zone.' : 'Propose a new zone; requires validation and approval.'}</p>}
                <p className="review-work-suggestion">{!unchanged ? 'Staged change — needs validation.' : proposal?.status === 'READY' && !proposal.approved ? 'Validated proposal — awaiting approval.' : decisionLabel(decision, candidates, group.conflicts?.some((finding) => finding.decision_key === decision.key))}</p>
                <details className="review-custom-target"><summary>Why these choices?</summary>
                  <p>{decision.reason}{decision.evidence_source ? ` · ${decision.evidence_source}` : ''}{decision.evidence_type ? ` · ${decision.evidence_type}` : ''}</p>
                  {candidates.some((candidate) => candidates.filter((item) => item.value === candidate.value).length > 1) && <p>These options share a value across target scopes. This decision stores the target value only, so it cannot select between those scopes.</p>}
                  <ul>{candidates.map((candidate) => <li key={`${candidate.target_scope}:${candidate.value}`}>{candidate.value} · {candidate.target_scope || 'Target scope not returned'} · {candidateLabel(candidate, decision.target_field)}{candidate.reason ? ` · ${candidate.reason}` : ''}{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].map((fact) => ` · ${fact}`)}</li>)}</ul>
                </details>
              </div>
            })}
            <div className="review-work-impact"><p>{group.affected_count} affected-object impact estimate · {group.dependent_decision_count} dependent mappings will be re-evaluated</p>{group.next_action && <p>Next action: {group.next_action}</p>}
              {Object.keys(group.source_evidence).length > 0 && <details><summary>Source facts</summary><ul>{Object.entries(group.source_evidence).map(([key, value]) => <li key={key}>{key.replace(/^source_/, '').replaceAll('_', ' ')}: {Array.isArray(value) ? value.join(', ') || '(explicitly empty)' : String(value)}</li>)}</ul></details>}
            </div>
            {group.decisions.filter((item) => item.mode === 'UNSUPPORTED').map((item) => <p key={item.key}>Unsupported: {item.target_field} · {item.reason}</p>)}
            {group.actions?.map((action) => <div key={`${action.type}:${action.source_key}`}><details><summary>Review member decision scope</summary><p>{group.source_vdom} · {action.source_key} → {action.value}</p><ul>{action.apply_to.map((key) => <li key={key}>{key}</li>)}</ul></details><button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyGroupAction(action))}>Apply {action.value} to {action.apply_to.length} member decisions</button></div>)}
            {(() => {
              const required = group.decisions.filter((item) => item.mode !== 'UNSUPPORTED' && item.mode !== 'AUTO')
              return required.length > 0 && <><p>Edits are saved locally in this workspace. Blank fields stay unresolved. Validation and approval are separate steps.</p><button className="secondary-button" type="button" disabled={busy} onClick={() => void updateGroup(group)}>Review staged changes</button></>
            })()}
          </article>)}
          </div></div>
          </div>
        </section>

    </>
  )
}
