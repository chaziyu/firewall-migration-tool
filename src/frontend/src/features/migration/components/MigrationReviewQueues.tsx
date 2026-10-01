import type { Dispatch, SetStateAction } from 'react'
import { tabKeyboard } from '../../../components/common/tabKeyboard'
import type { Decision, Proposal, ReviewData, ReviewGroup, RuleSuggestion } from '../reviewTypes'

type RunAction = (action: () => Promise<void>, done?: string) => Promise<void>

export function MigrationReviewQueues({
  review,
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
  groupPage,
  setGroupPage,
  setDecisionPage,
  drafts,
  setDrafts,
  proposals,
  decisions,
  busy,
  run,
  applyRuleSuggestion,
  applyGroupAction,
  confirmGroup,
}: {
  review: ReviewData
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
  groupPage: number
  setGroupPage: Dispatch<SetStateAction<number>>
  setDecisionPage: Dispatch<SetStateAction<number>>
  drafts: Record<string, string>
  setDrafts: Dispatch<SetStateAction<Record<string, string>>>
  proposals: Proposal[]
  decisions: Decision[]
  busy: boolean
  run: RunAction
  applyRuleSuggestion: (suggestion: RuleSuggestion) => Promise<void>
  applyGroupAction: (action: NonNullable<ReviewGroup['actions']>[number]) => Promise<void>
  confirmGroup: (group: ReviewGroup) => Promise<void>
}) {
  return (
    <>
        <section className="architecture-decisions" aria-label="Architecture decisions">
          <h3>Architecture decisions</h3>
          {(review.architecture_questions ?? []).map((question) => {
            const group = reviewGroups.find((item) => item.source_vdom === question.source_vdom && item.source_name === question.source_name)
            return <article key={`${question.type}:${question.source_vdom}:${question.source_name}`} className="review-work-card">
              <strong>{question.source_vdom} · {question.source_name}</strong>
              <p>{question.type === 'VDOM_CONTEXT' ? 'Choose target VSYS and virtual router.' : question.type === 'AGGREGATE_MAPPING' ? 'Choose the target aggregate interface.' : 'Choose the target zone.'} {question.affected_count ?? group?.affected_count ?? 0} affected objects.</p>
              {group && <button type="button" className="secondary-button" onClick={() => {
                setActiveQueue(group.queue); setSearch(''); setVdomFilter('all'); setGroupPage(Math.floor(reviewGroups.filter((item) => item.queue === group.queue).indexOf(group) / 10) + 1)
                requestAnimationFrame(() => { const input = document.getElementById(`decision-${group.decision_keys[0]}`); input?.scrollIntoView({ block: 'center' }); input?.focus() })
              }}>Review architecture mapping</button>}
            </article>
          })}
          {!review.architecture_questions?.length && <p>No architecture questions reported.</p>}
        </section>
        <div className="review-summary">
          {[
            ['verified', 'Verified'], ['derived', 'Derived'], ['choose_candidate', 'Choices'],
            ['needs_input', 'Manual'], ['conflicts', 'Conflicts'],
          ].map(([key, label]) => <div className="review-summary-card" key={key}><strong>{review.review_summary[key] ?? 0}</strong><span>{label} decisions</span></div>)}
        </div>
        <section className="review-workflow" aria-label="Migration review queues">
          <nav className="review-queues" role="tablist" aria-label="Migration review work queues" onKeyDown={tabKeyboard}>
            {queueNames.map((queue) => <button type="button" role="tab" key={queue} id={`queue-tab-${queue}`} aria-controls={`queue-panel-${queue}`} tabIndex={activeQueue === queue ? 0 : -1} aria-selected={activeQueue === queue} onClick={() => { setActiveQueue(queue); setGroupPage(1) }}>
              {({ READY_TO_CONFIRM: 'Ready to approve', CHOOSE_CANDIDATE: 'Choose match', NEEDS_INPUT: 'Needs design', CONFLICT: 'Conflicts', COMPLETE: 'Completed' } as Record<string, string>)[queue]} <span>{reviewGroups.filter((group) => group.queue === queue).length} groups</span>
            </button>)}
          </nav>
          {queueNames.filter((queue) => queue !== activeQueue).map((queue) => <div key={queue} hidden role="tabpanel" id={`queue-panel-${queue}`} aria-labelledby={`queue-tab-${queue}`} />)}
          <div role="tabpanel" id={`queue-panel-${activeQueue}`} aria-labelledby={`queue-tab-${activeQueue}`} tabIndex={0}>
          <div className="migration-toolbar">
            <label className="field">Search review groups<input value={search} onChange={(event) => { setSearch(event.target.value); setGroupPage(1) }} placeholder="Search source mappings" /></label>
            <label className="field">VDOM<select value={vdomFilter} onChange={(event) => { setVdomFilter(event.target.value); setGroupPage(1); setDecisionPage(1) }}><option value="all">All VDOMs</option>{vdoms.map((item) => <option key={item}>{item}</option>)}</select></label>
          </div>
          {!visibleGroups.length && <p>{reviewGroups.length ? 'Nothing in this queue.' : 'No migration decisions are required.'}</p>}
          {review.rule_suggestions.map((suggestion) => <article className="review-work-card architecture-question" key={`${suggestion.source_vdom}:${suggestion.source_zone}`}>
            <h3>Apply {suggestion.target_zone} to {suggestion.affected.length} other interfaces in {suggestion.source_zone}?</h3>
            <p>Based on {suggestion.confirmed_count} engineer-confirmed mappings for explicit zone members.</p>
            <details><summary>Review affected mappings</summary><ul>{suggestion.affected.map((name) => <li key={name}>{name}</li>)}</ul></details>
            <button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyRuleSuggestion(suggestion))}>Apply to {suggestion.affected.length} mappings</button>
          </article>)}
          {visibleGroups.slice((groupPage - 1) * 10, groupPage * 10).map((group) => <article className={`review-work-card queue-${group.queue.toLowerCase()}`} key={`${group.source_vdom}:${group.source_kind}:${group.source_name}`}>
            <div className="review-work-heading"><div><h3>{group.source_kind === 'vdom' ? `${group.source_name} VDOM` : group.source_name}</h3><p>{group.source_vdom} · {group.source_kind}{typeof group.source_evidence.source_type === 'string' ? ` · ${group.source_evidence.source_type}` : ''}</p></div><span className="review-work-badge">{group.queue.replaceAll('_', ' ')}</span></div>
            {(review.architecture_questions ?? []).filter((question) => question.source_vdom === group.source_vdom && question.source_name === group.source_name).map((question) => <div className="review-work-suggestion" key={`${question.type}:${question.source_name}`}>
              <p>{question.type === 'AGGREGATE_MAPPING' ? `Architecture question: Which PAN aggregate replaces this interface? ${question.affected_count ?? 0} VLAN mappings will be re-evaluated.` : question.type === 'VDOM_CONTEXT' ? 'Architecture question: Choose the target VSYS and virtual router for this VDOM.' : 'Architecture question: Choose the PAN zone for this source zone.'}</p>
              {question.type === 'VDOM_CONTEXT' ? question.fields?.filter((item) => item.suggested_value).map((item) => <button className="secondary-button" type="button" key={item.key} onClick={() => setDrafts((current) => ({ ...current, [item.key]: item.suggested_value ?? '' }))}>{item.target_field === 'vsys' ? 'VSYS' : 'VR'}: {item.suggested_value}</button>) : (question.candidates ?? []).map((value) => <button className="secondary-button" type="button" key={value} onClick={() => question.decision_key && setDrafts((current) => ({ ...current, [question.decision_key as string]: value }))}>Use {value}</button>)}
            </div>)}
            {group.decisions.filter((item) => item.mode !== 'UNSUPPORTED').map((decision) => {
              const value = drafts[decision.key] ?? decision.value ?? decision.suggested_value ?? ''
              const candidates = group.candidates[decision.key] ?? review.decision_candidates[decision.key] ?? []
              return <div className="review-work-field" key={decision.key}>
                <label>{decision.target_field.replaceAll('_', ' ')}<input id={`decision-${decision.key}`} disabled={busy} aria-label={`${decision.target_field} for ${group.source_name}`} value={value} onChange={(event) => setDrafts((current) => ({ ...current, [decision.key]: event.target.value }))} placeholder={decision.suggested_value ? `Suggested: ${decision.suggested_value}` : 'Enter mapping'} /></label>
                {decision.suggested_value && decision.review_state !== 'CONFIRMED' && <p className="review-work-suggestion">Suggested: {decision.suggested_value}</p>}
                {candidates.length > 0 && <details className="review-work-candidates"><summary>{candidates.length} possible matches</summary>{candidates.map((candidate) => <div className="review-work-candidate" key={candidate.value}><span>{candidate.class === 'STRONG' ? 'Recommended' : 'Possible match'}: {candidate.value}{candidate.target_scope ? ` · ${candidate.target_scope}` : ''}</span><button className="text-button" type="button" onClick={() => setDrafts((current) => ({ ...current, [decision.key]: candidate.value }))}>Use</button><details><summary>Why?</summary><ul>{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].map((fact) => <li key={fact}>{fact}</li>)}</ul></details></div>)}</details>}
                {proposals.find((item) => item.decision_key === decision.key) && <p className="review-work-suggestion">AI proposal is available in the optional AI review section.</p>}
              </div>
            })}
            <div className="review-work-impact"><p>{group.affected_count} affected objects · {group.dependent_decision_count} dependent mappings will be re-evaluated</p>{group.next_action && <p>Next action: {group.next_action}</p>}
              {Object.keys(group.source_evidence).length > 0 && <details><summary>Source facts</summary><ul>{Object.entries(group.source_evidence).map(([key, value]) => <li key={key}>{key.replace(/^source_/, '').replaceAll('_', ' ')}: {Array.isArray(value) ? value.join(', ') || '(explicitly empty)' : String(value)}</li>)}</ul></details>}
            </div>
            {group.decisions.filter((item) => item.mode === 'UNSUPPORTED').map((item) => <p key={item.key}>Unsupported: {item.target_field} · {item.reason}</p>)}
            {group.actions?.map((action) => <div key={`${action.type}:${action.source_key}`}><details><summary>Review member decision scope</summary><p>{group.source_vdom} · {action.source_key} → {action.value}</p><ul>{action.apply_to.map((key) => <li key={key}>{key}</li>)}</ul></details><button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyGroupAction(action))}>Apply {action.value} to {action.apply_to.length} member decisions</button></div>)}
            {group.decisions.some((item) => item.mode !== 'UNSUPPORTED') && <button className="primary-button" type="button" disabled={busy || !group.decision_keys.some((key) => (drafts[key] ?? decisions.find((item) => item.key === key)?.value ?? decisions.find((item) => item.key === key)?.suggested_value ?? '').trim())} onClick={() => void run(() => confirmGroup(group), 'Mapping confirmed.')}>Confirm mapping</button>}
          </article>)}
          <div className="report-pager"><button type="button" className="secondary-button" disabled={groupPage <= 1} onClick={() => setGroupPage((page) => page - 1)}>Previous groups</button><span role="status">Page {groupPage} of {Math.max(1, Math.ceil(visibleGroups.length / 10))} · {visibleGroups.length} groups</span><button type="button" className="secondary-button" disabled={groupPage * 10 >= visibleGroups.length} onClick={() => setGroupPage((page) => page + 1)}>Next groups</button></div>
          </div>
        </section>

    </>
  )
}
