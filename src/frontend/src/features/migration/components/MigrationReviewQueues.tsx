import { candidateLabel, decisionLabel } from '../reviewDrafts'
import type { Dispatch, SetStateAction } from 'react'
import { tabKeyboard } from '../../../components/common/tabKeyboard'
import type { Decision, ReviewData, ReviewGroup, RuleSuggestion } from '../reviewTypes'

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
  busy,
  run,
  applyRuleSuggestion,
  applyGroupAction,
  confirmGroup,
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
  busy: boolean
  run: RunAction
  applyRuleSuggestion: (suggestion: RuleSuggestion) => Promise<void>
  applyGroupAction: (action: NonNullable<ReviewGroup['actions']>[number]) => Promise<void>
  confirmGroup: (group: ReviewGroup) => Promise<void>
}) {
  return (
    <>
        <section className="review-workflow" aria-label="Migration review queues">
          <nav className="review-queues" role="tablist" aria-label="Migration review work queues" onKeyDown={tabKeyboard}>
            {queueNames.map((queue) => <button type="button" role="tab" key={queue} id={`queue-tab-${queue}`} aria-controls={`queue-panel-${queue}`} tabIndex={activeQueue === queue ? 0 : -1} aria-selected={activeQueue === queue} onClick={() => { setActiveQueue(queue); setSelectedGroupKey('') }}>
              {({ READY_TO_CONFIRM: 'Review suggestions', CHOOSE_CANDIDATE: 'Choose a match', NEEDS_INPUT: 'Needs input', CONFLICT: 'Conflicts', COMPLETE: 'Completed' } as Record<string, string>)[queue]} <span>{reviewGroups.filter((group) => group.queue === queue).length} groups</span>
            </button>)}
          </nav>
          {queueNames.filter((queue) => queue !== activeQueue).map((queue) => <div key={queue} hidden role="tabpanel" id={`queue-panel-${queue}`} aria-labelledby={`queue-tab-${queue}`} />)}
          <div role="tabpanel" id={`queue-panel-${activeQueue}`} aria-labelledby={`queue-tab-${activeQueue}`} tabIndex={0}>
          <div className="migration-toolbar">
            <label className="field">Search review groups<input value={search} onChange={(event) => { setSearch(event.target.value); setSelectedGroupKey('') }} placeholder="Search source mappings" /></label>
            <label className="field">VDOM<select value={vdomFilter} onChange={(event) => { setVdomFilter(event.target.value); setSelectedGroupKey(''); setDecisionPage(1) }}><option value="all">All VDOMs</option>{vdoms.map((item) => <option key={item}>{item}</option>)}</select></label>
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
              {visibleGroups.map((group) => <button type="button" key={group.decision_keys[0]} aria-current={selectedGroupKey === group.decision_keys[0] || (!visibleGroups.some((item) => item.decision_keys[0] === selectedGroupKey) && group === visibleGroups[0]) ? 'true' : undefined} onClick={() => setSelectedGroupKey(group.decision_keys[0])}>
                <strong>{group.source_name}</strong><span>{group.source_vdom} · {group.source_kind}</span><span>{({ READY_TO_CONFIRM: 'Review suggestion', CHOOSE_CANDIDATE: 'Choose a match', NEEDS_INPUT: 'Needs input', CONFLICT: 'Conflict', COMPLETE: 'Completed' } as Record<string, string>)[group.queue]}</span>
              </button>)}
            </nav>
            <div className="mapping-editor">
          {visibleGroups.filter((group) => group === (visibleGroups.find((item) => item.decision_keys[0] === selectedGroupKey) ?? visibleGroups[0])).map((group) => <article className={`review-work-card queue-${group.queue.toLowerCase()}`} key={`${group.source_vdom}:${group.source_kind}:${group.source_name}`}>
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
                <p className="review-work-suggestion">{decisionLabel(decision, candidates, group.conflicts?.some((finding) => finding.decision_key === decision.key))}{decision.suggested_value && decision.review_state !== 'CONFIRMED' ? `: ${decision.suggested_value} · requires confirmation` : ''}</p>
                <p>{decision.reason}{decision.evidence_source ? ` · ${decision.evidence_source}` : ''}{decision.evidence_type ? ` · ${decision.evidence_type}` : ''}</p>
                {candidates.length > 0 && <details className="review-work-candidates"><summary>{candidates.filter((item) => item.available !== false).length} available candidates</summary>{candidates.map((candidate) => <div className="review-work-candidate" key={`${candidate.target_scope}:${candidate.value}`}><span>{candidateLabel(candidate)}: {candidate.value}{candidate.target_scope ? ` · ${candidate.target_scope}` : ''}</span><button className="text-button" type="button" disabled={busy || candidate.available === false} onClick={() => setDrafts((current) => ({ ...current, [decision.key]: candidate.value }))}>Use</button><details><summary>Why?</summary><ul>{[...(candidate.strong_evidence ?? []), ...(candidate.supporting_evidence ?? [])].map((fact) => <li key={fact}>{fact}</li>)}</ul></details></div>)}</details>}
              </div>
            })}
            <div className="review-work-impact"><p>{group.affected_count} affected objects · {group.dependent_decision_count} dependent mappings will be re-evaluated</p>{group.next_action && <p>Next action: {group.next_action}</p>}
              {Object.keys(group.source_evidence).length > 0 && <details><summary>Source facts</summary><ul>{Object.entries(group.source_evidence).map(([key, value]) => <li key={key}>{key.replace(/^source_/, '').replaceAll('_', ' ')}: {Array.isArray(value) ? value.join(', ') || '(explicitly empty)' : String(value)}</li>)}</ul></details>}
            </div>
            {group.decisions.filter((item) => item.mode === 'UNSUPPORTED').map((item) => <p key={item.key}>Unsupported: {item.target_field} · {item.reason}</p>)}
            {group.actions?.map((action) => <div key={`${action.type}:${action.source_key}`}><details><summary>Review member decision scope</summary><p>{group.source_vdom} · {action.source_key} → {action.value}</p><ul>{action.apply_to.map((key) => <li key={key}>{key}</li>)}</ul></details><button className="secondary-button" type="button" disabled={busy} onClick={() => void run(() => applyGroupAction(action))}>Apply {action.value} to {action.apply_to.length} member decisions</button></div>)}
            {group.decisions.some((item) => item.mode !== 'UNSUPPORTED') && <button className="primary-button" type="button" disabled={busy || !group.decision_keys.some((key) => (drafts[key] ?? decisions.find((item) => item.key === key)?.value ?? decisions.find((item) => item.key === key)?.suggested_value ?? '').trim())} onClick={() => void run(() => confirmGroup(group))}>Confirm mapping</button>}
          </article>)}
          </div></div>
          </div>
        </section>

    </>
  )
}
