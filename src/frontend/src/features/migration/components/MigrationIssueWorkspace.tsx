import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { MigrationIssue, MigrationReviewTab } from '../types'
import { Button } from '../../../components/common/Button'
import { groupManualIssues, migrationIssueImpact, migrationIssueReason, migrationIssueSourceCount, migrationIssueTasks, migrationIssueTitle, migrationIssueWork } from '../reviewPresentation'

const PAGE_SIZE = 10
const categoryLabels: Record<MigrationIssue['category'], string> = {
  CHOICE: 'Target choice', PREREQUISITE: 'Prerequisite', CONFLICT: 'Conflict', MANUAL: 'Separate review or implementation',
}

export function MigrationIssueWorkspace({ issues, configurationKeys, tab, contextKey, selectedId, onSelect, onRoute, renderAction }: {
  issues: MigrationIssue[]
  configurationKeys: ReadonlySet<string>
  tab: Exclude<MigrationReviewTab, 'changes'>
  contextKey: string
  selectedId: string
  onSelect: (id: string) => void
  onRoute: (issue: MigrationIssue) => void
  renderAction?: (issue: MigrationIssue) => ReactNode
}) {
  const initialFilters = { contextKey, search: '', type: 'all', vdom: 'all', page: 1 }
  const [filters, setFilters] = useState(initialFilters)
  const current = filters.contextKey === contextKey ? filters : initialFilters
  const changeFilter = (values: Partial<typeof initialFilters>) => {
    setFilters({ ...current, page: 1, ...values })
    onSelect('')
  }
  const { search, type, vdom, page } = current
  const manual = tab === 'manual'
  const tasks = useMemo(() => migrationIssueTasks(issues, tab), [issues, tab])
  const vdoms = [...new Set(tasks.map((issue) => issue.source_vdom))].sort()
  const filtered = tasks.filter((issue) => (type === 'all' || issue.category === type)
    && (vdom === 'all' || issue.source_vdom === vdom)
    && `${issue.source_vdom} ${issue.source_kind} ${issue.source_name} ${issue.code} ${issue.explanation} ${migrationIssueTitle(issue)}`.toLowerCase().includes(search.trim().toLowerCase()))
  const groups = manual ? groupManualIssues(filtered) : filtered.map((issue) => ({ id: issue.id, issues: [issue] }))
  const pages = Math.max(1, Math.ceil(groups.length / PAGE_SIZE))
  const selectedIndex = groups.findIndex((group) => group.issues.some((issue) => issue.id === selectedId))
  const currentPage = selectedIndex < 0 ? Math.min(page, pages) : Math.floor(selectedIndex / PAGE_SIZE) + 1
  const visible = groups.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)
  const selected = visible.find((group) => group.issues.some((issue) => issue.id === selectedId)) ?? visible[0]
  return <section className="migration-issue-workspace" aria-label={manual ? 'Work outside this tool' : 'Needs your input'}>
    <p>{manual ? 'These findings have no supported fix in this editor. Review the reason and affected items, then arrange separate review or implementation.'
      : 'Choose a task, enter the required target choice or correct the source, then validate all pending edits. Approval happens separately in Changes.'}</p>
    <div className="migration-issue-filters">
      <label className="field">Search<input aria-label="Search tasks" placeholder="Object name or reason" value={search} onChange={(event) => changeFilter({ search: event.target.value })} /></label>
      <label className="field">Task type<select aria-label="Task type" value={type} onChange={(event) => changeFilter({ type: event.target.value })}>
        <option value="all">All types</option>{[...new Set(tasks.map((issue) => issue.category))].map((item) => <option key={item} value={item}>{categoryLabels[item]}</option>)}
      </select></label>
      <label className="field">Source VDOM<select aria-label="Task VDOM" value={vdom} onChange={(event) => changeFilter({ vdom: event.target.value })}>
        <option value="all">All VDOMs</option>{vdoms.map((item) => <option key={item} value={item}>{item}</option>)}
      </select></label>
    </div>
    <p className="migration-issue-counts" role="status">Issues: {filtered.length}{manual ? ` · Reason groups: ${groups.length}` : ''} · Unique source objects: {migrationIssueSourceCount(filtered)} · Linked configuration items: {migrationIssueImpact(filtered, configurationKeys)}. Impact can overlap between tasks.</p>
    {!filtered.length ? <p>{tasks.length ? 'No tasks match these filters.' : manual ? 'No separate work is currently reported.' : 'No input is currently required. Review supported configuration in Changes.'}</p> : <>
      <ul className="migration-issue-list" style={{ gridTemplateRows: `repeat(${visible.length}, auto)` }}>
        {visible.map((group) => {
          const issue = group.issues[0]
          const active = selected?.id === group.id
          const detailId = `migration-${tab}-detail-${group.id}`
          return <li key={group.id} className={active ? 'selected' : ''}>
            <button className="migration-issue-task" type="button" aria-current={active ? 'true' : undefined} aria-controls={active ? detailId : undefined}
              onClick={() => onSelect(issue.id)}>
              <strong>{manual ? migrationIssueTitle(issue) : issue.source_name}</strong>
              <span>{issue.source_vdom} · {issue.source_kind.replaceAll('_', ' ')}{manual ? ` · Issues: ${group.issues.length}` : ''}</span>
              {!manual && <span>{migrationIssueTitle(issue)}</span>}
              <span>Source objects: {migrationIssueSourceCount(group.issues)} · Linked configuration items: {migrationIssueImpact(group.issues, configurationKeys)}</span>
              <span className="migration-issue-task-action">{active ? 'Selected task' : manual ? 'Review work' : 'Review task'}</span>
            </button>
            {active && <article id={detailId} className="migration-issue-detail" aria-label={`Task details: ${migrationIssueTitle(issue)}`} style={{ gridRow: `1 / span ${visible.length}` }}>
              <h3>{migrationIssueTitle(issue)}</h3>
              <p>{issue.source_vdom} · {manual ? `Issues: ${group.issues.length}` : issue.source_name}</p>
              <h4>{manual ? 'Reason / work needed' : 'What is needed'}</h4>
              <p>{migrationIssueReason(issue)}</p>
              {manual ? <>
                <h4>Required work</h4><p>{migrationIssueWork(issue)}</p>
                <p>Reading these findings does not resolve them or enable command generation for blocked items.</p>
                <IssueMembers key={group.id} issues={group.issues} configurationKeys={configurationKeys} />
              </> : <>
                <h4>Why it is needed</h4>
                <p>{issue.action?.kind === 'REVIEW_SOURCE' ? 'The source evidence needs correction before the affected configuration can be reviewed.'
                  : 'The affected configuration cannot be approved until this choice and its prerequisites pass validation.'}</p>
                <h4>Your choice</h4>
                {issue.action?.kind === 'REVIEW_SOURCE' ? <Button className="secondary-button" onClick={() => onRoute(issue)}>Review source</Button> : renderAction?.(issue)}
                {!!issue.prerequisite_keys.length && <details open><summary>Required first ({issue.prerequisite_keys.length})</summary><ul>
                  {issue.prerequisite_keys.map((key) => {
                    const prerequisite = tasks.find((item) => item.action?.kind === 'EDIT_MAPPING' && item.action.decision_key === key)
                    return <li key={key}>{prerequisite ? <Button className="text-button" onClick={() => {
                      const index = tasks.findIndex((item) => item.id === prerequisite.id)
                      setFilters({ ...initialFilters, page: Math.floor(index / PAGE_SIZE) + 1 }); onSelect(prerequisite.id)
                    }}>{prerequisite.source_vdom} / {prerequisite.source_name}</Button> : 'Related placement requires review in Target setup.'}</li>
                  })}
                </ul></details>}
                <IssueEvidence key={issue.id} issue={issue} configurationKeys={configurationKeys} />
              </>}
            </article>}
          </li>
        })}
      </ul>
      {groups.length > PAGE_SIZE && <div className="report-pager"><Button className="secondary-button" disabled={currentPage <= 1} onClick={() => changeFilter({ page: currentPage - 1 })}>Previous</Button><span>Page {currentPage} of {pages}</span><Button className="secondary-button" disabled={currentPage >= pages} onClick={() => changeFilter({ page: currentPage + 1 })}>Next</Button></div>}
    </>}
  </section>
}

function IssueMembers({ issues, configurationKeys }: { issues: MigrationIssue[]; configurationKeys: ReadonlySet<string> }) {
  const [page, setPage] = useState(1)
  const pages = Math.max(1, Math.ceil(issues.length / PAGE_SIZE))
  const currentPage = Math.min(page, pages)
  return <><h4>Affected findings</h4>
    {issues.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE).map((issue) => <details key={issue.id}>
      <summary>{issue.source_vdom} / {issue.source_name} · {issue.source_kind.replaceAll('_', ' ')}</summary>
      <IssueEvidence issue={issue} configurationKeys={configurationKeys} />
    </details>)}
    {pages > 1 && <div className="report-pager"><Button className="secondary-button" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous findings</Button><span>Findings page {currentPage} of {pages}</span><Button className="secondary-button" disabled={currentPage === pages} onClick={() => setPage(currentPage + 1)}>Next findings</Button></div>}
  </>
}

function IssueEvidence({ issue, configurationKeys }: { issue: MigrationIssue; configurationKeys: ReadonlySet<string> }) {
  const [page, setPage] = useState(1)
  const pages = Math.max(1, Math.ceil(issue.affected_sources.length / 30))
  const currentPage = Math.min(page, pages)
  return <>
    <h4>What this affects</h4><p>Source objects: {issue.affected_sources.length} · Linked configuration items: {migrationIssueImpact([issue], configurationKeys)}. Counts may overlap with other tasks.</p>
    {migrationIssueImpact([issue], configurationKeys) === 0 && <p>The draft has not linked configuration-item keys for this finding. Review the source objects below to assess its impact.</p>}
    {!!issue.affected_sources.length && <details><summary>Affected source objects ({issue.affected_sources.length})</summary>
      <ul>{issue.affected_sources.slice((currentPage - 1) * 30, currentPage * 30).map((item, index) => <li key={index}>{item.source_vdom} / {item.source_kind} / {item.source_name}</li>)}</ul>
      {pages > 1 && <div className="report-pager"><Button className="secondary-button" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous objects</Button><span>Objects page {currentPage} of {pages}</span><Button className="secondary-button" disabled={currentPage === pages} onClick={() => setPage(currentPage + 1)}>Next objects</Button></div>}
    </details>}
    <details><summary>Technical evidence</summary><p>Code: {issue.code} · Resolution: {issue.resolution_kind}</p><p>Reported reason: {issue.explanation}</p>
      {!!issue.explanations?.length && <ul className="migration-technical-reasons">{issue.explanations.map((reason, index) => <li key={index}>{reason}</li>)}</ul>}
    </details>
  </>
}
