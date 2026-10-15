import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Button } from '../../../components/common/Button'
import type { ConversionSettings, DraftRow, MigrationDraft } from '../types'
import type { ReviewData } from '../reviewTypes'
import { draftRowKey, interfaceMappingRows, orderInterfaceMappings } from '../reviewDrafts'
import { mappingSummary, taskCategory } from '../reviewPresentation'
import { MigrationMappingSummary } from './MigrationMappingSummary'

export function MigrationTargetSetup({ draft, review, drafts, approvedItems, busy, focusRequest, onChange, onApply, onReview, settings, onSettingsChange, settingsDirty = false, approvalRevoked = false, onUndo, onViewIssues, hardwareCheck, managementAccess }: {
  draft: MigrationDraft
  review: ReviewData
  drafts: Record<string, string>
  approvedItems: string[]
  busy: boolean
  focusRequest?: { key: string; request: number } | null
  onChange: (key: string, value: string) => void
  onApply: () => void
  onReview: () => void
  settings: ConversionSettings
  onSettingsChange: (settings: ConversionSettings) => void
  settingsDirty?: boolean
  approvalRevoked?: boolean
  onUndo: () => void
  onViewIssues: () => void
  hardwareCheck?: ReactNode
  managementAccess?: ReactNode
}) {
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const handledFocus = useRef<typeof focusRequest>(null)
  const rows = draft.decisions
  const byKey = useMemo(() => new Map([...rows, ...draft.configuration].map((row) => [draftRowKey(row), row])), [rows, draft.configuration])
  const approved = new Set(approvedItems)
  const valueFor = (row: DraftRow) => drafts[row.decision_key!] ?? row.proposed_value ?? ''
  const changed = rows.filter((row) => valueFor(row).trim() !== (row.proposed_value ?? ''))
  const excluded = settings?.excluded_interfaces ?? []
  const counts = mappingSummary(rows, byKey, approved, draft.context?.conversion_settings?.excluded_interfaces ?? [])
  const pending = changed.length > 0 || settingsDirty
  const context = review.decision_context ?? {}
  const interfaces = useMemo(() => orderInterfaceMappings(interfaceMappingRows(review.decisions.decisions, drafts, {}), review.decision_context ?? {}, rows)
    .map(({ decision }) => byKey.get(decision.key)).filter((row): row is DraftRow => !!row), [review, drafts, rows, byKey])
  const filtered = interfaces.filter((row) => `${row.source_vdom} ${row.source_name} ${valueFor(row)}`.toLowerCase().includes(search.toLowerCase()))
  const pages = Math.max(1, Math.ceil(filtered.length / 25))
  const currentPage = Math.min(page, pages)
  const ownership = rows.filter((row) => row.source_kind === 'vdom').sort((a, b) => Number(b.target_field === 'vsys') - Number(a.target_field === 'vsys'))
  const zones = rows.filter((row) => row.source_kind === 'zone')
  const sourceProblem = (row: DraftRow) => row.source_kind === 'interface' && draft.source_issues?.find((issue) =>
    issue.code === 'SOURCE_INTERFACE_MISSING' && issue.source_vdom === row.source_vdom && issue.source_name === row.source_name)
  const unavailable = (row: DraftRow) => row.status === 'UNSUPPORTED' || !!sourceProblem(row)
  const attention = (draft.issues ?? []).filter((issue) => {
    const row = issue.action && byKey.get(issue.action.decision_key)
    return ['CHOICE', 'CONFLICT'].includes(issue.category) && row && !unavailable(row)
      && !draft.source_issues?.some((source) => source.source_vdom === row.source_vdom && source.source_name === row.source_name)
  })
  useEffect(() => {
    if (!focusRequest || handledFocus.current === focusRequest) return
    handledFocus.current = focusRequest
    const target = byKey.get(focusRequest.key)
    const index = interfaces.findIndex((row) => row.source_vdom === target?.source_vdom && row.source_name === target?.source_name)
    // Synchronize a navigation request with the paginated mapping editor.
    setSearch('')
    setPage(index < 0 ? 1 : Math.floor(index / 25) + 1)
    requestAnimationFrame(() => {
      const field = document.getElementById(`setup-${focusRequest.key}`)
      const details = field?.closest('details')
      if (details) details.open = true
      field?.scrollIntoView({ block: 'center' })
      field?.focus()
    })
  }, [focusRequest, byKey, interfaces])
  const status = (row: DraftRow) => valueFor(row).trim() !== (row.proposed_value ?? '') ? 'Pending validation'
    : row.status === 'CONFLICT' ? 'Conflict' : taskCategory(row, byKey, approved)
  const input = (row: DraftRow, label: string) => unavailable(row)
    ? <div id={`setup-${row.decision_key}`} tabIndex={-1}>
      <strong>{sourceProblem(row) ? 'Source interface missing' : 'Not converted automatically'}</strong>
      <small className="mapping-topology">{sourceProblem(row) ? 'Correct the source configuration and upload it again. A target interface name alone cannot resolve this source gap.'
        : row.blocking_reasons.filter((reason) => !reason.startsWith('Unresolved prerequisite:')).join('; ') || 'Separate target design required. Excluded from generated commands.'}</small>
    </div>
    : <input id={`setup-${row.decision_key}`} aria-label={label} value={valueFor(row)}
      disabled={busy} placeholder="Enter target value"
      onChange={(event) => onChange(row.decision_key!, event.target.value)} />
  return <section className="target-setup" aria-label="Offline target setup">
    <p>Review the automatically proposed physical ports and target ownership. Dependent VLANs, routes, NAT and policies reuse these mappings. Proposals require final approval.</p>
    {(!!draft.source_issues?.length || !!attention.length) && <section aria-label="Needs attention">
      <h3>Needs attention</h3>
      {!!draft.source_issues?.length && <h4>Source corrections</h4>}
      {draft.source_issues?.map((issue) => <article className="migration-issue" key={`${issue.code}:${issue.source_vdom}:${issue.source_name}`}>
        <strong>{issue.source_vdom} / {issue.source_name}</strong>
        <p>{issue.code === 'SOURCE_INTERFACE_IPV4_INVALID' ? 'Invalid primary IPv4 address' : issue.code === 'SOURCE_INTERFACE_MISSING' ? 'Source interface missing' : 'Source configuration needs correction'}</p>
        <small>{new Set(issue.affected_keys).size} dependent configuration items</small>
        <p>Correct the source configuration and upload it again.</p>
        <details><summary>Details</summary><p>{issue.message}</p></details>
      </article>)}
      {!!attention.length && <h4>Target decisions</h4>}
      {attention.slice(0, 5).map((issue) => <article className="migration-issue" key={issue.id}><strong>{issue.source_vdom} / {issue.source_name}</strong><p>{issue.explanation}</p> <Button className="secondary-button" disabled={busy} onClick={() => {
        const key = issue.action!.decision_key
        const target = byKey.get(key)
        const index = interfaces.findIndex((row) => row.source_vdom === target?.source_vdom && row.source_name === target?.source_name)
        setSearch(''); setPage(index < 0 ? 1 : Math.floor(index / 25) + 1)
        requestAnimationFrame(() => { const field = document.getElementById(`setup-${key}`); field?.scrollIntoView({ block: 'center' }); field?.focus() })
      }}>Review mapping</Button></article>)}
      <Button className="secondary-button" disabled={busy} onClick={onViewIssues}>View all issues</Button>
    </section>}
    <MigrationMappingSummary counts={counts} pending={pending} />
    <section aria-label="Target placement">
      <h3>Target placement</h3>
      <p>Choose where each VDOM’s configuration will be created. Proposed names require final approval.</p>
      <div className="target-ownership">
        {[...new Set(ownership.map((row) => row.source_vdom))].map((vdom) => <fieldset key={vdom}><legend>VDOM: {vdom}</legend>
          {ownership.filter((row) => row.source_vdom === vdom).map((row) => <label className="field" key={row.decision_key}>
            {row.target_field === 'vsys' ? 'Target VSYS' : 'Virtual router'}
            {input(row, `${row.target_field === 'vsys' ? 'VSYS' : 'Virtual router'} for ${vdom}`)}
            <small>{status(row)}</small>
          </label>)}
        </fieldset>)}
      </div>
    </section>
    {hardwareCheck}
    {(interfaces.length > 0 || zones.length > 0) && <section aria-label="Target interface mappings">
      <h3>Interfaces and zones</h3>
      <p>Physical ports are proposed as ethernet1/N allocations. Verify that the ports exist on your target and match the intended cabling before approval. Edit a shared source zone once below. Unsupported interfaces show their reason and remain excluded from commands.</p>
      {!!zones.length && <div className="target-ownership" aria-label="Shared source zones">
        {zones.map((row) => <label className="field" key={row.decision_key}>{row.source_vdom} / {row.source_name} — shared target zone
          {input(row, `Source zone for ${row.source_vdom} / ${row.source_name}`)}
          <small>{status(row)}</small>
          <small>Source members: {Array.isArray(context[row.decision_key!]?.source_members) ? (context[row.decision_key!].source_members as string[]).join(', ') : 'Not explicitly configured'}</small>
        </label>)}
      </div>}
      <label className="field target-setup-search">Search interfaces<input value={search} onChange={(event) => { setSearch(event.target.value); setPage(1) }} /></label>
      <div className="report-table-wrap"><table className="report-table target-setup-table">
        <thead><tr><th>Source / inclusion</th><th>Target interface</th><th>Proposed zone</th><th>State</th></tr></thead>
        <tbody>{filtered.slice((currentPage - 1) * 25, currentPage * 25).map((row) => {
          const facts = context[row.decision_key!] ?? {}
          const zone = rows.find((candidate) => candidate.source_vdom === row.source_vdom && candidate.source_kind === 'interface'
            && candidate.source_name === row.source_name && candidate.target_field === 'target_zone')
          const sharedZone = zone?.dependencies.map((key) => byKey.get(key)).find((parent) => parent?.source_kind === 'zone')
          const zoneOverride = zone && (Object.hasOwn(draft.context?.overrides ?? {}, zone.decision_key!)
            || (drafts[zone.decision_key!] != null && drafts[zone.decision_key!] !== (zone.proposed_value ?? ''))
            || zone.proposed_value !== sharedZone?.proposed_value)
          const identity = `${row.source_vdom}/${row.source_name}`
          const included = !excluded.includes(identity)
          const explicitlyExcluded = (draft.context?.conversion_settings?.excluded_interfaces ?? []).includes(identity)
          const canChooseScope = !sourceProblem(row) && (row.status !== 'UNSUPPORTED' || explicitlyExcluded)
          return <tr key={row.decision_key}>
            <td><strong>{row.source_vdom} / {row.source_name}</strong><small className="mapping-topology">
              {String(facts.source_type ?? 'Type not explicit')}{facts.source_parent ? ` · parent ${facts.source_parent}` : ''}{facts.source_vlan != null ? ` · VLAN ${facts.source_vlan}` : ''}
            </small>
              {canChooseScope && <label className="interface-inclusion"><input type="checkbox" aria-label={`Include ${identity} in conversion`} checked={included} disabled={busy}
                onChange={(event) => onSettingsChange({ ...settings, excluded_interfaces: event.target.checked ? excluded.filter((key) => key !== identity) : [...excluded, identity] })} /> Include in conversion</label>}
              {!included && <small className="mapping-topology">Explicitly excluded. Source evidence is retained; dependent configuration stays blocked.</small>}
              {included !== !explicitlyExcluded && <small className="mapping-topology">Inclusion changed. Validate to update dependent configuration.</small>}
            </td>
            <td>{input(row, `Target interface for ${row.source_vdom} / ${row.source_name}`)}{!!row.evidence?.length && <details><summary>Proposal evidence</summary><ul>{row.evidence.map((fact, index) => <li key={index}>{fact}</li>)}</ul></details>}</td>
            <td>{unavailable(row) ? 'Not generated' : zone && sharedZone && !zoneOverride
              ? <span id={`setup-${zone.decision_key}`} tabIndex={-1}>{valueFor(sharedZone)}<small className="mapping-topology">From source zone {sharedZone.source_name}. Shared edits are validated when mappings are applied.</small></span>
              : zone ? input(zone, `Zone for ${zone.source_vdom} / ${zone.source_name}`) : 'No zone decision required'}</td>
            <td>{status(row)}{zone && status(zone) !== status(row) && <small className="mapping-topology">Zone: {status(zone)}</small>}</td>
          </tr>
        })}</tbody>
      </table></div>
      {!filtered.length && <p>No interfaces match this search.</p>}
      {pages > 1 && <div className="report-pager"><Button className="secondary-button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>Previous interfaces</Button>
        <span>Page {currentPage} of {pages}</span><Button className="secondary-button" disabled={currentPage >= pages} onClick={() => setPage(currentPage + 1)}>Next interfaces</Button></div>}
    </section>}
    {managementAccess}
    <div className="action-row target-setup-actions">
      {pending || approvalRevoked ? <Button disabled={busy || (!settingsDirty && changed.length > 0 && !changed.some((row) => valueFor(row).trim()))} onClick={onApply}>Validate changes</Button>
        : <Button disabled={busy} onClick={onReview}>Continue to configuration review</Button>}
      {pending && <Button className="secondary-button" disabled={busy} onClick={onUndo}>Undo pending edits</Button>}
      {pending && <span role="status">{changed.length} edited mapping fields{settingsDirty ? ' · settings changed' : ''}. Validation does not approve changes.</span>}
      {changed.some((row) => !valueFor(row).trim()) && <span>Blank edits stay local and unresolved. Restore a value or undo pending edits before continuing.</span>}
      {busy && <span>Validation is running or the draft needs revalidation.</span>}
      {approvalRevoked && !pending && <span>Edits were undone. Validate the draft again before approval.</span>}
    </div>
  </section>
}
