import { useEffect, useMemo, useRef, useState } from 'react'
import type { RefObject } from 'react'
import type { SourcePreviewData } from '../source/types'
import { activeSubsection, asRecord, asRows, compactValue, interfaceTopologyRows, matchingSourceRows, reportCounts, reportSections, reportSectionRowCount, reportSearchText, rowColumns, safeValue, defaultColumns, cellSummary, columnWidth, fieldLabel, findingGroups, findingGroupKey } from './reportPresentation'
import { ReportDetails } from './ReportDetails'
import { ExcelExportControls } from './ExcelExportControls'
import { tabKeyboard } from '../../components/common/tabKeyboard'
import { ErrorBanner } from '../../components/common/ErrorBanner'

type Finding = Record<string, unknown>
const EMPTY_ROWS: Finding[] = []
type ValidationTarget = { section: string; label: string; rows: unknown[] }
type OverviewMetric = { label: string; value: number | null; section?: string; objectSection?: string; tone?: string }

const VALIDATION_TARGETS: Record<string, [string, string]> = {
  nat: ['nat', 'NAT'],
  interface: ['interfaces', 'Interfaces'],
  address: ['addresses', 'Addresses'],
  address6: ['addresses', 'Addresses'],
  address_group: ['address_groups', 'Address groups'],
  service: ['services', 'Services'],
  service_group: ['service_groups', 'Service groups'],
  policy: ['policies', 'Policies'],
  'default-security-rule': ['default_security_rules', 'Default security rules'],
  'security-profile-group': ['security_profile_groups', 'Security profile groups'],
  schedule: ['schedules', 'Schedules'],
  scheduler: ['schedules', 'Schedules'],
  time_range: ['schedules', 'Schedules'],
  route: ['routes', 'Routes'],
  static_route: ['routes', 'Routes'],
  'static-route': ['routes', 'Routes'],
  static_route6: ['routes', 'Routes'],
  vpn: ['vpn_tunnels', 'VPN tunnels'],
  'ipsec-tunnel': ['vpn_tunnels', 'VPN tunnels'],
  ipsec_phase1: ['vpn_tunnels', 'VPN tunnels'],
  vpn_phase2: ['vpn_phase2', 'VPN phase 2'],
}

function validationTarget(finding: Finding) {
  return VALIDATION_TARGETS[String(finding.object_type ?? '').toLowerCase()]
    ?? VALIDATION_TARGETS[String(finding.domain ?? '').toLowerCase()]
}

function text(value: unknown): string {
  if (value === null || value === undefined || value === '') return compactValue(value)
  if (Array.isArray(value)) return value.length ? value.map(text).join(', ') : '(empty list)'
  if (typeof value === 'object') return 'Structured details'
  return String(value)
}

function ValidationSummary({ rows, activeGroup, onGroupChange }: {
  rows: Finding[]
  activeGroup: string
  onGroupChange: (key: string) => void
}) {
  const ordered = findingGroups(rows)
  const errors = rows.filter((row) => String(row.severity).toLowerCase() === 'error').length
  const warnings = rows.filter((row) => String(row.severity).toLowerCase() === 'warning').length

  return <section className="validation-summary" aria-label="Validation summary">
    <div className="validation-counts"><strong>{rows.length} {rows.length === 1 ? 'finding' : 'findings'}</strong><span>{errors} {errors === 1 ? 'error' : 'errors'}</span><span>{warnings} {warnings === 1 ? 'warning' : 'warnings'}</span></div>
    <button type="button" className="secondary-button" aria-pressed={!activeGroup} onClick={() => onGroupChange('')}>All findings</button>
    {!!ordered.length && <div className="validation-groups" aria-label="Finding groups">{ordered.map((group) => { const key = group.key; return (
      <button type="button" key={key} className={`validation-group ${activeGroup === key ? 'active' : ''}`} aria-pressed={activeGroup === key} onClick={() => onGroupChange(activeGroup === key ? '' : key)}>
        <span className={`finding-severity severity-${String(group.row.severity ?? 'other').toLowerCase()}`}>{text(group.row.severity || 'Issue')}</span>
        <span className="finding-group-count">{group.count}</span>
        <span>{text(group.row.message || group.row.field || group.row.domain || 'Validation finding')}</span>
      </button>
    )})}</div>}
  </section>
}

function ValidationFilters({ rows, search, scope, severity, activeGroup, onSearch, onScope, onSeverity, onClear }: {
  rows: Finding[]
  search: string
  scope: string
  severity: string
  activeGroup: string
  onSearch: (value: string) => void
  onScope: (value: string) => void
  onSeverity: (value: string) => void
  onClear: () => void
}) {
  const scopes = [...new Set(rows.map((row) => String(row.scope || row.vdom || '')).filter(Boolean))].sort()
  return <div className="validation-filters" aria-label="Validation filters">
    <label>Search findings<input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search findings" /></label>
    <label>Severity<select value={severity} onChange={(event) => onSeverity(event.target.value)}><option value="">All severities</option>{[...new Set(['error', 'warning', ...rows.map((row) => String(row.severity ?? '').toLowerCase()).filter(Boolean)])].map((item) => <option key={item} value={item}>{fieldLabel(item)}</option>)}</select></label>
    <label>Scope<select value={scope} onChange={(event) => onScope(event.target.value)}><option value="">All scopes</option>{scopes.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
    <button type="button" className="filter-clear" disabled={!search && !scope && !severity && !activeGroup} onClick={onClear}>Clear filters</button>
  </div>
}

function ValidationTable({ rows, selected, onSelect, onNavigate, grouped }: {
  rows: Finding[]
  selected: Finding | null
  onSelect: (row: Finding) => void
  onNavigate: (row: Finding) => void
  grouped: boolean
}) {
  if (!rows.length) return <p className="validation-empty">No findings match the current filters.</p>
  return <div className="validation-table-wrap"><table className="validation-table"><thead><tr><th>Object</th><th>Scope</th><th>Domain / field</th><th>Severity</th>{!grouped && <th>Finding</th>}<th>Review</th></tr></thead>
    <tbody>{rows.map((row, index) => {
      const targetInfo = validationTarget(row)
      return <tr key={`${row.code ?? ''}-${row.domain ?? ''}-${row.object_name ?? ''}-${index}`} className={selected === row ? 'selected' : ''}>
        <td><strong>{text(row.object_name)}</strong></td><td>{text(row.scope ?? row.vdom)}</td><td>{text(row.domain)}<br />{text(row.field)}</td>
        <td><span className={`finding-severity severity-${String(row.severity ?? 'other').toLowerCase()}`}>{text(row.severity ?? 'Issue')}</span></td>
        {!grouped && <td><button type="button" className="finding-message" onClick={() => onSelect(row)}>{text(row.message)}</button></td>}
        <td><button type="button" className="finding-inline-link" onClick={() => onSelect(row)}>Details</button>{row.object_name != null && targetInfo != null ? <button type="button" className="finding-inline-link" onClick={() => onNavigate(row)}>View object →</button> : null}</td>
      </tr>
    })}</tbody></table></div>
}

function useScrollRows(filteredRows: Finding[], active = true) {
  const [renderedRowCount, setRenderedRowCount] = useState(200)
  const loadMoreRef = useRef<HTMLDivElement>(null)
  const [previousRows, setPreviousRows] = useState(filteredRows)
  if (previousRows !== filteredRows) { setPreviousRows(filteredRows); setRenderedRowCount(200) }
  useEffect(() => {
    const sentinel = loadMoreRef.current
    if (!active || !sentinel || renderedRowCount >= filteredRows.length || typeof IntersectionObserver === 'undefined') return
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) setRenderedRowCount((count) => Math.min(count + 200, filteredRows.length))
    }, { rootMargin: '600px' })
    observer.observe(sentinel)
    return () => observer.disconnect()
  }, [filteredRows, renderedRowCount, active])
  return { visibleRows: filteredRows.slice(0, renderedRowCount), loadMoreRef,
    loadMore: () => setRenderedRowCount((count) => Math.min(count + 200, filteredRows.length)) }
}

function ValidationReport({ data, reportScope, onReportScope, active }: { data: SourcePreviewData; reportScope: string; onReportScope: (scope: string) => void; active: boolean }) {
  const sections = asRecord(data.sections)
  const allRows = useMemo(() => asRows(sections.validation), [sections.validation])
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [activeGroup, setActiveGroup] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [target, setTarget] = useState<ValidationTarget | null>(null)
  const scopes = useMemo(() => [...new Set(allRows.map((row) => String(row.scope || row.vdom || '')).filter(Boolean))], [allRows])
  const scope = scopes.includes(reportScope) ? reportScope : ''
  const [requestedScope, setRequestedScope] = useState(reportScope)
  if (requestedScope !== reportScope) { setRequestedScope(reportScope); setSelected(null); setTarget(null) }

  const matchingRows = useMemo(() => {
    const query = search.toLowerCase()
    return allRows.filter((row) => {
      if (scope && (row.scope || row.vdom) !== scope) return false
      if (severity && String(row.severity || '').toLowerCase() !== severity) return false
      if (query) return reportSearchText(row).includes(query)
      return true
    })
  }, [allRows, scope, severity, search])
  const group = findingGroups(matchingRows).find((item) => item.key === activeGroup)
  const filteredRows = useMemo(() => matchingRows.filter((row) => !activeGroup
    || findingGroupKey(row) === activeGroup), [matchingRows, activeGroup])
  const { visibleRows, loadMoreRef, loadMore } = useScrollRows(filteredRows, active)

  function clearFilters() {
    setSearch('')
    onReportScope('')
    setSeverity('')
    setActiveGroup('')
  }

  function navigateToObject(finding: Finding) {
    const route = validationTarget(finding)
    if (!route || finding.object_name == null) return
    const rows = matchingSourceRows(asRows(sections[route[0]]), finding)
    setSelected(finding)
    setTarget({ section: route[0], label: route[1], rows: rows.map((row) => safeValue(row)) })
  }

  return <div className="validation-report">
    <h3>Validation findings</h3>
    <ValidationFilters rows={allRows} search={search} scope={scope} severity={severity} activeGroup={group?.key ?? ''} onSearch={(value) => { setSearch(value); setSelected(null) }} onScope={(value) => { onReportScope(value); setSelected(null) }} onSeverity={(value) => { setSeverity(value); setSelected(null) }} onClear={() => { clearFilters(); setSelected(null) }} />
    <ValidationSummary rows={matchingRows} activeGroup={group?.key ?? ''} onGroupChange={(key) => { setActiveGroup(key); setSelected(null) }} />
    {group && <p className="validation-group-explanation"><strong>{group.count} affected findings</strong> · {text(group.row.message)}</p>}
    <div className={`validation-workspace${selected && visibleRows.includes(selected) ? ' has-details' : ''}`}>
      <div><ValidationTable rows={visibleRows} selected={selected} grouped={!!group} onSelect={(row) => { setSelected(row); setTarget(null) }} onNavigate={navigateToObject} /><div ref={loadMoreRef} aria-hidden="true" style={{ height: 1 }} /></div>
      {active && selected && visibleRows.includes(selected) && <ReportDetails finding row={selected} target={target} onNavigate={() => navigateToObject(selected)} onClose={() => { setSelected(null); setTarget(null) }} />}
    </div>
    {!allRows.length && <p className="validation-empty">No validation findings were reported.</p>}
    {!!scopes.length && <p className="validation-scope-note">Findings are reported for {scopes.length} {scopes.length === 1 ? 'scope' : 'scopes'}.</p>}
    <p className="report-row-count" role="status">Showing {visibleRows.length.toLocaleString()} of {filteredRows.length.toLocaleString()} matching findings · {allRows.length.toLocaleString()} total</p>
    {visibleRows.length < filteredRows.length && <button type="button" className="secondary-button button-compact" onClick={loadMore}>Load more findings</button>}
  </div>
}

function SourceRowsTable({ rows, columns, selected, hasSource, topology, loadMoreRef, onSelect }: { rows: Finding[]; columns: string[]; selected: Finding | null; hasSource: boolean; topology: boolean; loadMoreRef: RefObject<HTMLDivElement | null>; onSelect: (row: Finding) => void }) {
  if (!rows.length) return <p className="report-empty">{hasSource ? 'No rows match the current filters.' : 'No reported entries in this subsection.'}</p>
  return <div className="report-table-wrap" role="region" aria-label="Source report rows" tabIndex={0}>
    <table className="report-table"><thead><tr>{columns.map((key, index) => <th key={key} scope="col" className={`report-column-${columnWidth(key)}${index === 0 ? ' report-identity' : ''}`}>{fieldLabel(key)}</th>)}</tr></thead>
      <tbody>{rows.map((row, index) => <tr className={selected === row ? 'selected' : ''} key={`${row.name ?? row.policy_id ?? index}-${index}`}>
        {columns.map((key, index) => {
          const value = topology && key === 'name' ? row.display_name ?? row.name : row[key]
          const cell = <span className={`report-cell${value == null ? ' report-not-reported' : ''}`} title={value == null ? 'This value was not reported. No default is inferred. See details for the exact value.' : undefined}>{cellSummary(value)}</span>
          return <td key={key} className={`report-column-${columnWidth(key)}${index === 0 ? ' report-identity' : ''}`}>
            {index === 0 ? <div className="report-identity-content">{cell}<button type="button" className="finding-inline-link" aria-label={`Details for ${text(row.name ?? row.policy_id ?? row.route_id ?? value)}`} onClick={() => onSelect(row)}>Details</button></div> : cell}
          </td>
        })}
      </tr>)}</tbody>
    </table>
    <div ref={loadMoreRef} aria-hidden="true" style={{ height: 1 }} />
  </div>
}

export function SourceReport({ data, excelProfile, onExcelProfileChange, exporting, exportStatus, exportError, onExport }: {
  data: SourcePreviewData
  excelProfile: 'fast' | 'full'
  onExcelProfileChange: (value: 'fast' | 'full') => void
  exporting: boolean
  exportStatus: string
  exportError?: string | null
  onExport: () => void
}) {
  const sectionsData = asRecord(data.sections)
  const sections = useMemo(() => reportSections(asRecord(data.sections)), [data.sections])
  const summary = asRecord(data.summary)
  const [activeSection, setActiveSection] = useState('Overview')
  const [views, setViews] = useState<Record<string, { search: string; columns?: string[] }>>({})
  const [scope, setScope] = useState('')
  const [subsectionChoices, setSubsectionChoices] = useState<Record<string, string>>({})
  const [showEmpty, setShowEmpty] = useState(false)
  const [selectedRow, setSelectedRow] = useState<Finding | null>(null)
  const validationRows = useMemo(() => asRows(sectionsData.validation), [sectionsData.validation])
  const counts = useMemo(() => reportCounts(data), [data])
  const errorCount = counts.errors
  const warningCount = counts.warnings
  const overviewMetrics: OverviewMetric[] = []
  overviewMetrics.push({ label: 'Policies', value: counts.policies, section: 'Policies' })
  overviewMetrics.push({ label: 'Address/service objects', value: counts.objects, section: 'Objects', objectSection: 'addresses' })
  overviewMetrics.push({ label: 'Interfaces', value: counts.interfaces, section: 'Interfaces', objectSection: 'interfaces' })
  for (const section of ['Schedules', 'NAT', 'Routes', 'VPN']) {
    const group = sections.find((item) => item.label === section)
    overviewMetrics.push({ label: section, value: reportSectionRowCount(group), section })
  }
  const unresolved = Array.isArray(sectionsData.unresolved_references) ? sectionsData.unresolved_references.length : null
  if (sectionsData.unresolved_references) overviewMetrics.push({ label: 'Unresolved references', value: unresolved, section: 'References', tone: unresolved ? 'warning' : undefined })
  const unsupported = Number(summary.unsupported_count ?? summary.source_only_count ?? 0)
  if (summary.unsupported_count != null || summary.source_only_count != null) overviewMetrics.push({ label: 'Unsupported / source-only', value: unsupported })
  const active = sections.find(({ label: sectionLabel }) => sectionLabel === activeSection)
  const activeRows: Finding[] = active?.rows ?? EMPTY_ROWS
  const sourceSections = active?.subsections.map((item) => item.key) ?? []
  const subsection = useMemo(() => activeSubsection(
    sections.find((item) => item.label === activeSection)?.subsections ?? [], subsectionChoices[activeSection] ?? '',
  ), [sections, activeSection, subsectionChoices])
  const unifiedInterfaces = activeSection === 'Interfaces'
  const activeObjectSection = unifiedInterfaces ? 'interface_topology' : subsection?.key ?? ''
  const unifiedRows = useMemo(() => {
    const subsections = sections.find((item) => item.label === activeSection)?.subsections
    return interfaceTopologyRows(
      subsections?.find((item) => item.key === 'interfaces')?.rows ?? EMPTY_ROWS,
      subsections?.find((item) => item.key === 'interface_topology')?.rows ?? EMPTY_ROWS,
    )
  }, [sections, activeSection])
  const subsectionRows = unifiedInterfaces ? unifiedRows : subsection?.rows ?? EMPTY_ROWS
  const scopeRows = activeSection === 'Extraction' ? subsectionRows : activeRows
  const scopes = [...new Set(scopeRows.map((row) => String(row.scope ?? row.vdom ?? '')).filter(Boolean))].sort()
  const view = views[activeObjectSection] ?? { search: '' }
  const search = view.search
  const effectiveScope = scopes.includes(scope) ? scope : ''
  const allColumns = useMemo(() => rowColumns(subsectionRows, activeObjectSection, data.vendor), [subsectionRows, activeObjectSection, data.vendor])
  const preferredColumns = useMemo(() => defaultColumns(subsectionRows, activeObjectSection, data.vendor), [subsectionRows, activeObjectSection, data.vendor])
  const columns = view.columns ?? preferredColumns
  function updateView(change: Partial<typeof view>) { setViews((current) => ({ ...current, [activeObjectSection]: { ...view, ...change } })); setSelectedRow(null) }
  function setSearch(value: string) { updateView({ search: value }) }
  function setSourceSection(value: string, section = activeSection) { setSubsectionChoices((current) => ({ ...current, [section]: value })); setSelectedRow(null) }
  function changeSection(value: string) { setActiveSection(value); setSelectedRow(null) }
  function changeScope(value: string) { setScope(value); setSelectedRow(null) }
  const filteredRows = useMemo(() => {
    const query = search.toLowerCase()
    return subsectionRows.filter((row) => {
      if (effectiveScope && String(row.scope ?? row.vdom ?? '') !== effectiveScope) return false
      if (!unifiedInterfaces && activeObjectSection && row['Source section'] !== activeObjectSection) return false
      return !query || reportSearchText(row).includes(query)
    })
  }, [subsectionRows, effectiveScope, activeObjectSection, search, unifiedInterfaces])
  const { visibleRows, loadMoreRef, loadMore } = useScrollRows(filteredRows, activeSection !== 'Overview' && activeSection !== 'Validation')
  const subsectionCount = search || effectiveScope ? `${filteredRows.length} of ${subsectionRows.length}` : subsectionRows.length
  const reportTabs = ['Overview', 'Interfaces', 'Objects', 'Schedules', 'Policies', 'NAT', 'Routes', 'VPN', 'References', ...(sections.some((item) => item.label === 'Extraction') ? ['Extraction'] : []), ...(sections.some((item) => item.label === 'Additional sections') ? ['Additional sections'] : []), 'Validation']
  const objectTabs = unifiedInterfaces ? ['interface_topology'] : sourceSections.filter((key) => showEmpty || key === activeObjectSection || active?.subsections.find((item) => item.key === key)?.rows.length)
  const currentSelected = selectedRow && visibleRows.includes(selectedRow) ? selectedRow : null
  const selectedIndex = currentSelected ? visibleRows.indexOf(currentSelected) : -1
  const warningGroups = findingGroups(validationRows).filter((group) => String(group.row.severity).toLowerCase() === 'warning').length

  function renderOverviewMetric(item: OverviewMetric) {
    return <tr key={item.label} className={item.tone ? `configuration-summary-${item.tone}` : undefined}>
      <th scope="row">{item.section ? <button type="button" onClick={() => { changeSection(item.section!); if (item.objectSection) setSourceSection(item.objectSection, item.section) }}>{item.label}</button> : item.label}</th>
      <td>{item.value === null ? 'Not reported' : item.value.toLocaleString()}</td>
      <td aria-hidden="true">{item.section && '›'}</td>
    </tr>
  }

  return <section className="panel source-report" aria-labelledby="report-title">
    <div className="report-sticky-header">
      <div className="report-workspace-header">
        <div><h2 id="report-title">Source inventory</h2>{Array.isArray(summary.scopes) && summary.scopes.length > 0 && <p className="report-scope-summary">Scopes: {summary.scopes.join(', ')}</p>}</div>
        <div className="report-header-actions">
          <ExcelExportControls vendor={data.vendor ?? ''} profile={excelProfile} onProfileChange={onExcelProfileChange} exporting={exporting} onExport={onExport} />
        </div>
      </div>
      {data.collection != null && <div className="report-count-note"><p>Collection: {String(asRecord(data.collection).status ?? 'Unknown')} · Method: {String(asRecord(data.collection).method ?? 'Not reported')}</p>{Array.isArray(asRecord(data.collection).warnings) && <ul>{(asRecord(data.collection).warnings as unknown[]).map((warning, index) => <li key={index}>{String(safeValue(warning))}</li>)}</ul>}</div>}
      <p className="preview-status" role="status" aria-live="polite">{exportStatus}</p>
      {exportError && <ErrorBanner message={exportError} />}
      <label className="report-section-select">Report section<select value={activeSection} onChange={(event) => changeSection(event.target.value)}>{reportTabs.map((name) => <option key={name}>{name}</option>)}</select></label>
      <nav className="report-tabs" role="tablist" aria-label="Report sections" onKeyDown={tabKeyboard}>
      {reportTabs.map((sectionLabel) => (
        <button key={sectionLabel} id={`report-tab-${encodeURIComponent(sectionLabel)}`} aria-controls={`report-panel-${encodeURIComponent(sectionLabel)}`} tabIndex={activeSection === sectionLabel ? 0 : -1} type="button" role="tab" aria-selected={activeSection === sectionLabel} className={`report-tab${activeSection === sectionLabel ? ' active' : ''}`} onClick={() => changeSection(sectionLabel)}>
          {sectionLabel}
        </button>
      ))}
      </nav>
    </div>
    {reportTabs.filter((item) => item !== activeSection).map((item) => <div key={item} hidden role="tabpanel" id={`report-panel-${encodeURIComponent(item)}`} aria-labelledby={`report-tab-${encodeURIComponent(item)}`} />)}
    <div role="tabpanel" id={`report-panel-${encodeURIComponent(activeSection)}`} aria-labelledby={`report-tab-${encodeURIComponent(activeSection)}`} tabIndex={0}>
    {activeSection === 'Overview' ? <>
      <h3 className="report-overview-heading">Validation</h3>
      <button type="button" className={`report-validation-attention${errorCount ? ' has-errors' : warningCount ? ' has-warnings' : ''}`} onClick={() => changeSection('Validation')}><div>{sectionsData.validation == null && asRecord(summary.validation).severity_counts == null ? 'Not reported' : <>{errorCount.toLocaleString()} {errorCount === 1 ? 'error' : 'errors'} · {warningCount.toLocaleString()} {warningCount === 1 ? 'warning' : 'warnings'} <small>{warningGroups.toLocaleString()} warning {warningGroups === 1 ? 'group' : 'groups'}</small></>}</div><span>Review findings →</span></button>
      <div className="report-overview-group">
        <h3 className="report-overview-heading" id="configuration-summary-title">Configuration summary</h3>
        <div className="configuration-summary-wrap">
          <table className="configuration-summary" aria-labelledby="configuration-summary-title">
            <thead><tr><th scope="col">Section</th><th scope="col">Count</th><th scope="col"><span className="visually-hidden">Navigation</span></th></tr></thead>
            <tbody>{overviewMetrics.map(renderOverviewMetric)}</tbody>
          </table>
        </div>
      </div>
      <details className="report-count-explanation"><summary>About these counts</summary><p>Configured objects count addresses, address groups, services, and service groups once. Policies and interfaces use configured inventory counts. Report sections count rows, including expanded entries. Not reported means the count is unavailable.</p></details>
    </> : activeSection === 'Validation' ? null : <>
      {activeSection === 'Extraction' && sectionsData.extraction_coverage != null && <>
        {data.vendor === 'palo_alto' && <p className="report-count-note">{Number(summary.source_only_count ?? 0).toLocaleString()} source-only records · {Number(summary.partial_count ?? 0).toLocaleString()} partial records · {asRows(sectionsData.source_inventory).length.toLocaleString()} source inventory records.</p>}
        {data.vendor === 'fortigate' && <p className="report-count-note">{Number(summary.source_only_count ?? 0).toLocaleString()} source-only records · {Number(summary.empty_section_count ?? 0).toLocaleString()} empty sections · {Number(summary.model_gap_count ?? 0).toLocaleString()} model gaps · {Number(summary.typed_with_additional_settings_count ?? 0).toLocaleString()} typed records with additional settings · {asRows(sectionsData.source_inventory).length.toLocaleString()} source object records.</p>}
      </>}
      {activeSection !== 'Interfaces' && active?.subsections.some((item) => !item.rows.length) && <label className="report-empty-toggle"><input type="checkbox" checked={showEmpty} onChange={(event) => setShowEmpty(event.target.checked)} /> Show empty sections</label>}
      {!!objectTabs.length && <nav className="report-object-tabs" role="tablist" aria-label="Source subsections" onKeyDown={tabKeyboard}>{objectTabs.map((item) => <button type="button" role="tab" id={`subsection-tab-${encodeURIComponent(item)}`} aria-controls={`subsection-panel-${encodeURIComponent(item)}`} tabIndex={activeObjectSection === item ? 0 : -1} aria-selected={activeObjectSection === item} className={activeObjectSection === item ? 'active' : ''} key={item} onClick={() => setSourceSection(item)}>{unifiedInterfaces ? `Interface Topology (${subsectionCount})` : `${fieldLabel(item)} (${activeObjectSection === item ? subsectionCount : active?.subsections.find((section) => section.key === item)?.rows.length ?? 0})`}</button>)}</nav>}
      {objectTabs.filter((item) => item !== activeObjectSection).map((item) => <div key={item} hidden role="tabpanel" id={`subsection-panel-${encodeURIComponent(item)}`} aria-labelledby={`subsection-tab-${encodeURIComponent(item)}`} />)}
      <div {...(unifiedInterfaces ? {} : { role: 'tabpanel', id: `subsection-panel-${encodeURIComponent(activeObjectSection)}`, 'aria-labelledby': `subsection-tab-${encodeURIComponent(activeObjectSection)}`, tabIndex: 0 as const })}>
      <div className="report-toolbar">
        <label className="report-search-control"><span className="visually-hidden">Search report rows</span><input type="search" value={search} placeholder={unifiedInterfaces ? 'Search topology' : 'Search this section'} onChange={(event) => setSearch(event.target.value)} /></label>
        <div className="report-filter-controls">
          {scopes.length > 0 && <select aria-label="Filter report scope" value={effectiveScope} onChange={(event) => changeScope(event.target.value)}><option value="">All scopes</option>{scopes.map((item) => <option key={item} value={item}>{item}</option>)}</select>}
          <button type="button" className="filter-clear" disabled={!search && !effectiveScope} onClick={() => { setSearch(''); changeScope('') }}>Clear filters</button>
        </div>
        <details className="report-column-selector"><summary>Columns ({columns.length})</summary><div>{allColumns.map((key, index) => <label key={key}><input type="checkbox" checked={columns.includes(key)} disabled={index === 0} onChange={(event) => updateView({ columns: allColumns.filter((column) => column === allColumns[0] || (column === key ? event.target.checked : columns.includes(column))) })} />{fieldLabel(key)}</label>)}<button className="filter-clear" type="button" onClick={() => updateView({ columns: undefined })}>Reset columns</button></div></details>
      </div>
      <p className="report-row-count" role="status">Showing {visibleRows.length.toLocaleString()} of {filteredRows.length.toLocaleString()} matching rows · {subsectionRows.length.toLocaleString()} total. Open Details for full values.</p>
      <div className={`validation-workspace${currentSelected ? ' has-details' : ''}${unifiedInterfaces ? ' report-topology-view' : ''}`} key={activeSection}>
        <SourceRowsTable rows={visibleRows} columns={columns} selected={currentSelected} hasSource={subsectionRows.length > 0} topology={activeObjectSection === 'interface_topology'} loadMoreRef={loadMoreRef} onSelect={setSelectedRow} />
        {currentSelected && <ReportDetails row={currentSelected} subsection={activeObjectSection} vendor={data.vendor} onClose={() => setSelectedRow(null)} previous={selectedIndex > 0 ? () => setSelectedRow(visibleRows[selectedIndex - 1]) : undefined} next={selectedIndex < visibleRows.length - 1 ? () => setSelectedRow(visibleRows[selectedIndex + 1]) : undefined} />}
      </div>
      {visibleRows.length < filteredRows.length && <button type="button" className="secondary-button button-compact" onClick={loadMore}>Load more rows</button>}
      </div>
    </>}
    <div hidden={activeSection !== 'Validation'}><ValidationReport data={data} reportScope={scope} onReportScope={changeScope} active={activeSection === 'Validation'} /></div>
    </div>
  </section>
}
