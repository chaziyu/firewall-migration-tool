import { useEffect, useMemo, useRef, useState } from 'react'
import type { RefObject } from 'react'
import type { SourcePreviewData } from '../source/types'
import { activeSubsection, asRecord, asRows, compactValue, interfaceTopologyRows, matchingSourceRows, reportCounts, reportSections, reportSectionRowCount, reportSearchText, rowColumns, safeValue, defaultColumns, cellSummary, columnWidth, fieldLabel, findingGroups, findingGroupKey } from './reportPresentation'
import { ReportDetails } from './ReportDetails'
import { tabKeyboard } from '../../components/common/tabKeyboard'

type Finding = Record<string, unknown>
const EMPTY_ROWS: Finding[] = []
type ValidationTarget = { section: string; label: string; rows: unknown[] }
type OverviewMetric = { label: string; value: number; tier: 'primary' | 'secondary'; section?: string; objectSection?: string; tone?: string }

const VALIDATION_TARGETS: Record<string, [string, string]> = {
  nat: ['nat', 'NAT'],
  interface: ['interfaces', 'Interfaces'],
  address: ['addresses', 'Addresses'],
  address6: ['addresses', 'Addresses'],
  address_group: ['address_groups', 'Address groups'],
  service: ['services', 'Services'],
  service_group: ['service_groups', 'Service groups'],
  policy: ['policies', 'Policies'],
  schedule: ['schedules', 'Schedules'],
  scheduler: ['schedules', 'Schedules'],
  time_range: ['schedules', 'Schedules'],
  route: ['routes', 'Routes'],
  static_route: ['routes', 'Routes'],
  static_route6: ['routes', 'Routes'],
  vpn: ['vpn_tunnels', 'VPN tunnels'],
  ipsec_phase1: ['vpn_tunnels', 'VPN tunnels'],
  vpn_phase2: ['vpn_phase2', 'VPN phase 2'],
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
    <div className="validation-counts"><strong>{rows.length} findings</strong><span>{errors} errors</span><span>{warnings} warnings</span></div>
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

function ValidationFilters({ rows, search, scope, severity, onSearch, onScope, onSeverity, onClear }: {
  rows: Finding[]
  search: string
  scope: string
  severity: string
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
    <button type="button" className="filter-clear" onClick={onClear}>Clear filters</button>
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
      const targetInfo = VALIDATION_TARGETS[String(row.domain || '').toLowerCase()]
      return <tr key={`${row.code ?? ''}-${row.domain ?? ''}-${row.object_name ?? ''}-${index}`} className={selected === row ? 'selected' : ''}>
        <td><strong>{text(row.object_name)}</strong></td><td>{text(row.scope ?? row.vdom)}</td><td>{text(row.domain)}<br />{text(row.field)}</td>
        <td><span className={`finding-severity severity-${String(row.severity ?? 'other').toLowerCase()}`}>{text(row.severity ?? 'Issue')}</span></td>
        {!grouped && <td><button type="button" className="finding-message" onClick={() => onSelect(row)}>{text(row.message)}</button></td>}
        <td><button type="button" className="finding-inline-link" onClick={() => onSelect(row)}>Details</button>{row.object_name != null && targetInfo != null ? <button type="button" className="finding-inline-link" onClick={() => onNavigate(row)}>View object →</button> : null}</td>
      </tr>
    })}</tbody></table></div>
}

function ValidationReport({ data, reportScope, onReportScope, active }: { data: SourcePreviewData; reportScope: string; onReportScope: (scope: string) => void; active: boolean }) {
  const sections = asRecord(data.sections)
  const allRows = useMemo(() => asRows(sections.validation), [sections.validation])
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [activeGroup, setActiveGroup] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [target, setTarget] = useState<ValidationTarget | null>(null)
  const [page, setPage] = useState(1)
  const scopes = useMemo(() => [...new Set(allRows.map((row) => String(row.scope || row.vdom || '')).filter(Boolean))], [allRows])
  const scope = scopes.includes(reportScope) ? reportScope : ''
  const [requestedScope, setRequestedScope] = useState(reportScope)
  if (requestedScope !== reportScope) { setRequestedScope(reportScope); setPage(1); setSelected(null); setTarget(null) }

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
  const filteredRows = useMemo(() => matchingRows.filter((row) => !group
    || findingGroupKey(row) === group.key), [matchingRows, group])
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / 50))
  const visibleRows = filteredRows.slice((page - 1) * 50, page * 50)

  function clearFilters() {
    setPage(1)
    setSearch('')
    onReportScope('')
    setSeverity('')
    setActiveGroup('')
  }

  function navigateToObject(finding: Finding) {
    const route = VALIDATION_TARGETS[String(finding.domain || '').toLowerCase()]
    if (!route || finding.object_name == null) return
    const rows = matchingSourceRows(asRows(sections[route[0]]), finding)
    setSelected(finding)
    setTarget({ section: route[0], label: route[1], rows: rows.map((row) => safeValue(row)) })
  }

  return <div className="validation-report">
    <h3>Validation findings</h3>
    <ValidationFilters rows={allRows} search={search} scope={scope} severity={severity} onSearch={(value) => { setSearch(value); setPage(1); setSelected(null) }} onScope={(value) => { onReportScope(value); setPage(1); setSelected(null) }} onSeverity={(value) => { setSeverity(value); setPage(1); setSelected(null) }} onClear={() => { clearFilters(); setSelected(null) }} />
    <ValidationSummary rows={matchingRows} activeGroup={group?.key ?? ''} onGroupChange={(key) => { setActiveGroup(key); setPage(1); setSelected(null) }} />
    {group && <p className="validation-group-explanation"><strong>{group.count} affected findings</strong> · {text(group.row.message)}</p>}
    <ReportPagination page={page} pageCount={pageCount} onPage={(value) => { setPage(value); setSelected(null) }} label="Validation pages" />
    <div className={`validation-workspace${selected && visibleRows.includes(selected) ? ' has-details' : ''}`}>
      <ValidationTable rows={visibleRows} selected={selected} grouped={!!group} onSelect={(row) => { setSelected(row); setTarget(null) }} onNavigate={navigateToObject} />
      {active && selected && visibleRows.includes(selected) && <ReportDetails finding row={selected} target={target} onNavigate={() => navigateToObject(selected)} onClose={() => { setSelected(null); setTarget(null) }} />}
    </div>
    <ReportPagination page={page} pageCount={pageCount} onPage={(value) => { setPage(value); setSelected(null) }} label="Validation pages below table" />
    {!allRows.length && <p className="validation-empty">No validation findings were reported.</p>}
    {!!scopes.length && <p className="validation-scope-note">Findings are reported for {scopes.length} {scopes.length === 1 ? 'scope' : 'scopes'}.</p>}
  </div>
}

function ReportPagination({ page, pageCount, onPage, pageSize, onPageSize, label: name = 'Report pages' }: { page: number; pageCount: number; onPage: (page: number) => void; pageSize?: number; onPageSize?: (size: number) => void; label?: string }) {
  return <div className="report-pager" aria-label={name}><button type="button" className="secondary-button" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button><label>Page <input aria-label={`${name}: page number`} type="number" min={1} max={pageCount} value={page} onChange={(event) => { const value = Number(event.target.value); if (Number.isInteger(value) && value >= 1 && value <= pageCount) onPage(value) }} /></label><span role="status">of {pageCount}</span><button type="button" className="secondary-button" disabled={page >= pageCount} onClick={() => onPage(page + 1)}>Next</button>{onPageSize && <label>Rows per page <select value={pageSize} onChange={(event) => onPageSize(Number(event.target.value))}>{[25, 50, 100].map((size) => <option key={size}>{size}</option>)}</select></label>}</div>
}

function SourceRowsTable({ rows, columns, selected, hasSource, topology, loadMoreRef, onSelect }: { rows: Finding[]; columns: string[]; selected: Finding | null; hasSource: boolean; topology: boolean; loadMoreRef: RefObject<HTMLDivElement | null>; onSelect: (row: Finding) => void }) {
  if (!rows.length) return <p className="report-empty">{hasSource ? 'No rows match the current filters.' : 'No reported entries in this subsection.'}</p>
  return <div className="report-table-wrap" role="region" aria-label="Source report rows" tabIndex={0}>
    <table className="report-table"><thead><tr>{columns.map((key, index) => <th key={key} scope="col" className={`report-column-${columnWidth(key)}${index === 0 ? ' report-identity' : ''}`}>{fieldLabel(key)}</th>)}</tr></thead>
      <tbody>{rows.map((row, index) => <tr className={selected === row ? 'selected' : ''} key={`${row.name ?? row.policy_id ?? index}-${index}`}>
        {columns.map((key, index) => { const value = topology && key === 'name' ? row.display_name ?? row.name : row[key]; return <td key={key} className={`report-column-${columnWidth(key)}${index === 0 ? ' report-identity' : ''}`}><span className={`report-cell${value == null ? ' report-not-reported' : ''}`} title={value == null ? 'This value was not reported. No default is inferred. See details for the exact value.' : undefined}>{cellSummary(value)}</span>{index === 0 && <button type="button" className="finding-inline-link" aria-label={`Details for ${text(row.name ?? row.policy_id ?? row.route_id ?? value)}`} onClick={() => onSelect(row)}>Details</button>}</td> })}
      </tr>)}</tbody>
    </table>
    <div ref={loadMoreRef} aria-hidden="true" style={{ height: 1 }} />
  </div>
}

function reportMetric(summary: Record<string, unknown>, sections: ReturnType<typeof reportSections>, labelText: string, keys: string[]) {
  const counts = asRecord(summary.objects)
  const section = sections.find((item) => item.label === labelText)
  for (const key of keys) {
    const value = counts[key] ?? summary[key]
    if (typeof value === 'number') return value
  }
  return section?.rows.length ?? 0
}

export function SourceReport({ data, excelProfile, onExcelProfileChange, exporting, onExport }: {
  data: SourcePreviewData
  excelProfile: 'fast' | 'full'
  onExcelProfileChange: (value: 'fast' | 'full') => void
  exporting: boolean
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
  if (counts.policies !== null) overviewMetrics.push({ label: 'Configured policies', value: counts.policies, tier: 'primary', section: 'Policies' })
  if (counts.objects !== null) overviewMetrics.push({ label: 'Configured address/service objects', value: counts.objects, tier: 'primary', section: 'Objects', objectSection: 'addresses' })
  if (counts.interfaces !== null) overviewMetrics.push({ label: 'Configured interfaces', value: counts.interfaces, tier: 'primary', section: 'Interfaces', objectSection: 'interfaces' })
  for (const [labelText, section] of [['Schedules', 'Schedules'], ['Routes', 'Routes'], ['VPN report rows', 'VPN']] as const) {
    const count = reportMetric(summary, sections, section, [])
    if (count || sections.some((item) => item.label === section)) overviewMetrics.push({ label: labelText, value: count, tier: 'secondary', section })
  }
  const unresolved = asRows(sectionsData.unresolved_references).length
  if (sectionsData.unresolved_references) overviewMetrics.push({ label: 'Unresolved references', value: unresolved, tier: 'secondary', section: 'References', tone: unresolved ? 'warning' : undefined })
  const unsupported = Number(summary.unsupported_count ?? summary.source_only_count ?? 0)
  if (summary.unsupported_count != null || summary.source_only_count != null) overviewMetrics.push({ label: 'Unsupported / source-only', value: unsupported, tier: 'secondary' })
  const active = sections.find(({ label: sectionLabel }) => sectionLabel === activeSection)
  const activeRows: Finding[] = active?.rows ?? EMPTY_ROWS
  const scopes = [...new Set(activeRows.map((row) => String(row.scope ?? row.vdom ?? '')).filter(Boolean))].sort()
  const sourceSections = active?.subsections.map((item) => item.key) ?? []
  const subsection = useMemo(() => activeSubsection(
    sections.find((item) => item.label === activeSection)?.subsections ?? [], subsectionChoices[activeSection] ?? '',
  ), [sections, activeSection, subsectionChoices])
  const unifiedInterfaces = activeSection === 'Interfaces'
  const activeObjectSection = unifiedInterfaces ? 'interface_topology' : subsection?.key ?? ''
  const inventoryRows = active?.subsections.find((item) => item.key === 'interfaces')?.rows ?? EMPTY_ROWS
  const topologyRows = active?.subsections.find((item) => item.key === 'interface_topology')?.rows ?? EMPTY_ROWS
  const unifiedRows = useMemo(() => interfaceTopologyRows(inventoryRows, topologyRows), [inventoryRows, topologyRows])
  const subsectionRows = unifiedInterfaces ? unifiedRows : subsection?.rows ?? EMPTY_ROWS
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
  }, [subsectionRows, effectiveScope, activeObjectSection, search])
  const [renderedRowCount, setRenderedRowCount] = useState(200)
  const loadMoreRef = useRef<HTMLDivElement>(null)
  useEffect(() => { setRenderedRowCount(200) }, [filteredRows])
  useEffect(() => {
    const sentinel = loadMoreRef.current
    if (!sentinel || renderedRowCount >= filteredRows.length) return
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) setRenderedRowCount((count) => Math.min(count + 200, filteredRows.length))
    }, { rootMargin: '600px' })
    observer.observe(sentinel)
    return () => observer.disconnect()
  }, [filteredRows.length, renderedRowCount])
  const visibleRows = unifiedInterfaces ? filteredRows : filteredRows.slice(0, renderedRowCount)
  const reportTabs = ['Overview', 'Interfaces', 'Objects', 'Schedules', 'Policies', 'NAT', 'Routes', 'VPN', 'References', ...(sections.some((item) => item.label === 'Additional sections') ? ['Additional sections'] : []), 'Validation']
  const objectTabs = unifiedInterfaces ? ['interface_topology'] : sourceSections.filter((key) => showEmpty || key === activeObjectSection || active?.subsections.find((item) => item.key === key)?.rows.length)
  const currentSelected = selectedRow && visibleRows.includes(selectedRow) ? selectedRow : null
  const selectedIndex = currentSelected ? visibleRows.indexOf(currentSelected) : -1
  const warningGroups = findingGroups(validationRows).filter((group) => String(group.row.severity).toLowerCase() === 'warning').length

  function renderOverviewMetric(item: OverviewMetric) {
    const className = `report-stat report-stat-${item.tier}${item.tone ? ` report-stat-${item.tone}` : ''}${item.section ? ' report-stat-button' : ''}`
    const content = <><strong>{item.value}</strong><span className="report-stat-label">{item.label}</span>{item.section && <span className="report-stat-affordance">View →</span>}</>
    if (!item.section) return <div className={className} key={item.label}>{content}</div>
    return <button className={className} type="button" key={item.label} onClick={() => { changeSection(item.section!); if (item.objectSection) setSourceSection(item.objectSection, item.section) }}>{content}</button>
  }

  return <section className="panel source-report" aria-labelledby="report-title">
    <div className="report-sticky-header">
      <div className="report-workspace-header">
        <div><h2 id="report-title">Source inventory</h2></div>
        <div className="report-header-actions">
          <div className="excel-actions"><label className="excel-profile-control">Excel<select aria-label="Excel export profile" value={excelProfile} onChange={(event) => onExcelProfileChange(event.target.value as 'fast' | 'full')}><option value="fast">FAST</option><option value="full">FULL</option></select></label>
            <button className="secondary-button" type="button" disabled={exporting} onClick={onExport}>{exporting ? 'Preparing workbook…' : 'Export Excel'}</button>
          </div>
        </div>
      </div>
      {data.collection != null && <div className="report-count-note"><p>Collection: {String(asRecord(data.collection).status ?? 'Unknown')} · Method: {String(asRecord(data.collection).method ?? 'Not reported')}</p>{Array.isArray(asRecord(data.collection).warnings) && <ul>{(asRecord(data.collection).warnings as unknown[]).map((warning, index) => <li key={index}>{String(safeValue(warning))}</li>)}</ul>}</div>}
      <label className="report-section-select">Report section<select value={activeSection} onChange={(event) => changeSection(event.target.value)}>{reportTabs.map((name) => <option key={name}>{name}</option>)}</select></label>
      <nav className="report-tabs" role="tablist" aria-label="Report sections" onKeyDown={tabKeyboard}>
      {reportTabs.map((sectionLabel) => (
        <button key={sectionLabel} id={`report-tab-${encodeURIComponent(sectionLabel)}`} aria-controls={`report-panel-${encodeURIComponent(sectionLabel)}`} tabIndex={activeSection === sectionLabel ? 0 : -1} type="button" role="tab" aria-selected={activeSection === sectionLabel} className={`report-tab${activeSection === sectionLabel ? ' active' : ''}`} onClick={() => changeSection(sectionLabel)}>
          {sectionLabel}{sectionLabel !== 'Overview' && <span className="report-tab-count">{sectionLabel === 'Validation' ? sectionsData.validation == null ? 'Not reported' : validationRows.length : reportSectionRowCount(sections.find((section) => section.label === sectionLabel)) ?? 'Not reported'}</span>}
        </button>
      ))}
      </nav>
    </div>
    {reportTabs.filter((item) => item !== activeSection).map((item) => <div key={item} hidden role="tabpanel" id={`report-panel-${encodeURIComponent(item)}`} aria-labelledby={`report-tab-${encodeURIComponent(item)}`} />)}
    <div role="tabpanel" id={`report-panel-${encodeURIComponent(activeSection)}`} aria-labelledby={`report-tab-${encodeURIComponent(activeSection)}`} tabIndex={0}>
    {activeSection === 'Overview' ? <>
      <button type="button" className={`report-validation-attention${errorCount ? ' has-errors' : warningCount ? ' has-warnings' : ''}`} onClick={() => changeSection('Validation')}>{errorCount} errors · {warningCount} warnings · {warningGroups} warning groups <span>Review findings →</span></button>
      <p className="report-count-note">Configured objects count addresses, address groups, services, and service groups once. Tab counts show report rows, including expanded entries. Interfaces counts configured inventory rows.</p>
      {(['primary', 'secondary'] as const).map((tier) => {
        const items = overviewMetrics.filter((item) => item.tier === tier)
        return items.length ? <div className={`report-summary-${tier}`} key={tier}>{items.map(renderOverviewMetric)}</div> : null
      })}
      {Array.isArray(summary.scopes) && summary.scopes.length > 0 && <p className="report-scope-summary">Scopes: {summary.scopes.join(', ')}</p>}
    </> : activeSection === 'Validation' ? null : <>
      {activeSection !== 'Interfaces' && active?.subsections.some((item) => !item.rows.length) && <label className="report-empty-toggle"><input type="checkbox" checked={showEmpty} onChange={(event) => setShowEmpty(event.target.checked)} /> Show empty sections</label>}
      {!!objectTabs.length && <nav className="report-object-tabs" role="tablist" aria-label="Source subsections" onKeyDown={tabKeyboard}>{objectTabs.map((item) => <button type="button" role="tab" id={`subsection-tab-${encodeURIComponent(item)}`} aria-controls={`subsection-panel-${encodeURIComponent(item)}`} tabIndex={activeObjectSection === item ? 0 : -1} aria-selected={activeObjectSection === item} className={activeObjectSection === item ? 'active' : ''} key={item} onClick={() => setSourceSection(item)}>{unifiedInterfaces ? `Interface Topology (${topologyRows.length})` : `${fieldLabel(item)} (${active?.subsections.find((section) => section.key === item)?.rows.length ?? 0})`}</button>)}</nav>}
      {objectTabs.filter((item) => item !== activeObjectSection).map((item) => <div key={item} hidden role="tabpanel" id={`subsection-panel-${encodeURIComponent(item)}`} aria-labelledby={`subsection-tab-${encodeURIComponent(item)}`} />)}
      <div {...(unifiedInterfaces ? {} : { role: 'tabpanel', id: `subsection-panel-${encodeURIComponent(activeObjectSection)}`, 'aria-labelledby': `subsection-tab-${encodeURIComponent(activeObjectSection)}`, tabIndex: 0 as const })}>
      <div className="report-toolbar">
        <label className="report-search-control"><span className="visually-hidden">Search report rows</span><input type="search" value={search} placeholder={unifiedInterfaces ? 'Search topology' : 'Search this section'} onChange={(event) => setSearch(event.target.value)} /></label>
        <div className="report-filter-controls">
          <details className="report-column-selector"><summary>Columns ({columns.length})</summary><div>{allColumns.map((key, index) => <label key={key}><input type="checkbox" checked={columns.includes(key)} disabled={index === 0} onChange={(event) => updateView({ columns: allColumns.filter((column) => column === allColumns[0] || (column === key ? event.target.checked : columns.includes(column))) })} />{fieldLabel(key)}</label>)}<button className="filter-clear" type="button" onClick={() => updateView({ columns: undefined })}>Reset columns</button></div></details>
          <button type="button" className="filter-clear" onClick={() => { setSearch(''); changeScope('') }}>Clear filters</button>
          {scopes.length > 0 && <select aria-label="Filter report scope" value={effectiveScope} onChange={(event) => changeScope(event.target.value)}><option value="">All scopes</option>{scopes.map((item) => <option key={item} value={item}>{item}</option>)}</select>}
        </div>
      </div>
      <div className="report-table-meta"><p role="status" aria-live="polite">Showing {visibleRows.length} of {filteredRows.length} {unifiedInterfaces ? 'topology rows' : 'report rows'}</p></div>
      <div className={`validation-workspace${currentSelected ? ' has-details' : ''}${unifiedInterfaces ? ' report-topology-view' : ''}`} key={activeSection}>
        <SourceRowsTable rows={visibleRows} columns={columns} selected={currentSelected} hasSource={subsectionRows.length > 0} topology={activeObjectSection === 'interface_topology'} loadMoreRef={loadMoreRef} onSelect={setSelectedRow} />
        {currentSelected && <ReportDetails row={currentSelected} subsection={activeObjectSection} vendor={data.vendor} onClose={() => setSelectedRow(null)} previous={selectedIndex > 0 ? () => setSelectedRow(visibleRows[selectedIndex - 1]) : undefined} next={selectedIndex < visibleRows.length - 1 ? () => setSelectedRow(visibleRows[selectedIndex + 1]) : undefined} />}
      </div>
      </div>
    </>}
    <div hidden={activeSection !== 'Validation'}><ValidationReport data={data} reportScope={scope} onReportScope={changeScope} active={activeSection === 'Validation'} /></div>
    </div>
  </section>
}
