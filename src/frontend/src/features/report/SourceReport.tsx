import { useEffect, useMemo, useRef, useState } from 'react'
import type { SourcePreviewData } from '../source/types'
import { activeSubsection, asRecord, asRows, cellBadgeVariant, compactValue, interfaceTopologyRows, isMonoColumn, matchingSourceRows, reportCounts, reportSections, reportSectionRowCount, reportSearchText, rowColumns, rowSemanticClass, safeValue, sectionLegend, defaultColumns, cellSummary, cellTooltip, columnWidth, fieldLabel, findingGroups, findingGroupKey, systemOverviewItems } from './reportPresentation'
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
  zone: ['zones', 'Zones'],
  administrator: ['administrators', 'Administrators'],
  'admin-role': ['admin_roles', 'Admin roles'],
  'dhcp-server': ['dhcp_servers', 'DHCP servers'],
  'sdwan-rule': ['sdwan_rules', 'SD-WAN rules'],
  profile_group: ['profile_groups', 'Profile groups'],
  protocol_options: ['protocol_options', 'Protocol options'],
  per_ip_shaper: ['per_ip_shapers', 'Per-IP shapers'],
  ips_sensor: ['ips_sensors', 'IPS sensors'],
  av_profile: ['antivirus_profiles', 'Antivirus profiles'],
  webfilter_profile: ['webfilter_profiles', 'Web filter profiles'],
  dnsfilter_profile: ['dnsfilter_profiles', 'DNS filter profiles'],
  application_list: ['application_lists', 'Application lists'],
  ssl_ssh_profile: ['ssl_ssh_profiles', 'SSL-SSH profiles'],
  proxy_policy: ['proxy_policies', 'Proxy policies'],
  auth_policy: ['auth_policies', 'Auth policies'],
  policy_route: ['policy_routes', 'Policy routes'],
  policy_route6: ['policy_routes', 'Policy routes'],
  ldap_server: ['ldap_servers', 'LDAP servers'],
  radius_server: ['radius_servers', 'RADIUS servers'],
  tacacs_server: ['tacacs_servers', 'TACACS+ servers'],
  kerberos_keytab: ['kerberos_keytabs', 'Kerberos keytabs'],
  wireless_vap: ['wireless_vaps', 'WiFi SSIDs'],
  'application-group': ['application_groups', 'Application groups'],
  'external-list': ['external_lists', 'External dynamic lists'],
  'custom-url-category': ['custom_url_categories', 'Custom URL categories'],
  'dynamic-user-group': ['dynamic_user_groups', 'Dynamic user groups'],
  'antivirus-profile': ['antivirus_profiles', 'Antivirus profiles'],
  'anti-spyware-profile': ['anti_spyware_profiles', 'Anti-Spyware profiles'],
  'url-filtering-profile': ['url_filtering_profiles', 'URL filtering profiles'],
  'file-blocking-profile': ['file_blocking_profiles', 'File blocking profiles'],
  'wildfire-analysis-profile': ['wildfire_profiles', 'WildFire profiles'],
  'data-filtering-profile': ['data_filtering_profiles', 'Data filtering profiles'],
  'dos-protection-profile': ['dos_protection_profiles', 'DoS protection profiles'],
  'decryption-profile': ['decryption_profiles', 'Decryption profiles'],
  'log-setting': ['log_forwarding_profiles', 'Log forwarding profiles'],
  'authentication-profile': ['authentication_profiles', 'Authentication profiles'],
  'authentication-sequence': ['authentication_sequences', 'Authentication sequences'],
  'ssl-tls-service-profile': ['ssl_tls_service_profiles', 'SSL/TLS service profiles'],
  certificate: ['certificates', 'Certificates'],
  'zone-protection-profile': ['zone_protection_profiles', 'Zone protection profiles'],
  'bfd-profile': ['bfd_profiles', 'BFD profiles'],
  'qos-rule': ['qos_rules', 'QoS rules'],
  'pbf-rule': ['pbf_rules', 'PBF rules'],
  'decryption-rule': ['decryption_rules', 'Decryption rules'],
  'tunnel-inspect-rule': ['tunnel_inspect_rules', 'Tunnel inspect rules'],
  'app-override-rule': ['app_override_rules', 'App override rules'],
  'authentication-rule': ['authentication_rules', 'Authentication rules'],
  'dos-rule': ['dos_rules', 'DoS rules'],
  vlan: ['vlans', 'VLANs'],
  'virtual-wire': ['virtual_wires', 'Virtual wires'],
  'gre-tunnel': ['gre_tunnels', 'GRE tunnels'],
  'dns-proxy': ['dns_proxies', 'DNS proxies'],
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

const ROW_HEIGHT = 40
const VALIDATION_ROW_HEIGHT = 56
const VIRTUAL_OVERSCAN = 8
const VIRTUAL_THRESHOLD = 50
// Bounds initial mount before clientHeight is measured so large tables never render thousands of DOM rows.
const DEFAULT_VIRTUAL_VIEWPORT_HEIGHT = 600

function useVirtualRows<T>(rows: T[], rowHeight: number, resetKey: unknown) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const rafRef = useRef<number | null>(null)
  const [scrollState, setScrollState] = useState({ scrollTop: 0, viewportHeight: 0 })

  useEffect(() => {
    const element = wrapRef.current
    if (!element) return
    if (element.scrollTop) element.scrollTop = 0
    const nextHeight = element.clientHeight ?? 0
    setScrollState((current) => (current.scrollTop === 0 && current.viewportHeight === nextHeight ? current : { scrollTop: 0, viewportHeight: nextHeight }))
  }, [rows, resetKey])

  useEffect(() => () => {
    if (rafRef.current !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(rafRef.current)
    }
  }, [])

  function onScroll(event: React.UIEvent<HTMLDivElement>) {
    const target = event.currentTarget
    const nextTop = target.scrollTop
    const nextHeight = target.clientHeight
    const apply = () => {
      rafRef.current = null
      setScrollState((current) => (current.scrollTop === nextTop && current.viewportHeight === nextHeight ? current : { scrollTop: nextTop, viewportHeight: nextHeight }))
    }
    if (typeof requestAnimationFrame === 'function') {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current)
      rafRef.current = requestAnimationFrame(apply)
    } else {
      apply()
    }
  }

  const virtualize = rows.length > VIRTUAL_THRESHOLD
  const effectiveHeight = (scrollState?.viewportHeight ?? 0) > 0 ? scrollState.viewportHeight : DEFAULT_VIRTUAL_VIEWPORT_HEIGHT
  const scrollTop = scrollState?.scrollTop ?? 0
  const startIndex = virtualize ? Math.max(0, Math.floor(scrollTop / rowHeight) - VIRTUAL_OVERSCAN) : 0
  const endIndex = virtualize ? Math.min(rows.length, Math.ceil((scrollTop + effectiveHeight) / rowHeight) + VIRTUAL_OVERSCAN) : rows.length
  return {
    wrapRef,
    onScroll,
    startIndex,
    visibleRows: virtualize ? rows.slice(startIndex, endIndex) : rows,
    topSpacerHeight: startIndex * rowHeight,
    bottomSpacerHeight: (rows.length - endIndex) * rowHeight,
  }
}

function ValidationSummary({ rows, activeGroup, onGroupChange }: {
  rows: Finding[]
  activeGroup: string
  onGroupChange: (key: string) => void
}) {
  const ordered = findingGroups(rows)
  let errors = 0
  let warnings = 0
  for (const row of rows) {
    const sev = String(row.severity).toLowerCase()
    if (sev === 'error') errors += 1
    else if (sev === 'warning') warnings += 1
  }

  return <section className="validation-summary" aria-label="Validation summary">
    <div className="validation-counts"><strong>{rows.length} {rows.length === 1 ? 'finding' : 'findings'}</strong><span>{errors} {errors === 1 ? 'error' : 'errors'}</span><span>{warnings} {warnings === 1 ? 'warning' : 'warnings'}</span></div>
    {!!ordered.length && <div className="validation-groups" aria-label="Finding groups">{ordered.map((group) => {
      const key = group.key; return (
        <button type="button" key={key} className={`validation-group ${activeGroup === key ? 'active' : ''}`} aria-pressed={activeGroup === key} onClick={() => onGroupChange(activeGroup === key ? '' : key)}>
          <span className={`finding-severity severity-${String(group.row.severity ?? 'other').toLowerCase()}`}>{text(group.row.severity || 'Issue')}</span>
          <span className="finding-group-count">{group.count}</span>
          <span>{text(group.row.message || group.row.field || group.row.domain || 'Validation finding')}</span>
        </button>
      )
    })}</div>}
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
  const scopes = useMemo(
    () => [...new Set(rows.map((row) => String(row.scope || row.vdom || '')).filter(Boolean))].sort(),
    [rows],
  )
  return <div className="validation-filters" aria-label="Validation filters">
    <label>Search findings<input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search findings" /></label>
    <label>Severity<select value={severity} onChange={(event) => onSeverity(event.target.value)}><option value="">All severities</option>{[...new Set(['error', 'warning', ...rows.map((row) => String(row.severity ?? '').toLowerCase()).filter(Boolean)])].map((item) => <option key={item} value={item}>{fieldLabel(item)}</option>)}</select></label>
    <label>Scope<select value={scope} onChange={(event) => onScope(event.target.value)}><option value="">All scopes</option>{scopes.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
    <button type="button" className="filter-clear" disabled={!search && !scope && !severity && !activeGroup} onClick={onClear}>Clear filters</button>
  </div>
}

function renderValidationRows(
  visibleRows: Finding[],
  startIndex: number,
  selected: Finding | null,
  grouped: boolean,
  onSelect: (row: Finding) => void,
  onNavigate: (row: Finding) => void,
) {
  return visibleRows.map((row, offset) => {
    const index = startIndex + offset
    const targetInfo = validationTarget(row)
    return <tr key={`${row.code ?? ''}-${row.domain ?? ''}-${row.object_name ?? ''}-${index}`} className={selected === row ? 'selected' : ''} onClick={() => onSelect(row)}>
      <td><div className="validation-object-cell"><strong>{text(row.object_name)}</strong>{row.object_name != null && targetInfo != null ? <button type="button" className="finding-inline-link" onClick={(event) => { event.stopPropagation(); onNavigate(row) }}>View object →</button> : null}</div></td>
      <td>{text(row.scope ?? row.vdom)}</td><td>{text(row.domain)}<br />{text(row.field)}</td>
      <td><span className={`finding-severity severity-${String(row.severity ?? 'other').toLowerCase()}`}>{text(row.severity ?? 'Issue')}</span></td>
      {!grouped && <td><button type="button" className="finding-message" onClick={(event) => { event.stopPropagation(); onSelect(row) }}>{text(row.message)}</button></td>}
    </tr>
  })
}

function VirtualizedValidationTable({ rows, selected, onSelect, onNavigate, grouped }: {
  rows: Finding[]
  selected: Finding | null
  onSelect: (row: Finding) => void
  onNavigate: (row: Finding) => void
  grouped: boolean
}) {
  const { wrapRef, onScroll, startIndex, visibleRows, topSpacerHeight, bottomSpacerHeight } = useVirtualRows(rows, VALIDATION_ROW_HEIGHT, grouped)
  const colCount = grouped ? 4 : 5
  return <div ref={wrapRef} className="validation-table-wrap" onScroll={onScroll}><table className="validation-table"><thead><tr><th>Object</th><th>Scope</th><th>Domain / field</th><th>Severity</th>{!grouped && <th>Finding</th>}</tr></thead>
    <tbody>
      {topSpacerHeight > 0 && <tr aria-hidden="true" className="report-virtual-spacer"><td colSpan={colCount} style={{ height: `${topSpacerHeight}px` }} /></tr>}
      {renderValidationRows(visibleRows, startIndex, selected, grouped, onSelect, onNavigate)}
      {bottomSpacerHeight > 0 && <tr aria-hidden="true" className="report-virtual-spacer"><td colSpan={colCount} style={{ height: `${bottomSpacerHeight}px` }} /></tr>}
    </tbody></table></div>
}

function ValidationTable({ rows, selected, onSelect, onNavigate, grouped }: {
  rows: Finding[]
  selected: Finding | null
  onSelect: (row: Finding) => void
  onNavigate: (row: Finding) => void
  grouped: boolean
}) {
  if (!rows.length) return <p className="validation-empty">No findings match the current filters.</p>
  if (rows.length > VIRTUAL_THRESHOLD) {
    return <VirtualizedValidationTable rows={rows} selected={selected} onSelect={onSelect} onNavigate={onNavigate} grouped={grouped} />
  }
  return <div className="validation-table-wrap"><table className="validation-table"><thead><tr><th>Object</th><th>Scope</th><th>Domain / field</th><th>Severity</th>{!grouped && <th>Finding</th>}</tr></thead>
    <tbody>{renderValidationRows(rows, 0, selected, grouped, onSelect, onNavigate)}</tbody></table></div>
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
    if (!query && !scope && !severity) return allRows
    return allRows.filter((row) => {
      if (scope && (row.scope || row.vdom) !== scope) return false
      if (severity && String(row.severity || '').toLowerCase() !== severity) return false
      if (query) return reportSearchText(row).includes(query)
      return true
    })
  }, [allRows, scope, severity, search])
  const matchingGroups = useMemo(() => findingGroups(matchingRows), [matchingRows])
  const group = matchingGroups.find((item) => item.key === activeGroup)
  const filteredRows = useMemo(() => matchingRows.filter((row) => !activeGroup
    || findingGroupKey(row) === activeGroup), [matchingRows, activeGroup])

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
    <div className={`validation-workspace${selected && filteredRows.includes(selected) ? ' has-details' : ''}`}>
      <ValidationTable rows={filteredRows} selected={selected} grouped={!!group} onSelect={(row) => { setSelected(row); setTarget(null) }} onNavigate={navigateToObject} />
      {active && selected && filteredRows.includes(selected) && <ReportDetails finding row={selected} target={target} onNavigate={() => navigateToObject(selected)} onClose={() => { setSelected(null); setTarget(null) }} />}
    </div>
    {!allRows.length && <p className="validation-empty">No validation findings were reported.</p>}
    {!!scopes.length && <p className="validation-scope-note">Findings are reported for {scopes.length} {scopes.length === 1 ? 'scope' : 'scopes'}.</p>}
  </div>
}

function columnPixelWidth(key: string): number {
  const kind = columnWidth(key)
  if (kind === 'short') return 118
  if (kind === 'identity') return 240
  return 230
}

function csvEscape(val: unknown): string {
  const s = val == null ? '' : typeof val === 'object' ? cellSummary(val) : String(val)
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"'
  }
  return s
}

function downloadTableCsv(columns: string[], rows: Finding[], filename: string) {
  if (typeof document === 'undefined' || typeof Blob === 'undefined') return
  const lines = [columns.map((c) => csvEscape(fieldLabel(c))).join(',')]
  for (const r of rows) {
    lines.push(columns.map((c) => csvEscape(r[c])).join(','))
  }
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename || 'export.csv'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function SourceRowsTable({ rows, columns, selected, hasSource, topology, subsection = '', sortCol = null, sortAsc = true, onSort, onSelect }: {
  rows: Finding[]
  columns: string[]
  selected: Finding | null
  hasSource: boolean
  topology: boolean
  subsection?: string
  sortCol?: string | null
  sortAsc?: boolean
  onSort?: (col: string) => void
  onSelect: (row: Finding) => void
}) {
  const { wrapRef, onScroll, startIndex, visibleRows, topSpacerHeight, bottomSpacerHeight } = useVirtualRows(rows, ROW_HEIGHT, columns)
  const totalWidth = columns.reduce((sum, key) => sum + columnPixelWidth(key), 0)

  if (!rows.length) return <p className="report-empty">{hasSource ? 'No rows match the current filters.' : 'No reported entries in this subsection.'}</p>

  return <div
    ref={wrapRef}
    className="report-table-wrap"
    role="region"
    aria-label="Source report rows"
    tabIndex={0}
    onScroll={onScroll}
  >
    <table className="report-table fw-table" style={{ width: `${totalWidth}px` }}>
      <colgroup>{columns.map((key) => <col key={key} style={{ width: `${columnPixelWidth(key)}px` }} />)}</colgroup>
      <thead>
        <tr>
          {columns.map((key, index) => {
            const label = topology && key === 'name' ? 'Interface' : fieldLabel(key)
            const isSorted = sortCol === key
            return (
              <th
                key={key}
                scope="col"
                className={`report-column-${columnWidth(key)}${index === 0 ? ' report-identity' : ''}${onSort ? ' fw-sortable-th' : ''}`}
                onClick={onSort ? () => onSort(key) : undefined}
                title={onSort ? `Sort by ${label}` : undefined}
              >
                {label}
                {isSorted ? (sortAsc ? ' ▲' : ' ▼') : ''}
              </th>
            )
          })}
        </tr>
      </thead>
      <tbody>
        {topSpacerHeight > 0 && <tr aria-hidden="true" className="report-virtual-spacer"><td colSpan={columns.length} style={{ height: `${topSpacerHeight}px` }} /></tr>}
        {visibleRows.map((row, offset) => {
          const rowIndex = startIndex + offset
          const semClass = rowSemanticClass(row, subsection)
          const trClass = [selected === row ? 'selected' : '', semClass].filter(Boolean).join(' ')
          return <tr className={trClass} key={`${row.name ?? row.policy_id ?? rowIndex}-${rowIndex}`} onClick={() => onSelect(row)}>
            {columns.map((key, colIndex) => {
              const value = topology && key === 'name' ? row.display_name ?? row.name : row[key]
              const summaryText = cellSummary(value)
              const badgeVariant = cellBadgeVariant(key, value)
              const mono = isMonoColumn(key)
              const cellClasses = [
                'report-cell',
                value == null ? 'report-not-reported' : '',
                mono ? 'fw-cell-mono' : '',
              ].filter(Boolean).join(' ')
              const cell = (
                <span className={cellClasses} title={cellTooltip(value, summaryText)}>
                  {badgeVariant ? <span className={`fw-badge fw-badge-${badgeVariant}`}>{summaryText}</span> : summaryText}
                </span>
              )
              return <td key={key} className={`report-column-${columnWidth(key)}${colIndex === 0 ? ' report-identity' : ''}`}>
                {colIndex === 0 ? <div className="report-identity-content">{cell}<button type="button" className="finding-inline-link" aria-label={`Details for ${text(row.name ?? row.policy_id ?? row.route_id ?? value)}`} onClick={(event) => { event?.stopPropagation?.(); onSelect(row) }}>Details</button></div> : cell}
              </td>
            })}
          </tr>
        })}
        {bottomSpacerHeight > 0 && <tr aria-hidden="true" className="report-virtual-spacer"><td colSpan={columns.length} style={{ height: `${bottomSpacerHeight}px` }} /></tr>}
      </tbody>
    </table>
  </div>
}

type SectionViewState = {
  search: string
  searchCol?: string
  sortCol?: string | null
  sortAsc?: boolean
  columns?: string[]
}

const VENDOR_DISPLAY_NAMES: Record<string, string> = {
  fortigate: 'FortiGate FortiOS',
  palo_alto: 'Palo Alto PAN-OS',
  cisco_asa: 'Cisco ASA',
  cisco_ftd: 'Cisco FTD / FMC',
  juniper_srx: 'Juniper SRX Junos',
  checkpoint: 'Check Point',
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
  const [views, setViews] = useState<Record<string, SectionViewState>>({})
  const [scope, setScope] = useState('')
  const [subsectionChoices, setSubsectionChoices] = useState<Record<string, string>>({})
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
  const scopes = useMemo(() => {
    const rowsForScope = activeSection === 'Extraction'
      ? subsectionRows
      : (sections.find(({ label }) => label === activeSection)?.rows ?? EMPTY_ROWS)
    const seen = new Set<string>()
    for (const row of rowsForScope) {
      const item = String(row.scope ?? row.vdom ?? '')
      if (item) seen.add(item)
    }
    return [...seen].sort()
  }, [activeSection, sections, subsectionRows])
  const view = views[activeObjectSection] ?? { search: '' }
  const search = view.search
  const searchCol = view.searchCol ?? '__all__'
  const sortCol = view.sortCol ?? null
  const sortAsc = view.sortAsc ?? true
  const effectiveScope = scopes.includes(scope) ? scope : ''
  const allColumns = useMemo(() => rowColumns(subsectionRows, activeObjectSection, data.vendor), [subsectionRows, activeObjectSection, data.vendor])
  const preferredColumns = useMemo(() => defaultColumns(subsectionRows, activeObjectSection, data.vendor, allColumns), [subsectionRows, activeObjectSection, data.vendor, allColumns])
  const columns = view.columns ?? preferredColumns
  function updateView(change: Partial<SectionViewState>) { setViews((current) => ({ ...current, [activeObjectSection]: { ...view, ...change } })); setSelectedRow(null) }
  function setSearch(value: string) { updateView({ search: value }) }
  function toggleSort(col: string) {
    if (sortCol === col) {
      updateView({ sortAsc: !sortAsc })
    } else {
      updateView({ sortCol: col, sortAsc: true })
    }
  }
  function setSourceSection(value: string, section = activeSection) { setSubsectionChoices((current) => ({ ...current, [section]: value })); setSelectedRow(null) }
  function changeSection(value: string) { setActiveSection(value); setSelectedRow(null) }
  function changeScope(value: string) { setScope(value); setSelectedRow(null) }
  const filteredRows = useMemo(() => {
    const query = search.toLowerCase()
    let rows = subsectionRows
    if (query || effectiveScope) {
      rows = subsectionRows.filter((row) => {
        if (effectiveScope && String(row.scope ?? row.vdom ?? '') !== effectiveScope) return false
        if (!unifiedInterfaces && activeObjectSection && row['Source section'] !== activeObjectSection) return false
        if (!query) return true
        if (searchCol && searchCol !== '__all__' && columns.includes(searchCol)) {
          return cellSummary(row[searchCol]).toLowerCase().includes(query) || String(row[searchCol] ?? '').toLowerCase().includes(query)
        }
        return reportSearchText(row).includes(query)
      })
    }
    if (sortCol && columns.includes(sortCol)) {
      rows = rows.slice().sort((a, b) => {
        const av = a[sortCol] == null ? '' : String(a[sortCol])
        const bv = b[sortCol] == null ? '' : String(b[sortCol])
        const an = Number(av)
        const bn = Number(bv)
        if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== '' && bv !== '') {
          return sortAsc ? an - bn : bn - an
        }
        return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av)
      })
    }
    return rows
  }, [subsectionRows, effectiveScope, activeObjectSection, search, searchCol, sortCol, sortAsc, columns, unifiedInterfaces])
  const subsectionCount = search || effectiveScope ? `${filteredRows.length} of ${subsectionRows.length}` : subsectionRows.length
  const reportTabs = useMemo(
    () => ['Overview', 'Interfaces', 'Objects', 'Schedules', 'Policies', 'NAT', 'Routes', 'VPN', 'References', ...(sections.some((item) => item.label === 'Extraction') ? ['Extraction'] : []), ...(sections.some((item) => item.label === 'Additional sections') ? ['Additional sections'] : []), 'Validation'],
    [sections],
  )
  const objectTabs = unifiedInterfaces ? ['interface_topology'] : sourceSections.filter((key) => key === activeObjectSection || active?.subsections.find((item) => item.key === key)?.rows.length)
  const tabLabel = (item: string) => unifiedInterfaces
    ? `Interface Topology (${subsectionCount})`
    : `${fieldLabel(item)} (${activeObjectSection === item ? subsectionCount : active?.subsections.find((section) => section.key === item)?.rows.length ?? 0})`
  const currentSelected = selectedRow && filteredRows.includes(selectedRow) ? selectedRow : null
  const selectedIndex = currentSelected ? filteredRows.indexOf(currentSelected) : -1
  const warningGroups = useMemo(
    () => findingGroups(validationRows).filter((group) => String(group.row.severity).toLowerCase() === 'warning').length,
    [validationRows],
  )
  const exposureWarnings = useMemo(() => validationRows.filter((row) => row.domain === 'interface' && row.field === 'allowaccess'), [validationRows])
  const systemItems = useMemo(() => systemOverviewItems(data), [data])
  const legendItems = useMemo(() => sectionLegend(activeObjectSection, subsectionRows), [activeObjectSection, subsectionRows])

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return
    const onSelectSection = (event: Event) => {
      const next = (event as CustomEvent<string>).detail
      if (next && reportTabs.includes(next)) {
        setActiveSection(next)
        setSelectedRow(null)
      }
    }
    window.addEventListener('fw-select-report-section', onSelectSection)
    return () => window.removeEventListener('fw-select-report-section', onSelectSection)
  })

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.dispatchEvent !== 'function') return
    const vendorLabel = VENDOR_DISPLAY_NAMES[String(data.vendor ?? '')] || String(data.vendor || 'Configuration')
    const filename = String(data.source_evidence?.source_name || data.acquisition || 'Loaded source')
    const sidebarSections = reportTabs.map((label) => {
      if (label === 'Overview') return { label, count: null }
      if (label === 'Policies') return { label, count: counts.policies }
      if (label === 'Objects') return { label, count: counts.objects }
      if (label === 'Interfaces') return { label, count: counts.interfaces }
      if (label === 'Validation') {
        const totalFindings = errorCount + warningCount
        return {
          label,
          count: totalFindings,
          tone: errorCount > 0 ? ('danger' as const) : warningCount > 0 ? ('warning' as const) : undefined,
        }
      }
      const grp = sections.find((s) => s.label === label)
      return { label, count: reportSectionRowCount(grp) }
    })
    window.dispatchEvent(new CustomEvent('fw-workspace-meta', {
      detail: {
        vendorLabel,
        filename,
        errors: errorCount,
        warnings: warningCount,
        activeSection,
        activeSubsectionLabel: unifiedInterfaces ? 'Interface Topology' : fieldLabel(activeObjectSection),
        reportSections: sidebarSections,
      },
    }))
  }, [data.vendor, data.source_evidence, data.acquisition, activeSection, activeObjectSection, unifiedInterfaces, counts, errorCount, warningCount, sections, reportTabs])

  function renderOverviewMetric(item: OverviewMetric) {
    return <tr key={item.label} className={item.tone ? `configuration-summary-${item.tone}` : undefined}>
      <th scope="row">{item.section ? <button type="button" onClick={() => { changeSection(item.section!); if (item.objectSection) setSourceSection(item.objectSection, item.section) }}>{item.label}</button> : item.label}</th>
      <td>{item.value === null ? 'Not reported' : item.value.toLocaleString()}</td>
      <td aria-hidden="true">{item.section && '›'}</td>
    </tr>
  }

  return <section className="panel source-report" aria-labelledby="report-title">
    <div className="report-sticky-header">
      <h2 id="report-title" className="visually-hidden">Source inventory</h2>
      {exportError && <ErrorBanner message={exportError} />}
      <label className="report-section-select">Report section<select value={activeSection} onChange={(event) => changeSection(event.target.value)}>{reportTabs.map((name) => <option key={name}>{name}</option>)}</select></label>
      <nav className="report-tabs fw-tablist" role="tablist" aria-label="Report sections" onKeyDown={tabKeyboard}>
        {reportTabs.map((sectionLabel) => (
          <button key={sectionLabel} id={`report-tab-${encodeURIComponent(sectionLabel)}`} aria-controls={`report-panel-${encodeURIComponent(sectionLabel)}`} tabIndex={activeSection === sectionLabel ? 0 : -1} type="button" role="tab" aria-selected={activeSection === sectionLabel} className={`report-tab fw-tab-btn${activeSection === sectionLabel ? ' active' : ''}`} onClick={() => changeSection(sectionLabel)}>
            {sectionLabel}
          </button>
        ))}
      </nav>
    </div>
    {reportTabs.filter((item) => item !== activeSection).map((item) => <div key={item} hidden role="tabpanel" id={`report-panel-${encodeURIComponent(item)}`} aria-labelledby={`report-tab-${encodeURIComponent(item)}`} />)}
    <div role="tabpanel" id={`report-panel-${encodeURIComponent(activeSection)}`} aria-labelledby={`report-tab-${encodeURIComponent(activeSection)}`} tabIndex={0}>
      {activeSection === 'Overview' ? <>
        <div className="fw-overview-top-bar">
          <div className="fw-overview-meta">
            {Array.isArray(summary.scopes) && summary.scopes.length > 0 && (
              <p className="report-scope-summary">Scopes: {summary.scopes.join(', ')}</p>
            )}
            {data.collection != null && (
              <div className="report-count-note">
                <p>Collection: {String(asRecord(data.collection).status ?? 'Unknown')} · Method: {String(asRecord(data.collection).method ?? 'Not reported')}</p>
                {Array.isArray(asRecord(data.collection).warnings) && <ul>{(asRecord(data.collection).warnings as unknown[]).map((warning, index) => <li key={index}>{String(safeValue(warning))}</li>)}</ul>}
              </div>
            )}
          </div>
          <div className="report-header-actions">
            <ExcelExportControls vendor={data.vendor ?? ''} profile={excelProfile} onProfileChange={onExcelProfileChange} exporting={exporting} onExport={onExport} />
          </div>
        </div>
        <p className="preview-status" role="status" aria-live="polite">{exportStatus}</p>
        <div className="system-overview-section">
          <h3 className="report-overview-heading fw-section-header" id="system-overview-title"><span className="dot" aria-hidden="true" />System Overview</h3>
          <dl className="system-overview-grid" aria-labelledby="system-overview-title">
            {systemItems.map((item) => (
              <div key={item.label} className="system-overview-card">
                <dt>{item.label}</dt>
                <dd className={item.value == null ? 'system-overview-missing' : undefined}>{item.value ?? 'Not reported'}</dd>
                {item.detail && <dd className="system-overview-detail">{item.detail}</dd>}
              </div>
            ))}
          </dl>
        </div>
        <h3 className="report-overview-heading fw-section-header"><span className="dot" aria-hidden="true" />Validation</h3>
        <button type="button" className={`report-validation-attention${errorCount ? ' has-errors' : warningCount ? ' has-warnings' : ''}`} onClick={() => changeSection('Validation')}><div>{sectionsData.validation == null && asRecord(summary.validation).severity_counts == null ? 'Not reported' : <>{errorCount.toLocaleString()} {errorCount === 1 ? 'error' : 'errors'} · {warningCount.toLocaleString()} {warningCount === 1 ? 'warning' : 'warnings'} <small>{warningGroups.toLocaleString()} warning {warningGroups === 1 ? 'group' : 'groups'}</small></>}</div><span>Review findings →</span></button>
        {!!exposureWarnings.length && <div className="report-exposure-warning" role="status">
          <div>
            <strong>Public management exposure ({exposureWarnings.length})</strong>
            <p>{exposureWarnings.map((row) => text(row.object_name)).filter(Boolean).join(', ')} — HTTP/HTTPS/SSH/Telnet management access is enabled on a WAN or public-facing interface.</p>
          </div>
          <button type="button" className="secondary-button" onClick={() => changeSection('Validation')}>Inspect in Validation →</button>
        </div>}
        <div className="report-overview-group">
          <h3 className="report-overview-heading fw-section-header" id="configuration-summary-title"><span className="dot" aria-hidden="true" />Configuration summary</h3>
          <div className="configuration-summary-wrap">
            <table className="configuration-summary" aria-labelledby="configuration-summary-title">
              <thead><tr><th scope="col">Section</th><th scope="col">Count</th><th scope="col"><span className="visually-hidden">Navigation</span></th></tr></thead>
              <tbody>{overviewMetrics.map(renderOverviewMetric)}</tbody>
            </table>
          </div>
        </div>
      </> : activeSection === 'Validation' ? null : <>
        {!!objectTabs.length && <nav className="report-object-tabs fw-tablist" role="tablist" aria-label="Source subsections" onKeyDown={tabKeyboard}>
          {objectTabs.map((item) => (
            <button
              type="button"
              role="tab"
              id={`subsection-tab-${encodeURIComponent(item)}`}
              aria-controls={`subsection-panel-${encodeURIComponent(item)}`}
              tabIndex={activeObjectSection === item ? 0 : -1}
              aria-selected={activeObjectSection === item}
              className={`fw-tab-btn${activeObjectSection === item ? ' active' : ''}`}
              key={item}
              onClick={() => setSourceSection(item)}
            >
              {tabLabel(item)}
            </button>
          ))}
        </nav>}
        {objectTabs.filter((item) => item !== activeObjectSection).map((item) => <div key={item} hidden role="tabpanel" id={`subsection-panel-${encodeURIComponent(item)}`} aria-labelledby={`subsection-tab-${encodeURIComponent(item)}`} />)}
        <div {...(unifiedInterfaces ? {} : { role: 'tabpanel', id: `subsection-panel-${encodeURIComponent(activeObjectSection)}`, 'aria-labelledby': `subsection-tab-${encodeURIComponent(activeObjectSection)}`, tabIndex: 0 as const })}>
          {legendItems.length > 0 && (
            <div className="fw-legend" aria-label="Table color legend">
              {legendItems.map((item) => (
                <span key={item.label} className={`fw-legend-item fw-legend-${item.variant}`}>
                  <span className="fw-legend-swatch" aria-hidden="true" />
                  {item.label}
                </span>
              ))}
            </div>
          )}
          <div className="report-toolbar fw-table-toolbar">
            <label className="report-search-control"><span className="visually-hidden">Search report rows</span><input type="search" value={search} placeholder={unifiedInterfaces ? 'Filter topology rows...' : 'Filter rows...'} onChange={(event) => setSearch(event.target.value)} /></label>
            <div className="report-filter-controls">
              <select aria-label="Search column scope" className="fw-table-col-select" value={searchCol} onChange={(event) => updateView({ searchCol: event.target.value })}>
                <option value="__all__">All columns</option>
                {columns.map((col) => <option key={col} value={col}>{fieldLabel(col)}</option>)}
              </select>
              {scopes.length > 0 && <select aria-label="Filter report scope" value={effectiveScope} onChange={(event) => changeScope(event.target.value)}><option value="">All scopes</option>{scopes.map((item) => <option key={item} value={item}>{item}</option>)}</select>}
              <button type="button" className="filter-clear" disabled={!search && !effectiveScope && !sortCol && searchCol === '__all__'} onClick={() => { updateView({ search: '', searchCol: '__all__', sortCol: null }); changeScope('') }}>Clear filters</button>
            </div>
            <div className="fw-table-toolbar-right">
              <button
                type="button"
                className="secondary-button button-compact fw-csv-btn"
                onClick={() => downloadTableCsv(columns, filteredRows, `${data.vendor || 'firewall'}_${activeObjectSection || 'report'}.csv`)}
                title="Export filtered rows to CSV"
              >
                ⬇ CSV
              </button>
              <details className="report-column-selector"><summary>Columns ({columns.length})</summary><div>{allColumns.map((key, index) => <label key={key}><input type="checkbox" checked={columns.includes(key)} disabled={index === 0} onChange={(event) => updateView({ columns: allColumns.filter((column) => column === allColumns[0] || (column === key ? event.target.checked : columns.includes(column))) })} />{fieldLabel(key)}</label>)}<button className="filter-clear" type="button" onClick={() => updateView({ columns: undefined })}>Reset columns</button></div></details>
            </div>
          </div>
          <div className={`validation-workspace${currentSelected ? ' has-details' : ''}${unifiedInterfaces ? ' report-topology-view' : ''}`}>
            <SourceRowsTable
              rows={filteredRows}
              columns={columns}
              selected={currentSelected}
              hasSource={subsectionRows.length > 0}
              topology={activeObjectSection === 'interface_topology'}
              subsection={activeObjectSection}
              sortCol={sortCol}
              sortAsc={sortAsc}
              onSort={toggleSort}
              onSelect={setSelectedRow}
            />
            {currentSelected && <ReportDetails row={currentSelected} subsection={activeObjectSection} vendor={data.vendor} onClose={() => setSelectedRow(null)} previous={selectedIndex > 0 ? () => setSelectedRow(filteredRows[selectedIndex - 1]) : undefined} next={selectedIndex < filteredRows.length - 1 ? () => setSelectedRow(filteredRows[selectedIndex + 1]) : undefined} />}
          </div>
        </div>
      </>}
      <div hidden={activeSection !== 'Validation'}><ValidationReport data={data} reportScope={scope} onReportScope={changeScope} active={activeSection === 'Validation'} /></div>
    </div>
  </section>
}

