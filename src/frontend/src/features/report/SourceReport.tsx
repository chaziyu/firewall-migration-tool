import { useEffect, useMemo, useRef, useState } from 'react'
import type { LifecycleCardData, PmChecklistResponse, SecurityAuditResponse, SourcePreviewData, SslToIpsecResponse } from '../source/types'
import { fetchSecurityAudit } from '../source/sourceApi'
import { activeSubsection, applianceHeroInfo, asRecord, asRows, cellBadgeVariant, compactValue, downloadCsvRows, extendedSystemOverviewItems, FORTIGATE_CORE_WIFI_SWITCH_TABS, haOverviewInfo, interfaceTopologyRows, isLifecycleCardData, isMonoColumn, matchingSourceRows, reportCounts, reportSections, reportSectionRowCount, reportSearchText, rowColumns, rowSemanticClass, rowSubtypeId, safeValue, sectionLegend, subtypeFilterTabs, defaultColumns, cellSummary, cellTooltip, columnWidth, fieldLabel, findingGroups, findingGroupKey } from './reportPresentation'
import { ConfigDiffPanel } from './ConfigDiffPanel'
import { LifecycleCard } from './LifecycleCard'
import { PacketTracePanel } from './PacketTracePanel'
import { PmLookupPanel } from './PmLookupPanel'
import { PolicyLookupPanel } from './PolicyLookupPanel'
import { ReportDetails } from './ReportDetails'
import { RouteLookupPanel } from './RouteLookupPanel'
import { PublicExposureCard, SecurityAuditPanel } from './SecurityAuditPanel'
import { SslToIpsecPanel } from './SslToIpsecPanel'
import { SdwanView } from './SdwanView'
import { VpnInspectorView } from './VpnInspectorView'
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
  wireless_vap: ['wireless_vaps', 'SSIDs'],
  wireless_wtp: ['wireless_wtps', 'Managed FortiAPs'],
  wtp_profile: ['wtp_profiles', 'FortiAP Profiles'],
  wids_profile: ['wids_profiles', 'WIDS Profiles'],
  managed_switch: ['managed_switches', 'Managed FortiSwitches'],
  managed_switch_port: ['managed_switches', 'Managed FortiSwitches'],
  switch_port_policy: ['switch_port_policies', 'Port Policies'],
  nac_policy: ['nac_policies', 'NAC Policies'],
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
    <h3>Config warnings</h3>
    <ValidationFilters rows={allRows} search={search} scope={scope} severity={severity} activeGroup={group?.key ?? ''} onSearch={(value) => { setSearch(value); setSelected(null) }} onScope={(value) => { onReportScope(value); setSelected(null) }} onSeverity={(value) => { setSeverity(value); setSelected(null) }} onClear={() => { clearFilters(); setSelected(null) }} />
    <ValidationSummary rows={matchingRows} activeGroup={group?.key ?? ''} onGroupChange={(key) => { setActiveGroup(key); setSelected(null) }} />
    {group && <p className="validation-group-explanation"><strong>{group.count} affected findings</strong> · {text(group.row.message)}</p>}
    <div className={`validation-workspace${selected && filteredRows.includes(selected) ? ' has-details' : ''}`}>
      <ValidationTable rows={filteredRows} selected={selected} grouped={!!group} onSelect={(row) => { setSelected(row); setTarget(null) }} onNavigate={navigateToObject} />
      {active && selected && filteredRows.includes(selected) && <ReportDetails finding row={selected} target={target} onNavigate={() => navigateToObject(selected)} onClose={() => { setSelected(null); setTarget(null) }} />}
    </div>
    {!allRows.length && <p className="validation-empty">No config warnings were reported.</p>}
    {!!scopes.length && <p className="validation-scope-note">Findings are reported for {scopes.length} {scopes.length === 1 ? 'scope' : 'scopes'}.</p>}
  </div>
}

function columnPixelWidth(key: string): number {
  const kind = columnWidth(key)
  if (kind === 'short') return 118
  if (kind === 'identity') return 240
  return 230
}

function emptySubsectionMessage(subsection: string): string {
  const messages: Record<string, string> = {
    wireless_wtps: 'No managed FortiAPs configured.',
    wireless_vaps: 'No SSIDs configured.',
    wtp_profiles: 'No FortiAP profiles configured.',
    wids_profiles: 'No WIDS profiles configured.',
    managed_switches: 'No managed FortiSwitches configured.',
    switch_port_policies: 'No port policies configured.',
    nac_policies: 'No NAC policies configured.',
  }
  return messages[subsection] ?? 'No reported entries in this subsection.'
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

  if (!rows.length) return <p className="report-empty">{hasSource ? 'No rows match the current filters.' : emptySubsectionMessage(subsection)}</p>

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

export function SourceReport({
  data,
  activeSection: controlledActiveSection,
  onSectionChange,
  exportStatus,
  exportError,
  liveDeviceAccess = false,
}: {
  data: SourcePreviewData
  activeSection?: string
  onSectionChange?: (section: string) => void
  excelProfile?: 'fast' | 'full'
  onExcelProfileChange?: (value: 'fast' | 'full') => void
  exporting?: boolean
  exportStatus: string
  exportError?: string | null
  onExport?: () => void
  liveDeviceAccess?: boolean
}) {
  const sectionsData = asRecord(data.sections)
  const sections = useMemo(() => reportSections(asRecord(data.sections)), [data.sections])
  const summary = asRecord(data.summary)
  const supportsSecurityAudit = (data.vendor === 'fortigate' || data.vendor === 'palo_alto') && Boolean(data.source_evidence)
  const [internalActiveSection, setInternalActiveSection] = useState('Overview')
  const activeSection = controlledActiveSection ?? internalActiveSection
  const [overviewTab, setOverviewTab] = useState<'summary' | 'packet_trace' | 'config_diff'>('summary')
  const [auditState, setAuditState] = useState<{
    vendor: string
    sourceEvidence: NonNullable<SourcePreviewData['source_evidence']>
    data: SecurityAuditResponse | null
    error: string | null
  } | null>(null)
  const [pmState, setPmState] = useState<{
    vendor: string
    sourceEvidence: NonNullable<SourcePreviewData['source_evidence']>
    data: PmChecklistResponse
  } | null>(null)
  const [sslToIpsecState, setSslToIpsecState] = useState<{
    vendor: string
    sourceEvidence: NonNullable<SourcePreviewData['source_evidence']>
    byVdom: Record<string, SslToIpsecResponse>
  } | null>(null)
  const [resolvedLifecycle, setResolvedLifecycle] = useState<LifecycleCardData | null>(null)
  const [views, setViews] = useState<Record<string, SectionViewState>>({})
  const [scope, setScope] = useState('')
  const [subsectionChoices, setSubsectionChoices] = useState<Record<string, string>>({})
  const [subtypeChoices, setSubtypeChoices] = useState<Record<string, string>>({})
  const [selectedRow, setSelectedRow] = useState<Finding | null>(null)
  const validationRows = useMemo(() => asRows(sectionsData.validation), [sectionsData.validation])
  const counts = useMemo(() => reportCounts(data), [data])
  const errorCount = counts.errors
  const warningCount = counts.warnings
  const overviewMetrics: OverviewMetric[] = []
  overviewMetrics.push({ label: 'Policies', value: counts.policies, section: 'Policies & NAT', objectSection: 'policies' })
  overviewMetrics.push({ label: 'Address/service objects', value: counts.objects, section: 'Objects', objectSection: 'addresses' })
  overviewMetrics.push({ label: 'Interfaces', value: counts.interfaces, section: 'Interfaces & Network', objectSection: 'interface_topology' })
  const schedulesGroup = sections.find((item) => item.label === 'Objects')?.subsections.find((s) => s.key === 'schedules')
  overviewMetrics.push({ label: 'Schedules', value: schedulesGroup ? schedulesGroup.rows.length : null, section: 'Objects', objectSection: 'schedules' })
  const natGroup = sections.find((item) => item.label === 'Policies & NAT')?.subsections.find((s) => s.key === 'nat')
  overviewMetrics.push({ label: 'NAT', value: natGroup ? natGroup.rows.length : null, section: 'Policies & NAT', objectSection: 'nat' })
  const routesGroup = sections.find((item) => item.label === 'Interfaces & Network')?.subsections.find((s) => s.key === 'routes')
  overviewMetrics.push({ label: 'Routes', value: routesGroup ? routesGroup.rows.length : null, section: 'Interfaces & Network', objectSection: 'routes' })
  const vpnGroup = sections.find((item) => item.label === 'VPN')
  overviewMetrics.push({ label: 'VPN', value: reportSectionRowCount(vpnGroup), section: 'VPN' })
  const unresolved = Array.isArray(sectionsData.unresolved_references) ? sectionsData.unresolved_references.length : null
  if (sectionsData.unresolved_references) overviewMetrics.push({ label: 'Unresolved references', value: unresolved, section: 'Diagnostics & Coverage', objectSection: 'unresolved_references', tone: unresolved ? 'warning' : undefined })
  const unsupported = Number(summary.unsupported_count ?? summary.source_only_count ?? 0)
  if (summary.unsupported_count != null || summary.source_only_count != null) overviewMetrics.push({ label: 'Unsupported / source-only', value: unsupported })
  const active = sections.find(({ label: sectionLabel }) => sectionLabel === activeSection)
  const isFortiGateWifiSwitch = data.vendor === 'fortigate' && activeSection === 'WiFi & Switch'
  const isFortiGateNetwork = data.vendor === 'fortigate' && activeSection === 'Interfaces & Network'
  const effectiveSubsections = useMemo(() => {
    const rawSubsections = active?.subsections ?? []
    if (isFortiGateWifiSwitch) {
      const byKey = new Map(rawSubsections.map((item) => [item.key, item]))
      const core = FORTIGATE_CORE_WIFI_SWITCH_TABS.map((key) => byKey.get(key) ?? { key, rows: EMPTY_ROWS })
      const coreSet = new Set<string>(FORTIGATE_CORE_WIFI_SWITCH_TABS)
      const extras = rawSubsections.filter((item) => !coreSet.has(item.key) && item.rows.length > 0)
      return [...core, ...extras]
    }
    if (isFortiGateNetwork && !rawSubsections.some((item) => item.key === 'sdwan')) {
      const next = [...rawSubsections]
      const topoIndex = next.findIndex((item) => item.key === 'interface_topology')
      const ifaceIndex = next.findIndex((item) => item.key === 'interfaces')
      const insertAt = topoIndex >= 0 ? topoIndex + 1 : ifaceIndex >= 0 ? ifaceIndex + 1 : 0
      next.splice(insertAt, 0, { key: 'sdwan', rows: EMPTY_ROWS })
      return next
    }
    return rawSubsections
  }, [active, isFortiGateWifiSwitch, isFortiGateNetwork])
  const sourceSections = effectiveSubsections.map((item) => item.key)
  const defaultNetworkChoice = activeSection === 'Interfaces & Network' && !subsectionChoices[activeSection] && sourceSections.includes('interface_topology')
    ? 'interface_topology'
    : (subsectionChoices[activeSection] ?? '')
  const subsection = useMemo(() => activeSubsection(
    effectiveSubsections, defaultNetworkChoice,
  ), [effectiveSubsections, defaultNetworkChoice])
  const virtualToolTab =
    supportsSecurityAudit && activeSection === 'Policies & NAT' && subsectionChoices[activeSection] === 'policy_lookup'
      ? 'policy_lookup'
      : supportsSecurityAudit && activeSection === 'Interfaces & Network' && subsectionChoices[activeSection] === 'route_lookup'
        ? 'route_lookup'
        : supportsSecurityAudit && data.vendor === 'fortigate' && activeSection === 'VPN' && subsectionChoices[activeSection] === 'ssl_to_ipsec'
          ? 'ssl_to_ipsec'
          : activeSection === 'Diagnostics & Coverage' && (
            subsectionChoices[activeSection] === 'config_warnings'
            || (!subsectionChoices[activeSection] && !subsection && validationRows.length > 0)
          )
            ? 'config_warnings'
            : ''
  const activeObjectSection = virtualToolTab || (subsection?.key ?? '')
  const unifiedInterfaces = activeSection === 'Interfaces & Network' && activeObjectSection === 'interface_topology'
  const unifiedRows = useMemo(() => {
    const subsections = sections.find((item) => item.label === activeSection)?.subsections
    return interfaceTopologyRows(
      subsections?.find((item) => item.key === 'interfaces')?.rows ?? EMPTY_ROWS,
      subsections?.find((item) => item.key === 'interface_topology')?.rows ?? EMPTY_ROWS,
    )
  }, [sections, activeSection])
  const subsectionRows = unifiedInterfaces ? unifiedRows : subsection?.rows ?? EMPTY_ROWS
  const subtypeTabs = useMemo(() => subtypeFilterTabs(activeObjectSection, subsectionRows), [activeObjectSection, subsectionRows])
  const activeSubtype = subtypeTabs.some((item) => item.id === subtypeChoices[activeObjectSection]) ? subtypeChoices[activeObjectSection] : 'all'
  const scopes = useMemo(() => {
    const rowsForScope = activeSection === 'Diagnostics & Coverage'
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
  function changeSection(value: string) {
    if (onSectionChange) onSectionChange(value)
    else setInternalActiveSection(value)
    setSelectedRow(null)
  }
  function changeScope(value: string) { setScope(value); setSelectedRow(null) }
  const filteredRows = useMemo(() => {
    const query = search.toLowerCase()
    let rows = subsectionRows
    if (query || effectiveScope || activeSubtype !== 'all') {
      rows = subsectionRows.filter((row) => {
        if (effectiveScope && String(row.scope ?? row.vdom ?? '') !== effectiveScope) return false
        if (!unifiedInterfaces && activeObjectSection && row['Source section'] !== activeObjectSection) return false
        if (activeSubtype !== 'all' && rowSubtypeId(activeObjectSection, row) !== activeSubtype) return false
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
  }, [subsectionRows, effectiveScope, activeObjectSection, activeSubtype, search, searchCol, sortCol, sortAsc, columns, unifiedInterfaces])
  const subtypeTotalCount = activeSubtype === 'all' ? subsectionRows.length : (subtypeTabs.find((item) => item.id === activeSubtype)?.count ?? subsectionRows.length)
  const subsectionCount = search || effectiveScope || activeSubtype !== 'all' ? `${filteredRows.length} of ${subtypeTotalCount}` : subsectionRows.length
  const matchingAuditState =
    supportsSecurityAudit && data.source_evidence && auditState
    && auditState.vendor === data.vendor && auditState.sourceEvidence === data.source_evidence
      ? auditState
      : null
  const auditData = matchingAuditState?.data ?? null
  const auditLoading = supportsSecurityAudit && Boolean(data.source_evidence) && !matchingAuditState
  const auditError = matchingAuditState?.error ?? null
  const matchingPmData =
    supportsSecurityAudit && data.source_evidence && pmState
    && pmState.vendor === data.vendor && pmState.sourceEvidence === data.source_evidence
      ? pmState.data
      : null
  const matchingSslToIpsecData =
    supportsSecurityAudit && data.vendor === 'fortigate' && data.source_evidence && sslToIpsecState
    && sslToIpsecState.vendor === data.vendor && sslToIpsecState.sourceEvidence === data.source_evidence
      ? (Object.values(sslToIpsecState.byVdom)[0] ?? null)
      : null
  const initialLifecycle = isLifecycleCardData(summary.lifecycle) ? summary.lifecycle : null
  const activeLifecycle = resolvedLifecycle ?? initialLifecycle

  useEffect(() => {
    if (!supportsSecurityAudit || !data.source_evidence || !data.vendor) return
    const vendor = data.vendor
    const evidence = data.source_evidence
    let active = true
    fetchSecurityAudit(vendor, evidence)
      .then((res) => {
        if (active) setAuditState({ vendor, sourceEvidence: evidence, data: res, error: null })
      })
      .catch((err: unknown) => {
        if (active) {
          setAuditState({
            vendor,
            sourceEvidence: evidence,
            data: null,
            error: err instanceof Error ? err.message : 'Security audit failed',
          })
        }
      })
    return () => { active = false }
  }, [supportsSecurityAudit, data.vendor, data.source_evidence])
  const reportTabs = useMemo(
    () => {
      const hasSection = (label: string) => sections.some((item) => item.label === label && item.rows.length > 0)
      return [
        'Overview',
        ...(supportsSecurityAudit ? ['Security Audit'] : []),
        ...(supportsSecurityAudit ? ['PM Lookup'] : []),
        'Policies & NAT',
        'Objects',
        'Interfaces & Network',
        ...(hasSection('Security Profiles') ? ['Security Profiles'] : []),
        'VPN',
        ...(hasSection('Users & Auth') ? ['Users & Auth'] : []),
        ...(data.vendor === 'fortigate' || hasSection('WiFi & Switch') ? ['WiFi & Switch'] : []),
        ...(sections.some((item) => item.label === 'Diagnostics & Coverage') || validationRows.length > 0 ? ['Diagnostics & Coverage'] : []),
        ...(hasSection('System & Logs') ? ['System & Logs'] : []),
        ...(sections.some((item) => item.label === 'Additional sections') ? ['Additional sections'] : []),
      ]
    },
    [sections, supportsSecurityAudit, data.vendor, validationRows.length],
  )
  const baseObjectTabs = isFortiGateWifiSwitch
    ? sourceSections
    : sourceSections.filter((key) => (
      key === activeObjectSection
      || (isFortiGateNetwork && key === 'sdwan')
      || active?.subsections.find((item) => item.key === key)?.rows.length
    ))
  const objectTabs = [
    ...baseObjectTabs,
    ...(supportsSecurityAudit && activeSection === 'Policies & NAT' ? ['policy_lookup'] : []),
    ...(supportsSecurityAudit && activeSection === 'Interfaces & Network' ? ['route_lookup'] : []),
    ...(supportsSecurityAudit && data.vendor === 'fortigate' && activeSection === 'VPN' ? ['ssl_to_ipsec'] : []),
    ...(activeSection === 'Diagnostics & Coverage' && (validationRows.length > 0 || activeObjectSection === 'config_warnings') ? ['config_warnings'] : []),
  ]
  const subsectionLabel = (key: string) => (
    key === 'vpn_inspector'
      ? (data.vendor === 'palo_alto' ? 'IPSec Inspector' : 'Site-to-Site Inspector')
      : key === 'policy_lookup'
        ? 'Policy Lookup'
        : key === 'route_lookup'
          ? 'Route Lookup'
          : key === 'ssl_to_ipsec'
            ? 'SSL-to-IPSec Assistant'
            : key === 'config_warnings'
              ? 'Config Warnings'
              : fieldLabel(key)
  )
  const COMPACT_TAB_LABELS: Record<string, string> = {
    interface_topology: 'Topology',
    router_bgp: 'BGP',
    router_ospf: 'OSPF',
    router_ospf6: 'OSPFv3',
    router_rip: 'RIP',
  }
  const tabRawCount = (item: string): number | null => {
    if (item === 'policy_lookup' || item === 'route_lookup' || item === 'ssl_to_ipsec') return null
    if (item === 'config_warnings') return errorCount + warningCount
    if (item === 'sdwan') {
      const sdwanRows = effectiveSubsections.find((section) => section.key === 'sdwan')?.rows ?? EMPTY_ROWS
      return sdwanRows.reduce((sum, entry) => sum + (Array.isArray(entry.services) ? entry.services.length : 0), 0)
    }
    if (item === 'interface_topology' && activeSection === 'Interfaces & Network') return unifiedRows.length
    return effectiveSubsections.find((section) => section.key === item)?.rows.length ?? 0
  }
  const tabLabel = (item: string) => {
    if (item === 'policy_lookup') return 'Policy Lookup'
    if (item === 'route_lookup') return 'Route Lookup'
    if (item === 'ssl_to_ipsec') return 'SSL-to-IPSec Assistant'
    if (item === 'config_warnings') return `Config Warnings (${(errorCount + warningCount).toLocaleString()})`
    if (item === 'sdwan') return `SD-WAN (${tabRawCount(item) ?? 0})`
    const count = activeObjectSection === item
      ? subsectionCount
      : (tabRawCount(item) ?? 0)
    const label = COMPACT_TAB_LABELS[item] ?? subsectionLabel(item)
    return `${label} (${count})`
  }
  const currentSelected = selectedRow && filteredRows.includes(selectedRow) ? selectedRow : null
  const selectedIndex = currentSelected ? filteredRows.indexOf(currentSelected) : -1
  const exposureWarnings = useMemo(() => validationRows.filter((row) => row.domain === 'interface' && row.field === 'allowaccess'), [validationRows])
  const vendorDisplayName = VENDOR_DISPLAY_NAMES[String(data.vendor ?? '')] || String(data.vendor || 'Configuration')
  const systemItems = extendedSystemOverviewItems(data, auditData, activeLifecycle)
  const HERO_DUPLICATE_LABELS = new Set(['Hostname', 'Model', 'Firmware Version', 'Software Version', 'Timezone', 'Serial Number'])
  const filteredSystemItems = systemItems.filter((item) => !HERO_DUPLICATE_LABELS.has(item.label))
  const displaySystemItems = filteredSystemItems.length > 0 ? filteredSystemItems : systemItems
  const scopeList = Array.isArray(summary.scopes) && summary.scopes.length > 0 ? summary.scopes.join(', ') : null
  const haInfo = useMemo(() => haOverviewInfo(data), [data])
  const heroInfo = applianceHeroInfo(data, vendorDisplayName, activeLifecycle, auditData)
  const legendItems = useMemo(() => sectionLegend(activeObjectSection, subsectionRows), [activeObjectSection, subsectionRows])

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return
    const onSelectSection = (event: Event) => {
      const next = (event as CustomEvent<string>).detail
      if (next && reportTabs.includes(next)) {
        if (onSectionChange) onSectionChange(next)
        else setInternalActiveSection(next)
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
      if (label === 'Policies & NAT') return { label, count: counts.policies }
      if (label === 'Objects') return { label, count: counts.objects }
      if (label === 'Interfaces & Network') return { label, count: counts.interfaces }
      if (label === 'Security Audit') {
        if (!auditData) return { label, count: null }
        const actionable = auditData.quick_audit.high_count + auditData.quick_audit.med_count
        return {
          label,
          count: actionable,
          tone: auditData.quick_audit.high_count > 0 ? ('danger' as const) : auditData.quick_audit.med_count > 0 ? ('warning' as const) : undefined,
        }
      }
      if (label === 'PM Lookup') {
        if (!matchingPmData) return { label, count: null }
        const { fail, warn } = matchingPmData.summary
        return {
          label,
          count: fail + warn,
          tone: fail > 0 ? ('danger' as const) : warn > 0 ? ('warning' as const) : undefined,
        }
      }
      if (label === 'Diagnostics & Coverage') {
        const grp = sections.find((s) => s.label === label)
        return { label, count: (reportSectionRowCount(grp) ?? 0) + validationRows.length }
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
        activeSubsectionLabel: activeObjectSection === 'policy_lookup'
          ? 'Policy Lookup'
          : activeObjectSection === 'route_lookup'
            ? 'Route Lookup'
            : activeObjectSection === 'ssl_to_ipsec'
              ? 'SSL-to-IPSec Assistant'
              : activeObjectSection === 'config_warnings'
                ? 'Config Warnings'
                : unifiedInterfaces
                  ? 'Interface Topology'
                  : fieldLabel(activeObjectSection),
        reportSections: sidebarSections,
      },
    }))
  }, [data.vendor, data.source_evidence, data.acquisition, activeSection, activeObjectSection, unifiedInterfaces, counts, errorCount, warningCount, sections, reportTabs, matchingPmData, auditData, validationRows.length])

  function renderOverviewMetric(item: OverviewMetric) {
    return <tr key={item.label} className={item.tone ? `configuration-summary-${item.tone}` : undefined}>
      <th scope="row">{item.section ? <button type="button" onClick={() => { changeSection(item.section!); if (item.objectSection) setSourceSection(item.objectSection, item.section) }}>{item.label}</button> : item.label}</th>
      <td>{item.value === null ? 'Not reported' : item.value.toLocaleString()}</td>
      <td aria-hidden="true">{item.section && '›'}</td>
    </tr>
  }

  return <section className="panel source-report" aria-labelledby="report-title">
    <h2 id="report-title" className="visually-hidden">Source inventory</h2>
    {exportError && <ErrorBanner message={exportError} />}
    {exportStatus && <p className="preview-status" role="status" aria-live="polite">{exportStatus}</p>}
    <div role="tabpanel" id={`report-panel-${encodeURIComponent(activeSection)}`} aria-label={activeSection} tabIndex={0}>
      {activeSection === 'Overview' ? <>
        {supportsSecurityAudit && (
          <nav className="report-object-tabs fw-tablist" role="tablist" aria-label="Overview subsections" onKeyDown={tabKeyboard}>
            <button
              type="button"
              role="tab"
              aria-selected={overviewTab === 'summary'}
              className={`fw-tab-btn${overviewTab === 'summary' ? ' active' : ''}`}
              onClick={() => setOverviewTab('summary')}
            >
              Summary
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={overviewTab === 'packet_trace'}
              className={`fw-tab-btn${overviewTab === 'packet_trace' ? ' active' : ''}`}
              onClick={() => setOverviewTab('packet_trace')}
            >
              Trace Packet
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={overviewTab === 'config_diff'}
              className={`fw-tab-btn${overviewTab === 'config_diff' ? ' active' : ''}`}
              onClick={() => setOverviewTab('config_diff')}
            >
              Config Diff
            </button>
          </nav>
        )}
        {supportsSecurityAudit && data.source_evidence && overviewTab === 'packet_trace' ? (
          <PacketTracePanel
            vendor={data.vendor ?? ''}
            sourceEvidence={data.source_evidence}
            sections={sectionsData}
          />
        ) : supportsSecurityAudit && data.source_evidence && overviewTab === 'config_diff' ? (
          <ConfigDiffPanel
            vendor={data.vendor ?? ''}
            sourceEvidence={data.source_evidence}
            currentFilename={String(data.source_evidence.source_name || data.acquisition || 'Loaded source')}
          />
        ) : <>
        {data.collection != null && (
          <div className="fw-overview-top-bar">
            <div className="fw-overview-meta">
              <div className="report-count-note">
                <p>Collection: {String(asRecord(data.collection).status ?? 'Unknown')} · Method: {String(asRecord(data.collection).method ?? 'Not reported')}</p>
                {Array.isArray(asRecord(data.collection).warnings) && <ul>{(asRecord(data.collection).warnings as unknown[]).map((warning, index) => <li key={index}>{String(safeValue(warning))}</li>)}</ul>}
              </div>
            </div>
          </div>
        )}

        <section className="fw-card fw-card-flex fw-hero-card" aria-label="Appliance overview">
          <div className="fw-hero-heading">
            <div className="fw-hero-eyebrow">{heroInfo.eyebrow}</div>
            <div className="fw-hero-title fw-mono">{heroInfo.title}</div>
            {(heroInfo.subtitle || scopeList) && (
              <div className="fw-hero-sub">
                {heroInfo.subtitle}
                {scopeList ? `${heroInfo.subtitle ? ' · ' : ''}Scopes: ${scopeList}` : ''}
              </div>
            )}
          </div>
          {(heroInfo.badges.length > 0 || errorCount > 0 || warningCount > 0) && (
            <div className="fw-hero-badges">
              {heroInfo.badges.map((badge, idx) => (
                badge.targetSection ? (
                  <button
                    key={`${badge.text}-${idx}`}
                    type="button"
                    id={badge.id}
                    className={`fw-badge fw-badge-${badge.variant} fw-badge-link`}
                    onClick={() => changeSection(badge.targetSection!)}
                  >
                    {badge.text}
                  </button>
                ) : (
                  <span key={`${badge.text}-${idx}`} id={badge.id} className={`fw-badge fw-badge-${badge.variant}`}>
                    {badge.text}
                  </span>
                )
              ))}
              {(errorCount > 0 || warningCount > 0) && (
                <button
                  type="button"
                  className={`fw-badge fw-badge-${errorCount > 0 ? 'deny' : 'warn'} fw-badge-link`}
                  onClick={() => { changeSection('Diagnostics & Coverage'); setSourceSection('config_warnings', 'Diagnostics & Coverage') }}
                >
                  Config Warnings: {(errorCount + warningCount).toLocaleString()}
                </button>
              )}
            </div>
          )}
        </section>

        <div className={`fw-overview-bento${!activeLifecycle && !haInfo ? ' fw-overview-bento-single' : ''}`}>
          <div className="fw-overview-main">
            <section className="fw-card fw-overview-panel" aria-labelledby="system-overview-title">
              <div className="fw-overview-panel-head">
                <h3 className="fw-overview-panel-title" id="system-overview-title">System &amp; Network</h3>
              </div>
              <dl className="fw-spec-list" aria-labelledby="system-overview-title">
                {displaySystemItems.map((item) => (
                  <div key={item.label} className="fw-spec-row">
                    <dt className="fw-spec-label">{item.label}</dt>
                    <dd className="fw-spec-val-wrap">
                      <span className={item.value == null ? 'fw-spec-val system-overview-missing' : 'fw-spec-val'}>
                        {item.value ?? 'Not reported'}
                      </span>
                      {item.detail && <span className="fw-spec-detail">{item.detail}</span>}
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          </div>

          {(activeLifecycle || haInfo) && (
            <div className="fw-overview-aside">
              {activeLifecycle && (
                <LifecycleCard lifecycle={activeLifecycle} onLifecycleResolved={setResolvedLifecycle} />
              )}

              {haInfo && (
                <section className="fw-card fw-overview-panel fw-ha-panel" aria-labelledby="ha-overview-title">
                  <div className="fw-overview-panel-head">
                    <h3 className="fw-overview-panel-title" id="ha-overview-title">High Availability</h3>
                    <span className={`fw-badge fw-badge-${haInfo.badgeVariant}`}>{haInfo.badgeText}</span>
                  </div>
                  <div className="fw-ha-summary">
                    <div className="fw-ha-title">{haInfo.title}</div>
                    <div className="fw-ha-sub">{haInfo.subtitle}</div>
                  </div>
                  {haInfo.enabled && haInfo.items.length > 0 && (
                    <dl className="fw-spec-list fw-spec-list-compact" aria-label="High Availability details">
                      {haInfo.items.map((item) => (
                        <div key={item.label} className="fw-spec-row">
                          <dt className="fw-spec-label">{item.label}</dt>
                          <dd className="fw-spec-val-wrap">
                            <span className="fw-spec-val">{item.value ?? '—'}</span>
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}
                </section>
              )}
            </div>
          )}
        </div>

        <PublicExposureCard
          vendor={data.vendor ?? ''}
          sourceEvidence={data.source_evidence}
          audit={auditData}
          liveDeviceAccess={liveDeviceAccess}
          exposureWarnings={exposureWarnings}
          onInspectValidation={() => { changeSection('Diagnostics & Coverage'); setSourceSection('config_warnings', 'Diagnostics & Coverage') }}
        />

        <section className="fw-card fw-overview-panel fw-overview-summary-panel" aria-labelledby="configuration-summary-title">
          <div className="fw-overview-panel-head">
            <h3 className="fw-overview-panel-title" id="configuration-summary-title">Configuration summary</h3>
          </div>
          <div className="configuration-summary-wrap">
            <table className="configuration-summary" aria-labelledby="configuration-summary-title">
              <thead><tr><th scope="col">Section</th><th scope="col">Count</th><th scope="col"><span className="visually-hidden">Navigation</span></th></tr></thead>
              <tbody>{overviewMetrics.map(renderOverviewMetric)}</tbody>
            </table>
          </div>
        </section>
        </>}
      </> : activeSection === 'Security Audit' ? (
        <>
          <section className="fw-card fw-card-flex fw-hero-card" aria-label="Security audit summary">
            <div className="fw-hero-heading">
              <div className="fw-hero-eyebrow">Security Audit</div>
              <div className="fw-hero-title fw-mono">{heroInfo.title}</div>
              {heroInfo.subtitle && <div className="fw-hero-sub">{heroInfo.subtitle}</div>}
            </div>
            <div className="fw-hero-badges">
              {heroInfo.badges
                .filter((b) => b.targetSection === 'Security Audit')
                .map((badge, idx) => (
                  <span key={`${badge.text}-${idx}`} className={`fw-badge fw-badge-${badge.variant}`}>
                    {badge.text}
                  </span>
                ))}
            </div>
          </section>

          {supportsSecurityAudit && data.source_evidence ? (
            <SecurityAuditPanel
              vendor={data.vendor ?? ''}
              sourceEvidence={data.source_evidence}
              liveDeviceAccess={liveDeviceAccess}
              initialAudit={auditData}
              managedExternally
              externalLoading={auditLoading}
              externalError={auditError}
            />
          ) : null}
        </>
      ) : activeSection === 'PM Lookup' && supportsSecurityAudit && data.source_evidence ? (
        <PmLookupPanel
          vendor={data.vendor ?? ''}
          sourceEvidence={data.source_evidence}
          initialData={matchingPmData}
          onLoaded={(res) => {
            if (data.vendor && data.source_evidence) {
              setPmState({ vendor: data.vendor, sourceEvidence: data.source_evidence, data: res })
            }
          }}
        />
      ) : <>
        {!!objectTabs.length && <nav className="report-object-tabs fw-tablist" role="tablist" aria-label="Source subsections" onKeyDown={tabKeyboard}>
          {objectTabs.map((item) => {
            const isEmpty = tabRawCount(item) === 0
            return (
              <button
                type="button"
                role="tab"
                id={`subsection-tab-${encodeURIComponent(item)}`}
                aria-controls={`subsection-panel-${encodeURIComponent(item)}`}
                tabIndex={activeObjectSection === item ? 0 : -1}
                aria-selected={activeObjectSection === item}
                className={`fw-tab-btn${activeObjectSection === item ? ' active' : ''}${isEmpty ? ' fw-tab-btn--empty' : ''}`}
                key={item}
                onClick={() => setSourceSection(item)}
              >
                {tabLabel(item)}
              </button>
            )
          })}
        </nav>}
        {objectTabs.filter((item) => item !== activeObjectSection).map((item) => <div key={item} hidden role="tabpanel" id={`subsection-panel-${encodeURIComponent(item)}`} aria-labelledby={`subsection-tab-${encodeURIComponent(item)}`} />)}
        <div role="tabpanel" id={`subsection-panel-${encodeURIComponent(activeObjectSection)}`} aria-labelledby={`subsection-tab-${encodeURIComponent(activeObjectSection)}`} tabIndex={0}>
          {activeObjectSection === 'config_warnings' ? (
            <ValidationReport data={data} reportScope={scope} onReportScope={changeScope} active />
          ) : activeObjectSection === 'policy_lookup' && supportsSecurityAudit && data.source_evidence ? (
            <PolicyLookupPanel
              vendor={data.vendor ?? ''}
              sourceEvidence={data.source_evidence}
              sections={sectionsData}
            />
          ) : activeObjectSection === 'route_lookup' && supportsSecurityAudit && data.source_evidence ? (
            <RouteLookupPanel
              vendor={data.vendor ?? ''}
              sourceEvidence={data.source_evidence}
              sections={sectionsData}
            />
          ) : activeObjectSection === 'ssl_to_ipsec' && supportsSecurityAudit && data.vendor === 'fortigate' && data.source_evidence ? (
            <SslToIpsecPanel
              vendor={data.vendor ?? ''}
              sourceEvidence={data.source_evidence}
              initialData={matchingSslToIpsecData}
              onLoaded={(vdomKey, res) => {
                if (data.vendor && data.source_evidence) {
                  const sourceEvidence = data.source_evidence
                  const vendor = data.vendor
                  setSslToIpsecState((current) => ({
                    vendor,
                    sourceEvidence,
                    byVdom: {
                      ...(current && current.vendor === vendor && current.sourceEvidence === sourceEvidence ? current.byVdom : {}),
                      [vdomKey]: res,
                    },
                  }))
                }
              }}
            />
          ) : activeObjectSection === 'sdwan' && data.vendor === 'fortigate' ? (
            <>
              {scopes.length > 0 && (
                <div className="sdwan-scope-bar">
                  <select aria-label="Filter report scope" value={effectiveScope} onChange={(event) => changeScope(event.target.value)}>
                    <option value="">All scopes</option>
                    {scopes.map((item) => <option key={item} value={item}>{item}</option>)}
                  </select>
                </div>
              )}
              <SdwanView rows={subsectionRows} scope={effectiveScope} />
            </>
          ) : <>
          {activeObjectSection === 'ssl_vpn_settings' && supportsSecurityAudit && data.vendor === 'fortigate' && (
            <div className="fw-ssl-ipsec-callout" role="note">
              <span>Planning a migration from SSL-VPN to Dial-up IPSec (IKEv2)?</span>
              <button
                type="button"
                className="secondary-button button-compact"
                onClick={() => setSourceSection('ssl_to_ipsec')}
              >
                Open SSL-to-IPSec Assistant →
              </button>
            </div>
          )}
          {subtypeTabs.length > 0 && (
            <nav className="fw-subtablist" role="tablist" aria-label="Object type filters" onKeyDown={tabKeyboard}>
              {subtypeTabs.map((sub) => (
                <button
                  key={sub.id}
                  type="button"
                  role="tab"
                  aria-selected={activeSubtype === sub.id}
                  className={`fw-subtab-btn${activeSubtype === sub.id ? ' active' : ''}`}
                  onClick={() => {
                    setSubtypeChoices((current) => ({ ...current, [activeObjectSection]: sub.id }))
                    setSelectedRow(null)
                  }}
                >
                  {sub.label} ({sub.count.toLocaleString()})
                </button>
              ))}
            </nav>
          )}
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
                onClick={() => downloadCsvRows(columns, filteredRows, `${data.vendor || 'firewall'}_${activeObjectSection || 'report'}.csv`)}
                title="Export filtered rows to CSV"
              >
                ⬇ CSV
              </button>
              <details className="report-column-selector"><summary>Columns ({columns.length})</summary><div>{allColumns.map((key, index) => <label key={key}><input type="checkbox" checked={columns.includes(key)} disabled={index === 0} onChange={(event) => updateView({ columns: allColumns.filter((column) => column === allColumns[0] || (column === key ? event.target.checked : columns.includes(column))) })} />{fieldLabel(key)}</label>)}<button className="filter-clear" type="button" onClick={() => updateView({ columns: undefined })}>Reset columns</button></div></details>
            </div>
          </div>
          {activeObjectSection === 'vpn_inspector' ? (
            <VpnInspectorView rows={filteredRows} vendor={data.vendor} />
          ) : (
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
          )}
          </>}
        </div>
      </>}
    </div>
  </section>
}

