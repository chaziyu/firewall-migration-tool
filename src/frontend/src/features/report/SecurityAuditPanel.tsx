import { useEffect, useMemo, useState } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { CertificateRow, ExposureProbeResponse, SecurityAuditResponse } from '../source/types'
import {
  fetchSecurityAudit,
  probePublicExposure,
} from '../source/sourceApi'
import { downloadCsvRows } from './reportPresentation'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { LoadingState } from '../../components/common/LoadingState'

function certStatusBadge(status: string): 'deny' | 'warn' | 'allow' | 'muted' {
  if (status === 'Expired') return 'deny'
  if (status === 'Expiring Soon') return 'warn'
  if (status === 'Valid') return 'allow'
  return 'muted'
}

function auditSeverityBadge(severity: string): 'deny' | 'warn' | 'info' {
  if (severity === 'High') return 'deny'
  if (severity === 'Medium') return 'warn'
  return 'info'
}

const CERT_STATUS_PRIORITY: Record<string, number> = {
  Expired: 0,
  'Expiring Soon': 1,
  Valid: 2,
}

function sortCertificates(rows: CertificateRow[]): CertificateRow[] {
  return rows.slice().sort((a, b) => {
    const pa = CERT_STATUS_PRIORITY[a.status] ?? 3
    const pb = CERT_STATUS_PRIORITY[b.status] ?? 3
    if (pa !== pb) return pa - pb
    const da = Number(a.days_left)
    const db = Number(b.days_left)
    const aValid = a.days_left !== '' && Number.isFinite(da)
    const bValid = b.days_left !== '' && Number.isFinite(db)
    if (aValid && bValid && da !== db) return da - db
    return String(a.name ?? '').localeCompare(String(b.name ?? ''))
  })
}

export function PublicExposureCard({
  vendor,
  sourceEvidence,
  audit,
  liveDeviceAccess = false,
  exposureWarnings = [],
  onInspectValidation,
}: {
  vendor: string
  sourceEvidence?: SourceEvidence | null
  audit?: SecurityAuditResponse | null
  liveDeviceAccess?: boolean
  exposureWarnings?: Record<string, unknown>[]
  onInspectValidation?: () => void
}) {
  const [probeState, setProbeState] = useState<{
    vendor: string
    sourceEvidence: SourceEvidence
    result: ExposureProbeResponse | null
    error: string | null
  } | null>(null)
  const [probeLoading, setProbeLoading] = useState(false)

  const matchingProbeState =
    probeState && sourceEvidence && probeState.vendor === vendor && probeState.sourceEvidence === sourceEvidence
      ? probeState
      : null
  const probeResult = matchingProbeState?.result ?? null
  const probeError = matchingProbeState?.error ?? null

  async function handleProbe() {
    if (!sourceEvidence) return
    setProbeLoading(true)
    setProbeState({ vendor, sourceEvidence, result: null, error: null })
    try {
      const res = await probePublicExposure(vendor, sourceEvidence)
      setProbeState({ vendor, sourceEvidence, result: res, error: null })
    } catch (err) {
      setProbeState({
        vendor,
        sourceEvidence,
        result: null,
        error: err instanceof Error ? err.message : 'Reachability probe failed',
      })
    } finally {
      setProbeLoading(false)
    }
  }

  if (!audit) {
    if (!exposureWarnings.length) return null
    const names = exposureWarnings.map((row) => String(row.object_name ?? '')).filter(Boolean).join(', ')
    return (
      <section id="overview-public-exposure" className="audit-section fw-overview-exposure" aria-label="Public management exposure">
        <div className="report-exposure-warning" role="status">
          <div>
            <strong>Public management exposure ({exposureWarnings.length})</strong>
            <p>{names} — HTTP/HTTPS/SSH/Telnet management access is enabled on a WAN or public-facing interface.</p>
          </div>
          {onInspectValidation && (
            <button type="button" className="secondary-button" onClick={onInspectValidation}>
              Inspect Config Warnings →
            </button>
          )}
        </div>
      </section>
    )
  }

  const hasProbeTargets = audit.exposure.some((item) => (item.targets?.length ?? 0) > 0)

  return (
    <section id="overview-public-exposure" className="audit-section fw-overview-exposure" aria-label="Public management and VIP exposure">
      <div className="audit-section-header">
        <h3 className="report-overview-heading fw-section-header">
          <span className="dot" aria-hidden="true" />
          Public Management &amp; High-Risk VIP Exposure ({audit.exposure.length})
        </h3>
        {hasProbeTargets && liveDeviceAccess && sourceEvidence && (
          <button
            type="button"
            className="secondary-button button-compact"
            disabled={probeLoading}
            onClick={() => void handleProbe()}
          >
            {probeLoading ? 'Probing Targets…' : 'Verify Live Reachability (Local)'}
          </button>
        )}
        {hasProbeTargets && !liveDeviceAccess && (
          <span className="audit-card-sub">Live TCP/TLS/SSH reachability probe is available in local/desktop mode only.</span>
        )}
      </div>
      {probeError && <ErrorBanner message={probeError} />}
      {!audit.exposure.length ? (
        <p className="audit-ok">No active interfaces with public IPs exposing HTTP/HTTPS/SSH or high-risk public VIPs detected.</p>
      ) : (
        <div className="audit-table-wrap">
          <table className="audit-table">
            <thead>
              <tr><th>Severity</th><th>Interface / VIP</th><th>IP</th><th>Exposed Services</th><th>Restrictions &amp; Notes</th></tr>
            </thead>
            <tbody>
              {audit.exposure.map((item, idx) => (
                <tr key={`${item.interface}-${item.ip}-${idx}`}>
                  <td className="fw-cell-nowrap">
                    <span className={`fw-badge fw-badge-${item.severity === 'critical' ? 'deny' : 'warn'}`}>
                      {item.severity === 'critical' ? 'Critical' : 'Warning'}
                    </span>
                  </td>
                  <td className="fw-cell-mono">{item.interface}</td>
                  <td className="fw-cell-mono fw-cell-nowrap">{item.ip}</td>
                  <td className="fw-cell-nowrap">{(item.display_protocols ?? item.protocols).join(', ')}</td>
                  <td className="audit-cell-details">{item.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {probeResult && (
        <div className="audit-probe-results">
          <p className="preview-status" role="status">
            Live probe completed: {probeResult.open_count} of {probeResult.total} tested port(s) accepted TCP connections from this host.
          </p>
          {probeResult.results.length > 0 && (
            <div className="audit-table-wrap">
              <table className="audit-table">
                <thead>
                  <tr><th>Interface</th><th>Public IP</th><th>Protocol / Port</th><th>Config Severity</th><th>Live Reachability</th></tr>
                </thead>
                <tbody>
                  {probeResult.results.map((row, idx) => (
                    <tr key={`${row.interface}-${row.ip}-${row.port}-${idx}`}>
                      <td className="fw-cell-mono">{row.interface}</td>
                      <td className="fw-cell-mono fw-cell-nowrap">{row.ip}</td>
                      <td className="fw-cell-nowrap">{row.protocol} ({row.port})</td>
                      <td>{row.config_severity}</td>
                      <td>
                        <span className={`fw-badge fw-badge-${row.status === 'open' ? 'deny' : row.status === 'refused' ? 'muted' : 'warn'}`}>
                          {row.detail}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

export function SecurityAuditPanel({
  vendor,
  sourceEvidence,
  initialAudit = null,
  managedExternally = false,
  externalLoading = false,
  externalError = null,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
  liveDeviceAccess?: boolean
  initialAudit?: SecurityAuditResponse | null
  managedExternally?: boolean
  externalLoading?: boolean
  externalError?: string | null
}) {
  const [auditState, setAuditState] = useState<{
    vendor: string
    sourceEvidence: SourceEvidence
    data: SecurityAuditResponse | null
    error: string | null
  } | null>(null)
  const [severityFilter, setSeverityFilter] = useState<'all' | 'High' | 'Medium' | 'Info'>('all')
  const [certView, setCertView] = useState<'flagged' | 'all' | null>(null)
  const [certFilter, setCertFilter] = useState('')
  const [hygieneOpen, setHygieneOpen] = useState(false)
  const [hygieneTab, setHygieneTab] = useState<'issues' | 'unused' | 'cli' | null>(null)
  const [hygieneSearch, setHygieneSearch] = useState('')
  const [unusedCategory, setUnusedCategory] = useState('all')
  const [unusedSearch, setUnusedSearch] = useState('')
  const [copiedCli, setCopiedCli] = useState(false)

  const matchingAuditState =
    auditState && auditState.vendor === vendor && auditState.sourceEvidence === sourceEvidence
      ? auditState
      : null
  const audit = initialAudit ?? (managedExternally ? null : matchingAuditState?.data ?? null)
  const loading = managedExternally ? externalLoading : (!initialAudit && !matchingAuditState)
  const error = managedExternally ? externalError : (!initialAudit ? matchingAuditState?.error ?? null : null)

  useEffect(() => {
    if (initialAudit || managedExternally) return
    let active = true
    fetchSecurityAudit(vendor, sourceEvidence)
      .then((res) => {
        if (active) setAuditState({ vendor, sourceEvidence, data: res, error: null })
      })
      .catch((err: unknown) => {
        if (active) {
          setAuditState({
            vendor,
            sourceEvidence,
            data: null,
            error: err instanceof Error ? err.message : 'Security audit failed',
          })
        }
      })
    return () => { active = false }
  }, [vendor, sourceEvidence, initialAudit, managedExternally])

  const sortedCerts = useMemo(
    () => sortCertificates(audit?.certificates ?? []),
    [audit?.certificates],
  )

  const flaggedCerts = useMemo(
    () => sortedCerts.filter((cert) => cert.status === 'Expired' || cert.status === 'Expiring Soon'),
    [sortedCerts],
  )

  const effectiveCertView: 'flagged' | 'all' = certView ?? (flaggedCerts.length > 0 ? 'flagged' : 'all')

  const visibleCerts = useMemo(() => {
    const base = effectiveCertView === 'flagged' ? flaggedCerts : sortedCerts
    const q = certFilter.trim().toLowerCase()
    if (!q) return base
    return base.filter((row) =>
      [row.name, row.store, row.vdom, row.common_name, row.san, row.issuer, row.status]
        .some((val) => String(val ?? '').toLowerCase().includes(q)),
    )
  }, [effectiveCertView, flaggedCerts, sortedCerts, certFilter])

  const filteredFindings = useMemo(() => {
    const rows = audit?.quick_audit.findings ?? []
    if (severityFilter === 'all') return rows
    return rows.filter((row) => row.severity === severityFilter)
  }, [audit?.quick_audit.findings, severityFilter])

  const unusedCategories = useMemo(() => {
    const counts = new Map<string, number>()
    for (const obj of audit?.hygiene.unused_objects ?? []) {
      const cat = String(obj.category || 'Other')
      counts.set(cat, (counts.get(cat) ?? 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [audit?.hygiene.unused_objects])

  const filteredHygieneIssues = useMemo(() => {
    const rows = audit?.hygiene.hygiene_issues ?? []
    const q = hygieneSearch.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((issue) =>
      [issue.severity, issue.finding, issue.target, issue.details]
        .some((val) => String(val ?? '').toLowerCase().includes(q)),
    )
  }, [audit?.hygiene.hygiene_issues, hygieneSearch])

  const filteredUnusedObjects = useMemo(() => {
    const rows = audit?.hygiene.unused_objects ?? []
    const q = unusedSearch.trim().toLowerCase()
    return rows.filter((obj) => {
      const cat = String(obj.category || 'Other')
      if (unusedCategory !== 'all' && cat !== unusedCategory) return false
      if (!q) return true
      return [obj.category, obj.name, obj.scope, obj.value]
        .some((val) => String(val ?? '').toLowerCase().includes(q))
    })
  }, [audit?.hygiene.unused_objects, unusedCategory, unusedSearch])

  async function handleCopyCli() {
    const cli = audit?.hygiene.cleanup_cli
    if (!cli || typeof navigator === 'undefined' || !navigator.clipboard) return
    try {
      await navigator.clipboard.writeText(cli)
      setCopiedCli(true)
      window.setTimeout(() => setCopiedCli(false), 2000)
    } catch {
      /* Clipboard write is best-effort. */
    }
  }

  function jumpToSection(id: string, openHygiene = false) {
    if (openHygiene) setHygieneOpen(true)
    if (typeof document !== 'undefined') {
      document.getElementById(id)?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
    }
  }

  if (loading) {
    return (
      <div className="security-audit-panel">
        <LoadingState label="Running security, certificate, and hygiene audit…" />
      </div>
    )
  }
  if (error && !audit) {
    return (
      <div className="security-audit-panel">
        <ErrorBanner message={error} />
      </div>
    )
  }
  if (!audit) return null

  const { high_count, med_count, info_count, findings } = audit.quick_audit
  const actionableFindings = high_count + med_count
  const auditTone = high_count > 0 ? 'deny' : med_count > 0 ? 'warn' : 'allow'

  const { expired, expiring_soon, total } = audit.certificate_summary
  const flaggedCount = expired + expiring_soon
  const certTone = expired > 0 ? 'deny' : expiring_soon > 0 ? 'warn' : 'allow'

  const { unused, disabled, broad, extra } = audit.hygiene.counts
  const hygieneTone = unused > 0 || broad > 0 ? 'warn' : 'allow'

  const hygieneIssuesCount = audit.hygiene.hygiene_issues.length
  const unusedObjectsCount = audit.hygiene.unused_objects.length
  const hasCleanupCli = Boolean(audit.hygiene.cleanup_cli)
  const availableHygieneTabs: Array<{ id: 'issues' | 'unused' | 'cli'; label: string }> = [
    ...(hygieneIssuesCount > 0 ? [{ id: 'issues' as const, label: `Hygiene Issues (${hygieneIssuesCount})` }] : []),
    ...(unusedObjectsCount > 0 ? [{ id: 'unused' as const, label: `Unused Objects (${unusedObjectsCount})` }] : []),
    ...(hasCleanupCli ? [{ id: 'cli' as const, label: 'Cleanup CLI' }] : []),
  ]
  const effectiveHygieneTab =
    hygieneTab && availableHygieneTabs.some((t) => t.id === hygieneTab)
      ? hygieneTab
      : (availableHygieneTabs[0]?.id ?? null)
  const cliLineCount = hasCleanupCli ? audit.hygiene.cleanup_cli.split(/\r?\n/).length : 0

  return (
    <div className="security-audit-panel">
      <div className="audit-summary-strip" role="navigation" aria-label="Security audit summary">
        <button
          type="button"
          className={`audit-summary-tile audit-summary-${auditTone}`}
          onClick={() => jumpToSection('audit-quick-findings')}
        >
          <span className="audit-summary-label">Security Audit</span>
          <strong className="audit-summary-value">
            {actionableFindings > 0 ? `${actionableFindings} Actionable` : 'Clean'}
          </strong>
          <span className="audit-summary-sub">{high_count} High · {med_count} Med · {info_count} Info</span>
        </button>

        <button
          type="button"
          className={`audit-summary-tile audit-summary-${certTone}`}
          onClick={() => jumpToSection('audit-certificates')}
        >
          <span className="audit-summary-label">Certificates</span>
          <strong className="audit-summary-value">
            {flaggedCount > 0 ? `${flaggedCount} Flagged` : `${total} Valid`}
          </strong>
          <span className="audit-summary-sub">{expired} Expired · {expiring_soon} Expiring · {total} Total</span>
        </button>

        <button
          type="button"
          className={`audit-summary-tile audit-summary-${hygieneTone}`}
          onClick={() => jumpToSection('audit-rule-hygiene', true)}
        >
          <span className="audit-summary-label">Rule Hygiene</span>
          <strong className="audit-summary-value">
            {unused > 0 ? `${unused} Unused` : 'Clean'}
          </strong>
          <span className="audit-summary-sub">{disabled} Disabled · {broad} Broad · {extra} Extra</span>
        </button>
      </div>

      {error && <ErrorBanner message={error} />}

      <section id="audit-quick-findings" className="audit-section" aria-label="Quick security and hygiene audit">
        <div className="audit-section-header">
          <h3 className="report-overview-heading fw-section-header">
            <span className="dot" aria-hidden="true" />
            Quick Security &amp; Hygiene Audit ({findings.length})
          </h3>
          <div className="audit-inline-actions">
            {findings.length > 0 && (
              <div className="audit-filter-pills" role="group" aria-label="Filter findings by severity">
                {(
                  [
                    ['all', `All (${findings.length})`],
                    ['High', `High (${high_count})`],
                    ['Medium', `Medium (${med_count})`],
                    ['Info', `Info (${info_count})`],
                  ] as const
                ).map(([key, label]) => (
                  <button
                    key={key}
                    type="button"
                    aria-pressed={severityFilter === key}
                    className={`audit-filter-pill${severityFilter === key ? ' active' : ''}`}
                    onClick={() => setSeverityFilter(key)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
            {filteredFindings.length > 0 && (
              <button
                type="button"
                className="secondary-button button-compact"
                onClick={() => downloadCsvRows(
                  ['severity', 'category', 'count', 'details'],
                  filteredFindings as Record<string, unknown>[],
                  `${vendor}_quick_security_audit.csv`,
                )}
              >
                ⬇ CSV
              </button>
            )}
          </div>
        </div>
        {!findings.length ? (
          <p className="audit-ok">No risky ANY-ANY rules, unprotected allow rules, weak VPN crypto, or unused objects detected.</p>
        ) : !filteredFindings.length ? (
          <p className="audit-card-sub">No findings match the selected severity filter.</p>
        ) : (
          <div className="audit-table-wrap">
            <table className="audit-table">
              <thead>
                <tr><th>Severity</th><th>Category</th><th className="fw-cell-num">Count</th><th>Details</th></tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding, idx) => (
                  <tr key={`${finding.category}-${idx}`}>
                    <td className="fw-cell-nowrap">
                      <span className={`fw-badge fw-badge-${auditSeverityBadge(finding.severity)}`}>{finding.severity}</span>
                    </td>
                    <td className="audit-cell-primary">{finding.category}</td>
                    <td className="fw-cell-num">{finding.count}</td>
                    <td className="audit-cell-details">{finding.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section id="audit-certificates" className="audit-section" aria-label="Certificates">
        <div className="audit-section-header">
          <h3 className="report-overview-heading fw-section-header">
            <span className="dot" aria-hidden="true" />
            Certificates ({audit.certificates.length})
          </h3>
          <span className={`fw-badge fw-badge-${certTone}`}>
            {flaggedCount > 0
              ? `${expired > 0 ? `${expired} Expired` : ''}${expired > 0 && expiring_soon > 0 ? ' · ' : ''}${expiring_soon > 0 ? `${expiring_soon} Expiring` : ''}`
              : 'All Valid'}
          </span>
        </div>

        {audit.certificates.length > 0 && (
          <div className="audit-toolbar-row">
            <div className="audit-filter-pills" role="group" aria-label="Certificate view">
              <button
                type="button"
                aria-pressed={effectiveCertView === 'flagged'}
                className={`audit-filter-pill${effectiveCertView === 'flagged' ? ' active' : ''}`}
                onClick={() => setCertView('flagged')}
              >
                Flagged ({flaggedCerts.length})
              </button>
              <button
                type="button"
                aria-pressed={effectiveCertView === 'all'}
                className={`audit-filter-pill${effectiveCertView === 'all' ? ' active' : ''}`}
                onClick={() => setCertView('all')}
              >
                All ({audit.certificates.length})
              </button>
            </div>
            <div className="audit-inline-actions">
              <input
                type="search"
                className="audit-search-input"
                aria-label="Filter certificates"
                value={certFilter}
                onChange={(event) => setCertFilter(event.target.value)}
                placeholder="Filter certs by name, CN, SAN, or issuer…"
              />
              {visibleCerts.length > 0 && (
                <button
                  type="button"
                  className="secondary-button button-compact"
                  onClick={() => downloadCsvRows(
                    ['name', 'store', 'common_name', 'san', 'issuer', 'not_before', 'expires', 'days_left', 'status'],
                    visibleCerts as Record<string, unknown>[],
                    `${vendor}_certificates.csv`,
                  )}
                >
                  ⬇ CSV
                </button>
              )}
            </div>
          </div>
        )}

        {effectiveCertView === 'flagged' && flaggedCerts.length > 0 && (
          <p className="audit-card-sub">
            Certificates that are expired or expiring within 30 days (may impact VPN, HTTPS mgmt, or SSL inspection).
          </p>
        )}

        {!audit.certificates.length ? (
          <p className="audit-card-sub">No certificates found in this configuration.</p>
        ) : !visibleCerts.length ? (
          <p className="audit-ok">
            {certFilter.trim()
              ? 'No certificates match the current search filter.'
              : 'No expired or expiring certificates detected.'}
          </p>
        ) : (
          <>
            <div className="audit-table-wrap">
              <table className="audit-table">
                <thead>
                  <tr><th>Status</th><th>Name</th><th>Store / Scope</th><th>Common Name</th><th>SAN / FQDN</th><th>Issuer</th><th>Expires</th><th className="fw-cell-num">Days Left</th></tr>
                </thead>
                <tbody>
                  {visibleCerts.map((cert, idx) => (
                    <tr key={`${cert.store}-${cert.name}-${idx}`}>
                      <td className="fw-cell-nowrap">
                        <span className={`fw-badge fw-badge-${certStatusBadge(cert.status)}`}>{cert.status}</span>
                      </td>
                      <td className="fw-cell-mono">{cert.name}</td>
                      <td>{cert.store}</td>
                      <td className="fw-cell-mono">{cert.common_name}</td>
                      <td className="fw-cell-mono">{cert.san}</td>
                      <td>{cert.issuer}</td>
                      <td className="fw-cell-mono fw-cell-nowrap">{cert.expires}</td>
                      <td className="fw-cell-num">{cert.days_left}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="audit-table-footer">
              <span>Showing {visibleCerts.length} of {audit.certificates.length} certificates</span>
            </div>
          </>
        )}
      </section>

      <details
        id="audit-rule-hygiene"
        className="audit-section audit-collapsible"
        open={hygieneOpen}
        onToggle={(event) => setHygieneOpen(event.currentTarget.open)}
      >
        <summary className="audit-collapsible-summary">
          <span className="report-overview-heading fw-section-header">
            <span className="dot" aria-hidden="true" />
            Rule Hygiene &amp; Unused Objects
          </span>
          <span className="audit-inline-actions">
            <span className={`fw-badge fw-badge-${unused > 0 ? 'warn' : 'muted'}`}>{unused} Unused</span>
            <span className={`fw-badge fw-badge-${disabled > 0 ? 'info' : 'muted'}`}>{disabled} Disabled</span>
            <span className={`fw-badge fw-badge-${broad > 0 ? 'warn' : 'muted'}`}>{broad} Broad</span>
          </span>
        </summary>
        <div className="audit-collapsible-body">
          <div className="audit-kpi-grid fw-quick-kpi">
            <div className="audit-card"><div className="audit-card-label">Unused Objects</div><div className="audit-card-value">{unused}</div></div>
            <div className="audit-card"><div className="audit-card-label">Disabled Rules</div><div className="audit-card-value">{disabled}</div></div>
            <div className="audit-card"><div className="audit-card-label">Broad Any/All Rules</div><div className="audit-card-value">{broad}</div></div>
            <div className="audit-card"><div className="audit-card-label">Expired Schedules / Unlogged</div><div className="audit-card-value">{extra}</div></div>
          </div>

          {!availableHygieneTabs.length ? (
            <p className="audit-ok">No rule hygiene issues or unused objects detected.</p>
          ) : (
            <>
              <div className="audit-subtabs" role="tablist" aria-label="Rule hygiene views">
                {availableHygieneTabs.map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={effectiveHygieneTab === tab.id}
                    className={`audit-subtab${effectiveHygieneTab === tab.id ? ' active' : ''}`}
                    onClick={() => setHygieneTab(tab.id)}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {effectiveHygieneTab === 'issues' && (
                <div className="audit-subtab-panel" role="tabpanel" aria-label="Hygiene Issues">
                  <div className="audit-toolbar-row">
                    <input
                      type="search"
                      className="audit-search-input"
                      aria-label="Filter hygiene issues"
                      value={hygieneSearch}
                      onChange={(event) => setHygieneSearch(event.target.value)}
                      placeholder="Filter hygiene issues…"
                    />
                    <span className="audit-card-sub">
                      Showing {filteredHygieneIssues.length} of {hygieneIssuesCount} issues
                    </span>
                  </div>
                  {!filteredHygieneIssues.length ? (
                    <p className="audit-card-sub">No hygiene issues match the current filter.</p>
                  ) : (
                    <div className="audit-table-wrap">
                      <table className="audit-table">
                        <thead>
                          <tr><th>Severity</th><th>Finding</th><th>Target</th><th>Details</th></tr>
                        </thead>
                        <tbody>
                          {filteredHygieneIssues.map((issue, idx) => (
                            <tr key={`${issue.finding}-${issue.target}-${idx}`}>
                              <td className="fw-cell-nowrap"><span className={`fw-badge fw-badge-${issue.tone === 'danger' ? 'deny' : 'warn'}`}>{issue.severity}</span></td>
                              <td className="audit-cell-primary">{issue.finding}</td>
                              <td className="fw-cell-mono">{issue.target}</td>
                              <td className="audit-cell-details">{issue.details}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {effectiveHygieneTab === 'unused' && (
                <div className="audit-subtab-panel" role="tabpanel" aria-label="Unused Objects">
                  <div className="audit-toolbar-row">
                    {unusedCategories.length > 1 && (
                      <div className="audit-filter-pills" role="group" aria-label="Filter unused objects by category">
                        <button
                          type="button"
                          aria-pressed={unusedCategory === 'all'}
                          className={`audit-filter-pill${unusedCategory === 'all' ? ' active' : ''}`}
                          onClick={() => setUnusedCategory('all')}
                        >
                          All ({unusedObjectsCount})
                        </button>
                        {unusedCategories.map(([cat, count]) => (
                          <button
                            key={cat}
                            type="button"
                            aria-pressed={unusedCategory === cat}
                            className={`audit-filter-pill${unusedCategory === cat ? ' active' : ''}`}
                            onClick={() => setUnusedCategory(cat)}
                          >
                            {cat} ({count})
                          </button>
                        ))}
                      </div>
                    )}
                    <div className="audit-inline-actions">
                      <input
                        type="search"
                        className="audit-search-input"
                        aria-label="Filter unused objects"
                        value={unusedSearch}
                        onChange={(event) => setUnusedSearch(event.target.value)}
                        placeholder="Filter unused objects by name, scope, or value…"
                      />
                      {filteredUnusedObjects.length > 0 && (
                        <button
                          type="button"
                          className="secondary-button button-compact"
                          onClick={() => downloadCsvRows(
                            ['category', 'name', 'scope', 'value'],
                            filteredUnusedObjects as Record<string, unknown>[],
                            `${vendor}_unused_objects.csv`,
                          )}
                        >
                          ⬇ Unused Objects CSV
                        </button>
                      )}
                    </div>
                  </div>
                  {!filteredUnusedObjects.length ? (
                    <p className="audit-card-sub">No unused objects match the current filter.</p>
                  ) : (
                    <>
                      <div className="audit-table-wrap">
                        <table className="audit-table">
                          <thead>
                            <tr><th>Category</th><th>Name</th><th>Scope</th><th>Value</th></tr>
                          </thead>
                          <tbody>
                            {filteredUnusedObjects.map((obj, idx) => (
                              <tr key={`${obj.category}-${obj.scope}-${obj.name}-${idx}`}>
                                <td>{obj.category}</td>
                                <td className="fw-cell-mono">{obj.name}</td>
                                <td>{obj.scope}</td>
                                <td className="fw-cell-mono audit-cell-details">{obj.value}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <div className="audit-table-footer">
                        <span>Showing {filteredUnusedObjects.length} of {unusedObjectsCount} unused objects</span>
                      </div>
                    </>
                  )}
                </div>
              )}

              {effectiveHygieneTab === 'cli' && (
                <div className="audit-subtab-panel" role="tabpanel" aria-label="Cleanup CLI">
                  <div className="audit-cli-wrap">
                    <div className="audit-cli-header">
                      <span className="audit-card-sub">
                        Draft FortiOS Cleanup CLI — review before applying ({cliLineCount} lines)
                      </span>
                      <button type="button" className="secondary-button button-compact" onClick={() => void handleCopyCli()}>
                        {copiedCli ? 'Copied' : 'Copy CLI'}
                      </button>
                    </div>
                    <pre className="audit-cli-pre">{audit.hygiene.cleanup_cli}</pre>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </details>
    </div>
  )
}
