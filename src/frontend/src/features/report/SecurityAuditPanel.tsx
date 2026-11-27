import { useEffect, useMemo, useState } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { ExposureProbeResponse, LifecycleCardData, SecurityAuditResponse } from '../source/types'
import {
  downloadSecurityAuditReport,
  fetchSecurityAudit,
  probePublicExposure,
} from '../source/sourceApi'
import { saveBlobWithFallback } from '../../utils/desktop'
import { downloadCsvRows } from './reportPresentation'
import { LifecycleCard } from './LifecycleCard'
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

export function SecurityAuditPanel({
  vendor,
  sourceEvidence,
  liveDeviceAccess = false,
  initialAudit = null,
  managedExternally = false,
  externalLoading = false,
  externalError = null,
  lifecycle = null,
  onLifecycleResolved,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
  liveDeviceAccess?: boolean
  initialAudit?: SecurityAuditResponse | null
  managedExternally?: boolean
  externalLoading?: boolean
  externalError?: string | null
  lifecycle?: LifecycleCardData | null
  onLifecycleResolved?: (card: LifecycleCardData) => void
}) {
  const [auditState, setAuditState] = useState<{
    vendor: string
    sourceEvidence: SourceEvidence
    data: SecurityAuditResponse | null
    error: string | null
  } | null>(null)
  const [probeState, setProbeState] = useState<{
    vendor: string
    sourceEvidence: SourceEvidence
    result: ExposureProbeResponse | null
    error: string | null
  } | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const [probeLoading, setProbeLoading] = useState(false)
  const [reportExporting, setReportExporting] = useState(false)
  const [reportStatus, setReportStatus] = useState('')
  const [certFilter, setCertFilter] = useState('')
  const [copiedCli, setCopiedCli] = useState(false)

  const matchingAuditState =
    auditState && auditState.vendor === vendor && auditState.sourceEvidence === sourceEvidence
      ? auditState
      : null
  const audit = initialAudit ?? (managedExternally ? null : matchingAuditState?.data ?? null)
  const loading = managedExternally ? externalLoading : (!initialAudit && !matchingAuditState)
  const error = exportError ?? (managedExternally ? externalError : (!initialAudit ? matchingAuditState?.error ?? null : null))
  const matchingProbeState =
    probeState && probeState.vendor === vendor && probeState.sourceEvidence === sourceEvidence
      ? probeState
      : null
  const probeResult = matchingProbeState?.result ?? null
  const probeError = matchingProbeState?.error ?? null

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

  const filteredCerts = useMemo(() => {
    const rows = audit?.certificates ?? []
    const q = certFilter.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((row) =>
      [row.name, row.store, row.vdom, row.common_name, row.san, row.issuer, row.status]
        .some((val) => String(val ?? '').toLowerCase().includes(q)),
    )
  }, [audit?.certificates, certFilter])

  async function handleProbe() {
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

  async function handleDownloadHtml() {
    setReportExporting(true)
    setReportStatus('')
    setExportError(null)
    try {
      const blob = await downloadSecurityAuditReport(vendor, sourceEvidence)
      const result = await saveBlobWithFallback(blob, `${vendor}_security_audit_report.html`)
      if (result.status === 'cancelled') setReportStatus('Audit report export cancelled.')
      else if (result.status === 'saved') setReportStatus(`Audit report saved: ${result.path || result.filename}.`)
      else setReportStatus(`Audit report downloaded: ${result.filename} (open in browser and Print → Save as PDF).`)
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Audit report export failed')
    } finally {
      setReportExporting(false)
    }
  }

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

  if (loading) {
    return (
      <div className="security-audit-panel">
        {lifecycle && <LifecycleCard lifecycle={lifecycle} onLifecycleResolved={onLifecycleResolved} />}
        <LoadingState label="Running security, exposure, certificate, and hygiene audit…" />
      </div>
    )
  }
  if (error && !audit) {
    return (
      <div className="security-audit-panel">
        {lifecycle && <LifecycleCard lifecycle={lifecycle} onLifecycleResolved={onLifecycleResolved} />}
        <ErrorBanner message={error} />
      </div>
    )
  }
  if (!audit) return lifecycle ? <LifecycleCard lifecycle={lifecycle} onLifecycleResolved={onLifecycleResolved} /> : null

  const hasProbeTargets = audit.exposure.some((item) => (item.targets?.length ?? 0) > 0)
  const expCrit = audit.exposure.filter((item) => item.severity === 'critical').length
  const flaggedCerts = audit.certificates.filter(
    (cert) => cert.status === 'Expired' || cert.status === 'Expiring Soon',
  )

  return (
    <div className="security-audit-panel">
      <div className="audit-toolbar">
        <div className="audit-toolbar-badges">
          <span className={`fw-badge fw-badge-${audit.quick_audit.high_count > 0 ? 'deny' : audit.quick_audit.med_count > 0 ? 'warn' : 'allow'}`}>
            Audit: {audit.quick_audit.high_count} High · {audit.quick_audit.med_count} Med · {audit.quick_audit.info_count} Info
          </span>
          <span className={`fw-badge fw-badge-${expCrit > 0 ? 'deny' : audit.exposure.length > 0 ? 'warn' : 'allow'}`}>
            {audit.exposure.length > 0 ? `Exposure: ${audit.exposure.length} (${expCrit} Crit)` : 'Exposure: Clean'}
          </span>
          <span className={`fw-badge fw-badge-${audit.certificate_summary.expired > 0 ? 'deny' : audit.certificate_summary.expiring_soon > 0 ? 'warn' : 'info'}`}>
            Certs: {audit.certificate_summary.expired + audit.certificate_summary.expiring_soon} Flagged / {audit.certificate_summary.total}
          </span>
          <span className={`fw-badge fw-badge-${audit.hygiene.counts.unused > 0 || audit.hygiene.counts.broad > 0 ? 'warn' : 'allow'}`}>
            Hygiene: {audit.hygiene.counts.unused} Unused · {audit.hygiene.counts.broad} Broad
          </span>
        </div>
        <button
          type="button"
          className="primary-button button-compact"
          disabled={reportExporting}
          onClick={() => void handleDownloadHtml()}
        >
          {reportExporting ? 'Generating Report…' : '⬇ Download Audit Report (HTML / PDF)'}
        </button>
      </div>

      {error && <ErrorBanner message={error} />}
      {reportStatus && <p className="preview-status" role="status">{reportStatus}</p>}

      {lifecycle && <LifecycleCard lifecycle={lifecycle} onLifecycleResolved={onLifecycleResolved} />}

      <section className="audit-section" aria-label="Public management and VIP exposure">
        <div className="audit-section-header">
          <h3 className="report-overview-heading fw-section-header"><span className="dot" aria-hidden="true" />Public Management &amp; High-Risk VIP Exposure ({audit.exposure.length})</h3>
          {hasProbeTargets && liveDeviceAccess && (
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
          <div className="where-used-table-wrap">
            <table className="where-used-table">
              <thead>
                <tr><th>Severity</th><th>Interface / VIP</th><th>IP</th><th>Exposed Services</th><th>Restrictions &amp; Notes</th></tr>
              </thead>
              <tbody>
                {audit.exposure.map((item, idx) => (
                  <tr key={`${item.interface}-${item.ip}-${idx}`}>
                    <td><span className={`fw-badge fw-badge-${item.severity === 'critical' ? 'deny' : 'warn'}`}>{item.severity === 'critical' ? 'Critical' : 'Warning'}</span></td>
                    <td className="fw-cell-mono">{item.interface}</td>
                    <td className="fw-cell-mono">{item.ip}</td>
                    <td>{(item.display_protocols ?? item.protocols).join(', ')}</td>
                    <td>{item.note}</td>
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
              <div className="where-used-table-wrap">
                <table className="where-used-table">
                  <thead>
                    <tr><th>Interface</th><th>Public IP</th><th>Protocol / Port</th><th>Config Severity</th><th>Live Reachability</th></tr>
                  </thead>
                  <tbody>
                    {probeResult.results.map((row, idx) => (
                      <tr key={`${row.interface}-${row.ip}-${row.port}-${idx}`}>
                        <td className="fw-cell-mono">{row.interface}</td>
                        <td className="fw-cell-mono">{row.ip}</td>
                        <td>{row.protocol} ({row.port})</td>
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

      {flaggedCerts.length > 0 && (
        <section className="audit-section fw-cert-alerts-card" aria-label="Certificate expiry alerts">
          <div className="audit-section-header">
            <h3 className="report-overview-heading fw-section-header"><span className="dot" aria-hidden="true" />Certificate Expiry Alerts</h3>
            <span className={`fw-badge fw-badge-${audit.certificate_summary.expired > 0 ? 'deny' : 'warn'}`}>
              {audit.certificate_summary.expired > 0
                ? `${audit.certificate_summary.expired} Expired${audit.certificate_summary.expiring_soon > 0 ? ` · ${audit.certificate_summary.expiring_soon} Expiring` : ''}`
                : `${audit.certificate_summary.expiring_soon} Expiring < 30d`}
            </span>
          </div>
          <p className="audit-card-sub">
            Certificates that are expired or expiring within 30 days (may impact VPN, HTTPS mgmt, or SSL inspection).
          </p>
          <div className="fw-kv-list">
            {flaggedCerts.map((cert, idx) => (
              <div key={`${cert.store}-${cert.name}-${idx}`} className="fw-kv-row">
                <span className="fw-kv-row-label fw-cell-mono">
                  {cert.name} ({cert.store}) · CN: {cert.common_name}
                </span>
                <span className={`fw-badge fw-badge-${certStatusBadge(cert.status)}`}>
                  {cert.status} ({cert.expires}, {cert.days_left}d)
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      <details className="fw-expander" open={audit.quick_audit.high_count > 0}>
        <summary>
          🩺 Quick Security &amp; Hygiene Audit ({audit.quick_audit.high_count} High · {audit.quick_audit.med_count} Med · {audit.quick_audit.info_count} Info)
        </summary>
        <div className="fw-expander-body">
          <div className="audit-section-header">
            <div className="audit-kpi-grid fw-quick-kpi">
              <div className="audit-card"><div className="audit-card-label">High Risk</div><div className="audit-card-value">{audit.quick_audit.high_count}</div></div>
              <div className="audit-card"><div className="audit-card-label">Medium Risk</div><div className="audit-card-value">{audit.quick_audit.med_count}</div></div>
              <div className="audit-card"><div className="audit-card-label">Hygiene / Info</div><div className="audit-card-value">{audit.quick_audit.info_count}</div></div>
            </div>
            {audit.quick_audit.findings.length > 0 && (
              <button
                type="button"
                className="secondary-button button-compact"
                onClick={() => downloadCsvRows(
                  ['severity', 'category', 'count', 'details'],
                  audit.quick_audit.findings as Record<string, unknown>[],
                  `${vendor}_quick_security_audit.csv`,
                )}
              >
                ⬇ CSV
              </button>
            )}
          </div>
          {!audit.quick_audit.findings.length ? (
            <p className="audit-ok">No risky ANY-ANY rules, unprotected allow rules, weak VPN crypto, or unused objects detected.</p>
          ) : (
            <div className="where-used-table-wrap">
              <table className="where-used-table">
                <thead>
                  <tr><th>Severity</th><th>Category</th><th>Count</th><th>Details</th></tr>
                </thead>
                <tbody>
                  {audit.quick_audit.findings.map((finding, idx) => (
                    <tr key={`${finding.category}-${idx}`}>
                      <td><span className={`fw-badge fw-badge-${auditSeverityBadge(finding.severity)}`}>{finding.severity}</span></td>
                      <td>{finding.category}</td>
                      <td>{finding.count}</td>
                      <td className="fw-cell-mono">{finding.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </details>

      <section className="audit-section" aria-label="Connectivity and storage posture">
        <h3 className="report-overview-heading fw-section-header"><span className="dot" aria-hidden="true" />Connectivity &amp; Storage Posture</h3>
        <div className="audit-posture-grid">
          <div className="audit-card">
            <div className="audit-card-label">Internet Connectivity</div>
            <div className="audit-card-value">{audit.posture.internet}</div>
            <div className="audit-card-sub">{audit.posture.internet_sub}</div>
          </div>
          <div className="audit-card">
            <div className="audit-card-label">Local Disk &amp; Log Storage</div>
            <div className="audit-card-value">{audit.posture.disk}</div>
            <div className="audit-card-sub">{audit.posture.disk_sub}</div>
          </div>
        </div>
      </section>

      <details className="fw-expander" open={flaggedCerts.length > 0}>
        <summary>📜 Certificate Expiry Inspector ({audit.certificates.length})</summary>
        <div className="fw-expander-body">
          <div className="audit-section-header">
            <div className="audit-inline-actions">
              {audit.certificates.length > 0 && (
                <input
                  type="search"
                  aria-label="Filter certificates"
                  value={certFilter}
                  onChange={(event) => setCertFilter(event.target.value)}
                  placeholder="Filter certs by name, CN, or status…"
                />
              )}
              {filteredCerts.length > 0 && (
                <button
                  type="button"
                  className="secondary-button button-compact"
                  onClick={() => downloadCsvRows(
                    ['name', 'store', 'common_name', 'san', 'issuer', 'not_before', 'expires', 'days_left', 'status'],
                    filteredCerts as Record<string, unknown>[],
                    `${vendor}_certificates.csv`,
                  )}
                >
                  ⬇ CSV
                </button>
              )}
            </div>
          </div>
          {!audit.certificates.length ? (
            <p className="audit-card-sub">No certificates found in this configuration.</p>
          ) : (
            <div className="where-used-table-wrap">
              <table className="where-used-table">
                <thead>
                  <tr><th>Status</th><th>Name</th><th>Store / Scope</th><th>Common Name</th><th>SAN / FQDN</th><th>Issuer</th><th>Expires</th><th>Days Left</th></tr>
                </thead>
                <tbody>
                  {filteredCerts.map((cert, idx) => (
                    <tr key={`${cert.store}-${cert.name}-${idx}`}>
                      <td><span className={`fw-badge fw-badge-${certStatusBadge(cert.status)}`}>{cert.status}</span></td>
                      <td className="fw-cell-mono">{cert.name}</td>
                      <td>{cert.store}</td>
                      <td className="fw-cell-mono">{cert.common_name}</td>
                      <td className="fw-cell-mono">{cert.san}</td>
                      <td>{cert.issuer}</td>
                      <td className="fw-cell-mono">{cert.expires}</td>
                      <td>{cert.days_left}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </details>

      <details className="fw-expander">
        <summary>
          🧹 Rule Hygiene &amp; Unused Objects ({audit.hygiene.counts.unused} Unused · {audit.hygiene.counts.disabled} Disabled · {audit.hygiene.counts.broad} Broad)
        </summary>
        <div className="fw-expander-body">
          <div className="audit-section-header">
            <div className="audit-kpi-grid fw-quick-kpi">
              <div className="audit-card"><div className="audit-card-label">Unused Objects</div><div className="audit-card-value">{audit.hygiene.counts.unused}</div></div>
              <div className="audit-card"><div className="audit-card-label">Disabled Rules</div><div className="audit-card-value">{audit.hygiene.counts.disabled}</div></div>
              <div className="audit-card"><div className="audit-card-label">Broad Any/All Rules</div><div className="audit-card-value">{audit.hygiene.counts.broad}</div></div>
              <div className="audit-card"><div className="audit-card-label">Expired Schedules / Unlogged</div><div className="audit-card-value">{audit.hygiene.counts.extra}</div></div>
            </div>
            {audit.hygiene.unused_objects.length > 0 && (
              <button
                type="button"
                className="secondary-button button-compact"
                onClick={() => downloadCsvRows(
                  ['category', 'name', 'scope', 'value'],
                  audit.hygiene.unused_objects as Record<string, unknown>[],
                  `${vendor}_unused_objects.csv`,
                )}
              >
                ⬇ Unused Objects CSV
              </button>
            )}
          </div>

          {audit.hygiene.hygiene_issues.length > 0 && (
            <div className="where-used-table-wrap">
              <table className="where-used-table">
                <thead>
                  <tr><th>Severity</th><th>Finding</th><th>Target</th><th>Details</th></tr>
                </thead>
                <tbody>
                  {audit.hygiene.hygiene_issues.map((issue, idx) => (
                    <tr key={`${issue.finding}-${issue.target}-${idx}`}>
                      <td><span className={`fw-badge fw-badge-${issue.tone === 'danger' ? 'deny' : 'warn'}`}>{issue.severity}</span></td>
                      <td>{issue.finding}</td>
                      <td className="fw-cell-mono">{issue.target}</td>
                      <td>{issue.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {audit.hygiene.unused_objects.length > 0 && (
            <details className="audit-details">
              <summary>Unused / Unreferenced Objects ({audit.hygiene.unused_objects.length})</summary>
              <div className="where-used-table-wrap">
                <table className="where-used-table">
                  <thead>
                    <tr><th>Category</th><th>Name</th><th>Scope</th><th>Value</th></tr>
                  </thead>
                  <tbody>
                    {audit.hygiene.unused_objects.map((obj, idx) => (
                      <tr key={`${obj.category}-${obj.scope}-${obj.name}-${idx}`}>
                        <td>{obj.category}</td>
                        <td className="fw-cell-mono">{obj.name}</td>
                        <td>{obj.scope}</td>
                        <td className="fw-cell-mono">{obj.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}

          {audit.hygiene.cleanup_cli && (
            <details className="audit-details">
              <summary>Draft FortiOS Cleanup CLI (Review Before Applying)</summary>
              <div className="audit-cli-wrap">
                <button type="button" className="secondary-button button-compact" onClick={() => void handleCopyCli()}>
                  {copiedCli ? 'Copied' : 'Copy CLI'}
                </button>
                <pre className="audit-cli-pre">{audit.hygiene.cleanup_cli}</pre>
              </div>
            </details>
          )}
        </div>
      </details>
    </div>
  )
}
