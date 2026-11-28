import { useEffect, useState } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { SslToIpsecPolicyRow, SslToIpsecResponse } from '../source/types'
import { fetchSslToIpsec } from '../source/sourceApi'
import { saveBlobWithFallback } from '../../utils/desktop'
import { downloadCsvRows } from './reportPresentation'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { LoadingState } from '../../components/common/LoadingState'

function policyRowClass(row: SslToIpsecPolicyRow): string {
  if (row.status.trim().toLowerCase() === 'disable') return 'row-danger'
  if (row.action.trim().toUpperCase() === 'ACCEPT') return 'row-success'
  return 'row-danger'
}

export function SslToIpsecPanel({
  vendor,
  sourceEvidence,
  initialData = null,
  onLoaded,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
  initialData?: SslToIpsecResponse | null
  onLoaded?: (vdomKey: string, data: SslToIpsecResponse) => void
}) {
  const [selectedVdom, setSelectedVdom] = useState<string>('')
  const [state, setState] = useState<{
    vendor: string
    sourceEvidence: SourceEvidence
    vdom: string
    data: SslToIpsecResponse | null
    error: string | null
  } | null>(null)
  const [copied, setCopied] = useState(false)
  const [downloadStatus, setDownloadStatus] = useState('')

  const effectiveInitial =
    initialData && (!selectedVdom || initialData.vdom === selectedVdom)
      ? initialData
      : null
  const matchingState =
    state && state.vendor === vendor && state.sourceEvidence === sourceEvidence && state.vdom === selectedVdom
      ? state
      : null
  const data = effectiveInitial ?? matchingState?.data ?? null
  const loading = !effectiveInitial && !matchingState
  const error = !effectiveInitial ? matchingState?.error ?? null : null

  useEffect(() => {
    if (effectiveInitial) return
    let active = true
    fetchSslToIpsec(vendor, sourceEvidence, selectedVdom || undefined)
      .then((res) => {
        if (!active) return
        setState({ vendor, sourceEvidence, vdom: selectedVdom, data: res, error: null })
        onLoaded?.(res.vdom ?? '', res)
      })
      .catch((err: unknown) => {
        if (!active) return
        setState({
          vendor,
          sourceEvidence,
          vdom: selectedVdom,
          data: null,
          error: err instanceof Error ? err.message : 'SSL-to-IPSec analysis failed',
        })
      })
    return () => { active = false }
  }, [vendor, sourceEvidence, selectedVdom, effectiveInitial, onLoaded])

  async function handleCopyCli() {
    const cli = data?.cli_draft ?? ''
    if (!cli) return
    try {
      await navigator.clipboard.writeText(cli)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setDownloadStatus('Clipboard copy unavailable; use Download CLI instead.')
    }
  }

  async function handleDownloadCli() {
    const cli = data?.cli_draft ?? ''
    if (!cli) return
    const vdomSuffix = data?.vdom ? `_${data.vdom}` : ''
    const blob = new Blob([cli], { type: 'text/plain;charset=utf-8' })
    const outcome = await saveBlobWithFallback(blob, `fortigate${vdomSuffix}_ssl_to_ipsec_draft.txt`)
    if (outcome.status === 'cancelled') setDownloadStatus('CLI draft download cancelled.')
    else if (outcome.status === 'saved') setDownloadStatus(`Saved CLI draft: ${outcome.path || outcome.filename}.`)
    else setDownloadStatus(`Downloaded CLI draft: ${outcome.filename}.`)
  }

  function handleExportPoliciesCsv() {
    const rows = data?.ssl_policies ?? []
    downloadCsvRows(
      ['id', 'name', 'status', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'action', 'nat', 'schedule', 'groups', 'users', 'profiles'],
      rows as unknown as Record<string, unknown>[],
      'fg_ssl_policies_to_migrate.csv',
      (col) => ({
        id: 'ID',
        name: 'Name',
        status: 'Status',
        srcintf: 'Src Interface',
        dstintf: 'Dst Interface',
        srcaddr: 'Source',
        dstaddr: 'Destination',
        service: 'Service',
        action: 'Action',
        nat: 'NAT',
        schedule: 'Schedule',
        groups: 'Groups',
        users: 'Users',
        profiles: 'Security Profiles',
      }[col] ?? col),
    )
  }

  function handleExportGuiCsv() {
    const rows = data?.gui_rows ?? []
    downloadCsvRows(
      ['parameter', 'recommended_value', 'notes'],
      rows as unknown as Record<string, unknown>[],
      'fg_ssl_to_ipsec_gui_params.csv',
      (col) => ({
        parameter: 'Parameter',
        recommended_value: 'Recommended Value',
        notes: 'Notes',
      }[col] ?? col),
    )
  }

  if (loading) {
    return (
      <div className="fw-ssl-ipsec-panel">
        <LoadingState label="Auditing SSL-VPN configuration for Dial-up IPSec migration…" />
      </div>
    )
  }

  if (error && !data) {
    return (
      <div className="fw-ssl-ipsec-panel">
        <ErrorBanner message={error} />
      </div>
    )
  }

  if (!data) return null

  if (!data.has_ssl_vpn) {
    return (
      <div className="fw-ssl-ipsec-panel">
        <div className="fw-ssl-ipsec-alert fw-ssl-ipsec-alert-info" role="status">
          No active SSL-VPN configuration detected in this FortiGate backup — no SSL-to-IPSec migration is required.
        </div>
      </div>
    )
  }

  const warnings = data.warnings ?? []
  const infos = data.infos ?? []
  const sslPolicies = data.ssl_policies ?? []
  const guiRows = data.gui_rows ?? []
  const fcRows = data.forticlient_rows ?? []
  const cutoverRows = data.cutover_rows ?? []
  const vdoms = data.vdoms ?? []
  const activeVdom = data.vdom ?? 'root'

  return (
    <div className="fw-ssl-ipsec-panel">
      <section className="fw-card fw-card-flex fw-hero-card" aria-label="SSL-VPN to Dial-up IPSec summary">
        <div className="fw-hero-heading">
          <div className="fw-hero-eyebrow">SSL-VPN → Dial-up IPSec (IKEv2) Assistant</div>
          <div className="fw-hero-title fw-mono">{data.model}</div>
          <div className="fw-hero-sub">
            Firmware {data.firmware} · VDOM {activeVdom} · Offline Draft from Backup Config
          </div>
        </div>
        <div className="fw-hero-badges fw-ssl-ipsec-header-right">
          {vdoms.length > 1 && (
            <label className="fw-ssl-ipsec-vdom-select">
              <span>VDOM</span>
              <select
                aria-label="Select SSL-VPN VDOM"
                value={activeVdom}
                onChange={(event) => setSelectedVdom(event.target.value)}
              >
                {vdoms.map((v) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            </label>
          )}
          <span className={`fw-badge fw-badge-${warnings.length ? 'warn' : 'allow'}`}>
            {warnings.length ? `${warnings.length} Review Item(s)` : 'Ready to Draft'}
          </span>
        </div>
      </section>

      <dl className="fw-sim-kv" aria-label="Detected SSL-VPN parameters">
        <div className="fw-sim-kv-item">
          <dt>Detected Auth Mode</dt>
          <dd>{data.auth_label ?? '-'}</dd>
        </div>
        <div className="fw-sim-kv-item">
          <dt>Server Certificate</dt>
          <dd className="fw-mono">{data.servercert ?? '-'}</dd>
        </div>
        <div className="fw-sim-kv-item">
          <dt>Underlay Interface</dt>
          <dd className="fw-mono">{data.wan_intf ?? '-'}</dd>
        </div>
        <div className="fw-sim-kv-item">
          <dt>Tunnel IP Pool</dt>
          <dd className="fw-mono">{data.primary_pool ?? '-'}</dd>
        </div>
        <div className="fw-sim-kv-item">
          <dt>SSL Portals</dt>
          <dd>{data.portals_count ?? 0}</dd>
        </div>
        <div className="fw-sim-kv-item">
          <dt>ssl.* Policies to Clone</dt>
          <dd>{sslPolicies.length}</dd>
        </div>
      </dl>

      {(warnings.length > 0 || infos.length > 0) && (
        <div className="fw-ssl-ipsec-alerts" aria-label="Migration readiness checks">
          {warnings.map((text, idx) => (
            <div key={`warn-${idx}`} className="fw-ssl-ipsec-alert fw-ssl-ipsec-alert-warn" role="status">
              <strong>Review:</strong> {text}
            </div>
          ))}
          {infos.map((text, idx) => (
            <div key={`info-${idx}`} className="fw-ssl-ipsec-alert fw-ssl-ipsec-alert-info">
              <strong>Note:</strong> {text}
            </div>
          ))}
        </div>
      )}

      <section className="fw-card fw-sim-card" aria-label="Existing SSL-VPN policies to migrate">
        <div className="fw-sim-header">
          <div>
            <h3 className="fw-sim-title">1. Existing SSL-VPN Policies to Migrate</h3>
            <p className="fw-sim-subtitle">
              Policies matching an <code className="fw-mono">ssl.*</code> source interface in VDOM <code className="fw-mono">{activeVdom}</code>.
            </p>
          </div>
          {sslPolicies.length > 0 && (
            <button
              type="button"
              className="secondary-button button-compact"
              onClick={handleExportPoliciesCsv}
            >
              ⬇ CSV
            </button>
          )}
        </div>
        {sslPolicies.length > 0 ? (
          <>
            <div className="fw-legend" aria-label="Policy status legend">
              <span className="fw-legend-item fw-legend-success"><span className="fw-legend-swatch" aria-hidden="true" />Enabled Allow Policy (green)</span>
              <span className="fw-legend-item fw-legend-danger"><span className="fw-legend-swatch" aria-hidden="true" />Deny or Disabled Policy (red)</span>
            </div>
            <div className="report-table-wrap">
              <table className="report-table fw-table fw-pm-table">
                <thead>
                  <tr>
                    <th scope="col">ID</th>
                    <th scope="col">Name</th>
                    <th scope="col">Status</th>
                    <th scope="col">Src Interface</th>
                    <th scope="col">Dst Interface</th>
                    <th scope="col">Source</th>
                    <th scope="col">Destination</th>
                    <th scope="col">Service</th>
                    <th scope="col">Action</th>
                    <th scope="col">Groups / Users</th>
                    <th scope="col">Profiles</th>
                  </tr>
                </thead>
                <tbody>
                  {sslPolicies.map((pol) => (
                    <tr key={`${pol.id}-${pol.name}`} className={policyRowClass(pol)}>
                      <td className="fw-cell-mono">{pol.id}</td>
                      <td><strong>{pol.name}</strong></td>
                      <td>{pol.status}</td>
                      <td className="fw-cell-mono">{pol.srcintf}</td>
                      <td className="fw-cell-mono">{pol.dstintf}</td>
                      <td className="fw-cell-mono">{pol.srcaddr}</td>
                      <td className="fw-cell-mono">{pol.dstaddr}</td>
                      <td className="fw-cell-mono">{pol.service}</td>
                      <td>{pol.action}</td>
                      <td>{pol.groups !== '-' ? pol.groups : pol.users}</td>
                      <td className="fw-cell-mono">{pol.profiles}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="fw-ssl-ipsec-alert fw-ssl-ipsec-alert-warn">
            No firewall policies referencing <code className="fw-mono">ssl.*</code> interfaces were found in VDOM <code className="fw-mono">{activeVdom}</code>.
          </div>
        )}
      </section>

      <details className="fw-sim-details fw-ssl-ipsec-details">
        <summary>2. FortiGate GUI / Wizard Quick-Reference Parameters ({guiRows.length})</summary>
        <div className="fw-ssl-ipsec-details-body">
          <div className="fw-ssl-ipsec-details-actions">
            <button
              type="button"
              className="secondary-button button-compact"
              onClick={handleExportGuiCsv}
            >
              ⬇ CSV
            </button>
          </div>
          <div className="report-table-wrap">
            <table className="report-table fw-table fw-pm-table">
              <thead>
                <tr>
                  <th scope="col">Parameter</th>
                  <th scope="col">Recommended Value</th>
                  <th scope="col">Notes</th>
                </tr>
              </thead>
              <tbody>
                {guiRows.map((row) => (
                  <tr key={row.parameter}>
                    <td><strong>{row.parameter}</strong></td>
                    <td className="fw-cell-mono">{row.recommended_value}</td>
                    <td>{row.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </details>

      <section className="fw-card fw-sim-card" aria-label="Draft Dial-up IPSec Migration CLI">
        <div className="fw-sim-header">
          <div>
            <h3 className="fw-sim-title">3. Draft Dial-up IPSec Migration CLI (Phase 1, Phase 2 &amp; Policies)</h3>
            <p className="fw-sim-subtitle">
              Reuses your existing IP pool, DNS, split-tunnel addresses, user groups, and UTM profiles. Review and replace placeholders before applying.
            </p>
          </div>
          <div className="fw-ssl-ipsec-cli-actions">
            <button
              type="button"
              className="secondary-button button-compact"
              onClick={() => void handleCopyCli()}
            >
              {copied ? 'Copied' : 'Copy CLI'}
            </button>
            <button
              type="button"
              className="primary-button button-compact"
              onClick={() => void handleDownloadCli()}
            >
              ⬇ Download .txt
            </button>
          </div>
        </div>
        {downloadStatus && <p className="preview-status" role="status">{downloadStatus}</p>}
        <pre className="fw-ssl-ipsec-cli"><code>{data.cli_draft ?? ''}</code></pre>
      </section>

      <details className="fw-sim-details fw-ssl-ipsec-details">
        <summary>4. FortiClient Profile &amp; Zero-Downtime Cutover Checklist</summary>
        <div className="fw-ssl-ipsec-details-body">
          <h4 className="fw-ssl-ipsec-subhead">FortiClient Endpoint Parameters</h4>
          <div className="report-table-wrap">
            <table className="report-table fw-table fw-pm-table">
              <thead>
                <tr>
                  <th scope="col">Setting</th>
                  <th scope="col">Value</th>
                </tr>
              </thead>
              <tbody>
                {fcRows.map((row) => (
                  <tr key={row.setting}>
                    <td><strong>{row.setting}</strong></td>
                    <td className="fw-cell-mono">{row.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h4 className="fw-ssl-ipsec-subhead">Parallel Cutover Sequence</h4>
          <div className="report-table-wrap">
            <table className="report-table fw-table fw-pm-table">
              <thead>
                <tr>
                  <th scope="col">Step</th>
                  <th scope="col">Phase</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {cutoverRows.map((row) => (
                  <tr key={row.step}>
                    <td className="fw-cell-mono">{row.step}</td>
                    <td><strong>{row.phase}</strong></td>
                    <td>{row.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </details>
    </div>
  )
}
