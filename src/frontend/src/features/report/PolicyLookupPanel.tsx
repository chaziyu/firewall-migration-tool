import { useMemo, useState, type FormEvent } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { PolicyLookupResponse, PolicyMatchRecord } from '../source/types'
import { runPolicyLookup } from '../source/sourceApi'
import { fieldLabel, type ReportRow } from './reportPresentation'
import { extractSimulatorOptions } from './simulatorOptions'
import { ErrorBanner } from '../../components/common/ErrorBanner'

function actionBadgeVariant(action: string): 'allow' | 'deny' | 'warn' | 'info' {
  const key = action.trim().toUpperCase()
  if (key === 'ACCEPT' || key === 'ALLOW' || key === 'IPSEC') return 'allow'
  if (key === 'NAT') return 'info'
  if (key === 'DENY' || key === 'DROP') return 'deny'
  return 'warn'
}

export function PolicyLookupPanel({
  vendor,
  sourceEvidence,
  sections,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
  sections: ReportRow
}) {
  const isFortiGate = vendor === 'fortigate'
  const options = useMemo(() => extractSimulatorOptions(sections), [sections])

  const [vdom, setVdom] = useState('')
  const [scope, setScope] = useState('')
  const [policyType, setPolicyType] = useState<'security' | 'nat'>('security')
  const [srcIface, setSrcIface] = useState('any')
  const [dstIface, setDstIface] = useState('any')
  const [srcZone, setSrcZone] = useState('any')
  const [dstZone, setDstZone] = useState('any')
  const [srcAddr, setSrcAddr] = useState('')
  const [dstAddr, setDstAddr] = useState('')
  const [protocol, setProtocol] = useState('any')
  const [dstPort, setDstPort] = useState('')
  const [srcUser, setSrcUser] = useState('any')

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<PolicyLookupResponse | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await runPolicyLookup(
        vendor,
        sourceEvidence,
        isFortiGate
          ? {
              vdom: vdom || undefined,
              src_iface: srcIface,
              dst_iface: dstIface,
              src_addr: srcAddr,
              dst_addr: dstAddr,
              protocol,
            }
          : {
              scope: scope || undefined,
              policy_type: policyType,
              src_zone: srcZone,
              dst_zone: dstZone,
              src_addr: srcAddr,
              dst_addr: dstAddr,
              dst_port: dstPort,
              protocol,
              src_user: srcUser,
            },
      )
      setResult(res)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Policy lookup failed')
    } finally {
      setLoading(false)
    }
  }

  function handleReset() {
    setVdom('')
    setScope('')
    setPolicyType('security')
    setSrcIface('any')
    setDstIface('any')
    setSrcZone('any')
    setDstZone('any')
    setSrcAddr('')
    setDstAddr('')
    setProtocol('any')
    setDstPort('')
    setSrcUser('any')
    setError(null)
    setResult(null)
  }

  const fgIfaceOptions = useMemo(() => [...new Set([...options.zones, ...options.interfaces])], [options.zones, options.interfaces])
  const matchEntries: Array<[string, string]> = result?.match
    ? Object.entries(result.match).map(([k, v]) => [fieldLabel(k), String(v ?? '-')])
    : []
  const shadowedRows: PolicyMatchRecord[] = result?.shadowed ?? []
  const shadowedColumns = shadowedRows.length ? Object.keys(shadowedRows[0]) : []

  return (
    <div className="fw-sim-panel">
      <section className="fw-card fw-sim-card" aria-label="Policy lookup simulator">
        <div className="fw-sim-header">
          <div>
            <h3 className="fw-sim-title">Policy Match Simulator</h3>
            <p className="fw-sim-subtitle">
              Evaluate {isFortiGate ? 'FortiGate policies' : 'PAN-OS rules'} top-to-bottom with address group, VIP, and service resolution.
            </p>
          </div>
        </div>

        <form className="fw-sim-form" onSubmit={(e) => void handleSubmit(e)}>
          <div className="fw-sim-grid">
            {isFortiGate ? (
              <>
                {options.vdoms.length > 1 && (
                  <label className="fw-sim-field">
                    <span>VDOM</span>
                    <select value={vdom} onChange={(e) => setVdom(e.target.value)}>
                      <option value="">All VDOMs</option>
                      {options.vdoms.map((v) => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </label>
                )}
                <label className="fw-sim-field">
                  <span>Source Interface / Zone</span>
                  <select value={srcIface} onChange={(e) => setSrcIface(e.target.value)}>
                    <option value="any">any</option>
                    {fgIfaceOptions.map((i) => <option key={i} value={i}>{i}</option>)}
                  </select>
                </label>
                <label className="fw-sim-field">
                  <span>Dest Interface / Zone</span>
                  <select value={dstIface} onChange={(e) => setDstIface(e.target.value)}>
                    <option value="any">any</option>
                    {fgIfaceOptions.map((i) => <option key={i} value={i}>{i}</option>)}
                  </select>
                </label>
                <label className="fw-sim-field">
                  <span>Source IP / Object</span>
                  <input type="text" value={srcAddr} onChange={(e) => setSrcAddr(e.target.value)} placeholder="e.g. 10.1.1.10 or any" />
                </label>
                <label className="fw-sim-field">
                  <span>Destination IP / VIP</span>
                  <input type="text" value={dstAddr} onChange={(e) => setDstAddr(e.target.value)} placeholder="e.g. 8.8.8.8 or VIP name" />
                </label>
                <label className="fw-sim-field">
                  <span>Service / Protocol / Port</span>
                  <input type="text" value={protocol} onChange={(e) => setProtocol(e.target.value)} placeholder="any, HTTPS, tcp/443, 8443" />
                </label>
              </>
            ) : (
              <>
                <label className="fw-sim-field">
                  <span>Rulebase</span>
                  <select value={policyType} onChange={(e) => setPolicyType(e.target.value as 'security' | 'nat')}>
                    <option value="security">Security Policy</option>
                    <option value="nat">NAT Policy</option>
                  </select>
                </label>
                {options.scopes.length > 1 && (
                  <label className="fw-sim-field">
                    <span>Scope / VSYS</span>
                    <select value={scope} onChange={(e) => setScope(e.target.value)}>
                      <option value="">All Scopes</option>
                      {options.scopes.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </label>
                )}
                <label className="fw-sim-field">
                  <span>Source Zone</span>
                  <select value={srcZone} onChange={(e) => setSrcZone(e.target.value)}>
                    <option value="any">any</option>
                    {options.zones.map((z) => <option key={z} value={z}>{z}</option>)}
                  </select>
                </label>
                <label className="fw-sim-field">
                  <span>Destination Zone</span>
                  <select value={dstZone} onChange={(e) => setDstZone(e.target.value)}>
                    <option value="any">any</option>
                    {options.zones.map((z) => <option key={z} value={z}>{z}</option>)}
                  </select>
                </label>
                <label className="fw-sim-field">
                  <span>Source IP / Object</span>
                  <input type="text" value={srcAddr} onChange={(e) => setSrcAddr(e.target.value)} placeholder="e.g. 10.1.1.10 or any" />
                </label>
                <label className="fw-sim-field">
                  <span>Destination IP / Object</span>
                  <input type="text" value={dstAddr} onChange={(e) => setDstAddr(e.target.value)} placeholder="e.g. 1.1.1.1 or any" />
                </label>
                <label className="fw-sim-field">
                  <span>Protocol</span>
                  <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                    <option value="any">any</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="sctp">SCTP</option>
                    <option value="icmp">ICMP</option>
                  </select>
                </label>
                <label className="fw-sim-field">
                  <span>Destination Port</span>
                  <input type="text" value={dstPort} onChange={(e) => setDstPort(e.target.value)} placeholder="e.g. 443 or blank for any" />
                </label>
                {policyType === 'security' && (
                  <label className="fw-sim-field">
                    <span>Source User</span>
                    <input type="text" value={srcUser} onChange={(e) => setSrcUser(e.target.value)} placeholder="any" />
                  </label>
                )}
              </>
            )}
          </div>

          <div className="fw-sim-actions">
            <button type="submit" className="primary-button button-compact" disabled={loading}>
              {loading ? 'Evaluating…' : 'Evaluate Policy'}
            </button>
            <button type="button" className="secondary-button button-compact" onClick={handleReset} disabled={loading}>
              Reset
            </button>
          </div>
        </form>
      </section>

      {error && <ErrorBanner message={error} />}

      {result && (
        <section className="fw-card fw-sim-result" aria-label="Policy lookup result">
          <div className="fw-sim-verdict-row">
            <div>
              <div className="fw-sim-verdict-label">Evaluation Result</div>
              <div className="fw-sim-verdict-reason">{result.reason}</div>
            </div>
            <span className={`fw-badge fw-badge-${actionBadgeVariant(result.action)}`}>
              {result.matched ? result.action : `No Match (${result.action})`}
            </span>
          </div>

          {matchEntries.length > 0 && (
            <dl className="fw-sim-kv">
              {matchEntries.map(([label, val]) => (
                <div key={label} className="fw-sim-kv-item">
                  <dt>{label}</dt>
                  <dd className="fw-mono">{val}</dd>
                </div>
              ))}
            </dl>
          )}

          {shadowedRows.length > 0 && (
            <details className="fw-sim-details">
              <summary>Shadowed Rules ({shadowedRows.length}) — lower-priority rules that also match</summary>
              <div className="report-table-wrap">
                <table className="report-table fw-table">
                  <thead>
                    <tr>
                      {shadowedColumns.map((col) => <th key={col} scope="col">{fieldLabel(col)}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {shadowedRows.map((row, idx) => (
                      <tr key={idx}>
                        {shadowedColumns.map((col) => (
                          <td key={col} className="fw-mono">{String(row[col] ?? '-')}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </section>
      )}
    </div>
  )
}
