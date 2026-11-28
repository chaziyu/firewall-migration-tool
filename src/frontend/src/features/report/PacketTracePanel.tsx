import { useMemo, useState, type FormEvent } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { PacketTraceResponse } from '../source/types'
import { runPacketTrace } from '../source/sourceApi'
import type { ReportRow } from './reportPresentation'
import { extractSimulatorOptions } from './simulatorOptions'
import { ErrorBanner } from '../../components/common/ErrorBanner'

function verdictBadgeVariant(verdict: string | undefined): 'allow' | 'deny' | 'info' | 'warn' {
  const v = (verdict ?? '').toUpperCase()
  if (v === 'ALLOW') return 'allow'
  if (v === 'LOCAL-IN' || v === 'L2 DIRECT') return 'info'
  if (v === 'DENY' || v === 'DROP') return 'deny'
  return 'warn'
}

function stepToneClass(tone: string): string {
  if (tone === 'success') return 'row-success'
  if (tone === 'warn') return 'row-warn'
  if (tone === 'danger') return 'row-danger'
  return ''
}

function stepBadgeVariant(tone: string): 'allow' | 'warn' | 'deny' | 'info' {
  if (tone === 'success') return 'allow'
  if (tone === 'warn') return 'warn'
  if (tone === 'danger') return 'deny'
  return 'info'
}

export function PacketTracePanel({
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

  const [srcIp, setSrcIp] = useState('')
  const [dstIp, setDstIp] = useState('')
  const [protocol, setProtocol] = useState('tcp')
  const [dstPort, setDstPort] = useState('443')
  const [vdom, setVdom] = useState('')
  const [virtualRouter, setVirtualRouter] = useState('all')
  const [checkReturn, setCheckReturn] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<PacketTraceResponse | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await runPacketTrace(vendor, sourceEvidence, {
        src_ip: srcIp.trim(),
        dst_ip: dstIp.trim(),
        protocol,
        dst_port: protocol === 'icmp' || protocol === 'any' ? '' : dstPort.trim(),
        ...(isFortiGate ? { vdom: vdom || undefined } : { virtual_router: virtualRouter }),
        check_return: checkReturn,
      })
      if (!res.valid) {
        setError(res.error || 'Invalid packet trace parameters.')
        setResult(null)
      } else {
        setResult(res)
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Packet trace failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fw-sim-panel">
      <section className="fw-card fw-sim-card" aria-label="End-to-end packet flow simulator">
        <div className="fw-sim-header">
          <div>
            <h3 className="fw-sim-title">End-to-End Packet Flow Simulator (Trace Packet)</h3>
            <p className="fw-sim-subtitle">
              Trace Ingress &amp; RPF → {isFortiGate ? 'DNAT / VIP' : 'Local-In / NAT'} → Egress LPM Route → Security Policy → Outbound SNAT → Return Path.
            </p>
          </div>
        </div>

        <form className="fw-sim-form" onSubmit={(e) => void handleSubmit(e)}>
          <div className="fw-sim-grid">
            <label className="fw-sim-field">
              <span>Source IPv4</span>
              <input
                type="text"
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="e.g. 10.10.10.25"
                required
              />
            </label>
            <label className="fw-sim-field">
              <span>Destination IPv4</span>
              <input
                type="text"
                value={dstIp}
                onChange={(e) => setDstIp(e.target.value)}
                placeholder="e.g. 8.8.8.8"
                required
              />
            </label>
            <label className="fw-sim-field">
              <span>Protocol</span>
              <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="any">Any</option>
              </select>
            </label>
            <label className="fw-sim-field">
              <span>Destination Port</span>
              <input
                type="text"
                value={dstPort}
                onChange={(e) => setDstPort(e.target.value)}
                placeholder="443"
                disabled={protocol === 'icmp' || protocol === 'any'}
              />
            </label>
            {isFortiGate && options.vdoms.length > 1 && (
              <label className="fw-sim-field">
                <span>VDOM</span>
                <select value={vdom} onChange={(e) => setVdom(e.target.value)}>
                  <option value="">All VDOMs</option>
                  {options.vdoms.map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </label>
            )}
            {!isFortiGate && options.virtualRouters.length > 0 && (
              <label className="fw-sim-field">
                <span>Virtual / Logical Router</span>
                <select value={virtualRouter} onChange={(e) => setVirtualRouter(e.target.value)}>
                  <option value="all">All Routers</option>
                  {options.virtualRouters.map((vr) => <option key={vr} value={vr}>{vr}</option>)}
                </select>
              </label>
            )}
          </div>

          <div className="fw-sim-actions">
            <label className="fw-sim-checkbox">
              <input type="checkbox" checked={checkReturn} onChange={(e) => setCheckReturn(e.target.checked)} />
              <span>Check return path symmetry</span>
            </label>
            <button type="submit" className="primary-button button-compact" disabled={loading || !srcIp.trim() || !dstIp.trim()}>
              {loading ? 'Tracing…' : 'Trace Packet'}
            </button>
          </div>
        </form>
      </section>

      {error && <ErrorBanner message={error} />}

      {result && result.valid && (
        <section className="fw-card fw-sim-result" aria-label="Packet trace result">
          <div className="fw-sim-verdict-row">
            <div>
              <div className="fw-sim-verdict-label">
                Flow: <span className="fw-mono">{result.src} → {result.dst}</span>
              </div>
              <div className="fw-sim-verdict-reason">{result.policy}</div>
            </div>
            <span className={`fw-badge fw-badge-${verdictBadgeVariant(result.verdict)}`}>
              {result.verdict}
            </span>
          </div>

          <dl className="fw-sim-kv">
            <div className="fw-sim-kv-item"><dt>Ingress</dt><dd className="fw-mono">{result.ingress ?? '-'}</dd></div>
            <div className="fw-sim-kv-item"><dt>Egress</dt><dd className="fw-mono">{result.egress ?? '-'}</dd></div>
            <div className="fw-sim-kv-item"><dt>Policy Decision</dt><dd className="fw-mono">{result.policy ?? '-'}</dd></div>
            <div className="fw-sim-kv-item"><dt>NAT</dt><dd className="fw-mono">{result.nat ?? 'None'}</dd></div>
            {result.return_path && (
              <div className="fw-sim-kv-item"><dt>Return Path</dt><dd className="fw-mono">{result.return_path}</dd></div>
            )}
          </dl>

          {result.warnings && result.warnings.length > 0 && (
            <div className="fw-sim-note-warn" role="status">
              <strong>Trace Warnings</strong>
              <ul>
                {result.warnings.map((w, idx) => <li key={idx}>{w}</li>)}
              </ul>
            </div>
          )}

          {result.steps && result.steps.length > 0 && (
            <div className="report-table-wrap" role="region" aria-label="Packet trace stages">
              <table className="report-table fw-table">
                <thead>
                  <tr>
                    <th scope="col">Step</th>
                    <th scope="col">Stage</th>
                    <th scope="col">Outcome</th>
                    <th scope="col">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {result.steps.map((st) => (
                    <tr key={`${st.step}-${st.stage}`} className={stepToneClass(st.tone)}>
                      <td className="fw-mono">{st.step}</td>
                      <td><strong>{st.stage}</strong></td>
                      <td>
                        <span className={`fw-badge fw-badge-${stepBadgeVariant(st.tone)}`}>{st.outcome}</span>
                      </td>
                      <td>{st.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
