import { useMemo, useState, type FormEvent } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { RouteLookupResponse } from '../source/types'
import { runRouteLookup } from '../source/sourceApi'
import type { ReportRow } from './reportPresentation'
import { extractSimulatorOptions } from './simulatorOptions'
import { ErrorBanner } from '../../components/common/ErrorBanner'

export function RouteLookupPanel({
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

  const [destIp, setDestIp] = useState('')
  const [vdom, setVdom] = useState('')
  const [virtualRouter, setVirtualRouter] = useState('all')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<RouteLookupResponse | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await runRouteLookup(vendor, sourceEvidence, {
        dest_ip: destIp.trim(),
        ...(isFortiGate ? { vdom: vdom || undefined } : { virtual_router: virtualRouter }),
      })
      if (!res.valid) {
        setError(res.error || 'Invalid destination IP address.')
        setResult(null)
      } else {
        setResult(res)
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Route lookup failed')
    } finally {
      setLoading(false)
    }
  }

  const winner = result?.winner ?? null
  const candidates = result?.candidates ?? []

  return (
    <div className="fw-sim-panel">
      <section className="fw-card fw-sim-card" aria-label="Longest-Prefix-Match route lookup">
        <div className="fw-sim-header">
          <div>
            <h3 className="fw-sim-title">Longest-Prefix-Match (LPM) Route Lookup</h3>
            <p className="fw-sim-subtitle">
              Resolve the winning connected or static route for a destination IP against {isFortiGate ? 'FortiGate interfaces & static routes' : 'PAN-OS Virtual / Logical Routers'}.
            </p>
          </div>
        </div>

        <form className="fw-sim-form" onSubmit={(e) => void handleSubmit(e)}>
          <div className="fw-sim-grid">
            <label className="fw-sim-field">
              <span>Destination IP</span>
              <input
                type="text"
                value={destIp}
                onChange={(e) => setDestIp(e.target.value)}
                placeholder="e.g. 8.8.8.8 or 10.20.30.5"
                required
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

            {!isFortiGate && (
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
            <button type="submit" className="primary-button button-compact" disabled={loading || !destIp.trim()}>
              {loading ? 'Looking up…' : 'Lookup Route'}
            </button>
          </div>
        </form>
      </section>

      {error && <ErrorBanner message={error} />}

      {result && result.valid && (
        <section className="fw-card fw-sim-result" aria-label="Route lookup result">
          {(result.active_policy_routes ?? 0) > 0 && (
            <div className="fw-sim-note-warn" role="status">
              Note: {result.active_policy_routes} active Policy Route(s) exist and are evaluated before static/connected routes on FortiGate.
            </div>
          )}

          <div className="fw-sim-verdict-row">
            <div>
              <div className="fw-sim-verdict-label">Winning Route for <span className="fw-mono">{result.dest_ip}</span></div>
              <div className="fw-sim-verdict-reason">
                {winner
                  ? `${winner.type} route ${winner.destination} via ${winner.interface} (${winner.gateway ?? winner.next_hop ?? '-'})`
                  : 'No matching connected or static route found (packet would be dropped).'}
              </div>
            </div>
            <span className={`fw-badge fw-badge-${winner ? (winner.type === 'Blackhole' ? 'deny' : 'allow') : 'deny'}`}>
              {winner ? `${winner.type} /${winner.prefix_len}` : 'No Route'}
            </span>
          </div>

          {winner && (
            <dl className="fw-sim-kv">
              {winner.virtual_router && (
                <div className="fw-sim-kv-item"><dt>Router</dt><dd className="fw-mono">{winner.virtual_router}</dd></div>
              )}
              {winner.vdom && (
                <div className="fw-sim-kv-item"><dt>VDOM</dt><dd className="fw-mono">{winner.vdom}</dd></div>
              )}
              <div className="fw-sim-kv-item"><dt>Destination</dt><dd className="fw-mono">{winner.destination}</dd></div>
              <div className="fw-sim-kv-item"><dt>Interface</dt><dd className="fw-mono">{winner.interface}</dd></div>
              <div className="fw-sim-kv-item"><dt>Next Hop / Gateway</dt><dd className="fw-mono">{winner.gateway ?? winner.next_hop ?? '-'}</dd></div>
              <div className="fw-sim-kv-item">
                <dt>{isFortiGate ? 'Distance / Priority' : 'AD / Metric'}</dt>
                <dd className="fw-mono">{isFortiGate ? `${winner.distance ?? 0} / ${winner.priority ?? 0}` : `${winner.ad ?? 0} / ${winner.metric ?? 0}`}</dd>
              </div>
            </dl>
          )}

          {candidates.length > 0 && (
            <div className="report-table-wrap" role="region" aria-label="Matching route candidates">
              <table className="report-table fw-table">
                <thead>
                  <tr>
                    <th scope="col">{isFortiGate ? 'VDOM' : 'Router'}</th>
                    <th scope="col">Type</th>
                    <th scope="col">Destination</th>
                    <th scope="col">Prefix</th>
                    <th scope="col">{isFortiGate ? 'Gateway' : 'Next Hop'}</th>
                    <th scope="col">Interface</th>
                    <th scope="col">{isFortiGate ? 'Dist / Prio' : 'AD / Metric'}</th>
                  </tr>
                </thead>
                <tbody>
                  {candidates.map((cand, idx) => (
                    <tr key={`${cand.destination}-${cand.interface}-${idx}`} className={idx === 0 ? 'row-success' : undefined}>
                      <td className="fw-mono">{cand.vdom ?? cand.virtual_router ?? '-'}</td>
                      <td>{cand.type}</td>
                      <td className="fw-mono">{cand.destination}</td>
                      <td className="fw-mono">/{cand.prefix_len}</td>
                      <td className="fw-mono">{cand.gateway ?? cand.next_hop ?? '-'}</td>
                      <td className="fw-mono">{cand.interface}</td>
                      <td className="fw-mono">{isFortiGate ? `${cand.distance ?? 0} / ${cand.priority ?? 0}` : `${cand.ad ?? 0} / ${cand.metric ?? 0}`}</td>
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
