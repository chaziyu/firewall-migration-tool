import { useState } from 'react'
import type { VpnInspectorFinding, VpnInspectorRow } from '../source/types'
import { cellSummary, asRecord, asRows } from './reportPresentation'

function healthBadgeVariant(health: string): 'allow' | 'warn' | 'deny' | 'muted' {
  const normalized = health.toLowerCase()
  if (normalized === 'healthy') return 'allow'
  if (normalized === 'warning') return 'warn'
  if (normalized === 'critical') return 'deny'
  return 'muted'
}

function findingBadgeVariant(severity: string): 'deny' | 'warn' | 'info' {
  const normalized = severity.toLowerCase()
  if (normalized === 'critical') return 'deny'
  if (normalized === 'warning') return 'warn'
  return 'info'
}

export function VpnInspectorView({
  rows,
  vendor,
}: {
  rows: Record<string, unknown>[]
  vendor?: string
}) {
  const tunnels = rows as VpnInspectorRow[]
  const [selectedName, setSelectedName] = useState<string>('')

  if (!tunnels.length) {
    return (
      <div className="vpn-inspector-empty">
        <p>No site-to-site IPsec tunnels matched the current filter.</p>
      </div>
    )
  }

  const active = tunnels.find((item) => item.name === selectedName) ?? tunnels[0]
  const phase1 = asRecord(active.phase1)
  const binding = asRecord(active.binding)
  const phase2Rows = asRows(active.phase2)
  const routeRows = asRows(active.routes)
  const policyRows = asRows(active.policies)
  const findings = (Array.isArray(active.findings) ? active.findings : []) as VpnInspectorFinding[]
  const isPanos = vendor === 'palo_alto'
  const gateways = asRows(phase1.ike_gateways)

  return (
    <div className="vpn-inspector">
      <div className="fw-legend" aria-label="VPN health legend">
        <span className="fw-legend-item fw-legend-success"><span className="fw-legend-swatch" aria-hidden="true" />Healthy</span>
        <span className="fw-legend-item fw-legend-warn"><span className="fw-legend-swatch" aria-hidden="true" />Warning</span>
        <span className="fw-legend-item fw-legend-danger"><span className="fw-legend-swatch" aria-hidden="true" />Critical</span>
        <span className="fw-legend-item fw-legend-muted"><span className="fw-legend-swatch" aria-hidden="true" />Disabled</span>
      </div>

      <div className="vpn-inspector-overview-wrap">
        <table className="vpn-inspector-table">
          <thead>
            <tr>
              <th scope="col">Health</th>
              <th scope="col">Tunnel</th>
              <th scope="col">{isPanos ? 'Scope' : 'VDOM'}</th>
              <th scope="col">Peer Gateway</th>
              <th scope="col">IKE</th>
              <th scope="col">Tunnel Interface</th>
              <th scope="col">Zones</th>
              <th scope="col">Phase 2</th>
              <th scope="col">Routes</th>
              <th scope="col">Policies</th>
              <th scope="col">Checks</th>
            </tr>
          </thead>
          <tbody>
            {tunnels.map((tunnel) => {
              const isSelected = tunnel === active
              return (
                <tr
                  key={`${tunnel.vdom ?? tunnel.scope ?? ''}:${tunnel.name}`}
                  className={isSelected ? 'selected' : undefined}
                  onClick={() => setSelectedName(tunnel.name)}
                >
                  <td>
                    <span className={`fw-badge fw-badge-${healthBadgeVariant(String(tunnel.health ?? 'muted'))}`}>
                      {String(tunnel.health ?? 'unknown').toUpperCase()}
                    </span>
                  </td>
                  <td className="fw-cell-mono">{tunnel.name}</td>
                  <td>{tunnel.vdom ?? tunnel.scope ?? '—'}</td>
                  <td className="fw-cell-mono">{tunnel.remote_gateway ?? 'Not reported'}</td>
                  <td>{tunnel.ike_version ?? 'Not reported'}</td>
                  <td className="fw-cell-mono">{tunnel.tunnel_interface ?? 'Unbound'}</td>
                  <td>{Array.isArray(tunnel.zones) && tunnel.zones.length ? tunnel.zones.join(', ') : 'None'}</td>
                  <td>{tunnel.phase2_count ?? 0}</td>
                  <td>{tunnel.route_count ?? 0}</td>
                  <td>{tunnel.policy_count ?? 0}</td>
                  <td>{tunnel.finding_count ?? 0}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <section className="vpn-inspector-detail" aria-label={`Inspector for ${active.name}`}>
        <header className="vpn-inspector-detail-header">
          <div>
            <h3>{active.name}</h3>
            <p className="vpn-inspector-detail-sub">
              {active.vpn_mode ?? 'route-based'} · {active.vdom ?? active.scope ?? 'default'} · Peer: {active.remote_gateway ?? 'Not reported'}
            </p>
          </div>
          <span className={`fw-badge fw-badge-${healthBadgeVariant(String(active.health ?? 'muted'))}`}>
            {String(active.health ?? 'unknown').toUpperCase()}
          </span>
        </header>

        <div className="vpn-inspector-findings">
          <h4>Automated Misconfiguration Checks ({findings.length})</h4>
          {!findings.length ? (
            <p className="vpn-inspector-ok">No misconfigurations detected across all 4 tunnel layers.</p>
          ) : (
            <ul className="vpn-inspector-finding-list">
              {findings.map((finding, idx) => (
                <li key={`${finding.code}-${idx}`} className="vpn-inspector-finding-item">
                  <span className={`fw-badge fw-badge-${findingBadgeVariant(finding.severity)}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <span className="fw-cell-mono">{finding.code}</span>
                  <span>{finding.message}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="vpn-inspector-layers">
          <div className="vpn-inspector-layer">
            <h4>Layer 1 · Phase 1 / IKE &amp; Crypto / Phase 2 Selectors</h4>
            {isPanos ? (
              <>
                <dl className="vpn-inspector-kv">
                  <div><dt>IPSec Crypto Profile</dt><dd>{cellSummary(phase1.ipsec_crypto_profile)}</dd></div>
                  <div><dt>ESP Encryption</dt><dd>{cellSummary(phase1.ipsec_esp_encryption)}</dd></div>
                  <div><dt>ESP Authentication</dt><dd>{cellSummary(phase1.ipsec_esp_authentication)}</dd></div>
                  <div><dt>IPSec DH Group</dt><dd>{cellSummary(phase1.ipsec_dh_group)}</dd></div>
                </dl>
                {gateways.length > 0 && (
                  <table className="vpn-inspector-subtable">
                    <thead>
                      <tr>
                        <th>IKE Gateway</th><th>IKE Version</th><th>Peer</th><th>Local Interface</th><th>IKE Crypto</th><th>DH Groups</th>
                      </tr>
                    </thead>
                    <tbody>
                      {gateways.map((gw, idx) => (
                        <tr key={idx}>
                          <td className="fw-cell-mono">{cellSummary(gw.name)}</td>
                          <td>{cellSummary(gw.ike_version)}</td>
                          <td className="fw-cell-mono">{cellSummary(gw.peer_address)}</td>
                          <td className="fw-cell-mono">{cellSummary(gw.local_interface)}</td>
                          <td>{cellSummary(gw.ike_crypto_profile)} ({cellSummary(gw.ike_crypto_encryption)})</td>
                          <td>{cellSummary(gw.ike_crypto_dh)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            ) : (
              <dl className="vpn-inspector-kv">
                <div><dt>IKE Version</dt><dd>{cellSummary(phase1.ike_version)}</dd></div>
                <div><dt>Remote Gateway</dt><dd>{cellSummary(phase1.remote_gateway)}</dd></div>
                <div><dt>Local Interface</dt><dd>{cellSummary(phase1.interface)}</dd></div>
                <div><dt>Phase 1 Proposal</dt><dd>{cellSummary(phase1.proposal)}</dd></div>
                <div><dt>Phase 1 DH Groups</dt><dd>{cellSummary(phase1.dh_groups)}</dd></div>
                <div><dt>DPD / NAT-T</dt><dd>{cellSummary(phase1.dpd)} / {cellSummary(phase1.nattraversal)}</dd></div>
              </dl>
            )}

            {phase2Rows.length > 0 ? (
              <table className="vpn-inspector-subtable">
                <thead>
                  <tr>
                    <th>Phase 2 / Proxy ID</th><th>Local Selector</th><th>Remote Selector</th>
                    {!isPanos && <><th>Proposal</th><th>PFS / DH</th></>}
                    {isPanos && <><th>Protocol</th><th>Ports</th></>}
                  </tr>
                </thead>
                <tbody>
                  {phase2Rows.map((p2, idx) => (
                    <tr key={idx}>
                      <td className="fw-cell-mono">{cellSummary(p2.name)}</td>
                      <td className="fw-cell-mono">{cellSummary(p2.local_selector)}</td>
                      <td className="fw-cell-mono">{cellSummary(p2.remote_selector)}</td>
                      {!isPanos && <><td>{cellSummary(p2.proposal)}</td><td>{cellSummary(p2.pfs)} / {cellSummary(p2.dh_groups)}</td></>}
                      {isPanos && <><td>{cellSummary(p2.protocol)}</td><td>{cellSummary(p2.local_port)} → {cellSummary(p2.remote_port)}</td></>}
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="vpn-inspector-muted">No Phase 2 selectors / Proxy IDs configured.</p>
            )}
          </div>

          <div className="vpn-inspector-layer">
            <h4>Layer 2 · Tunnel Interface, Zone &amp; Virtual Router Binding</h4>
            <dl className="vpn-inspector-kv">
              <div><dt>Tunnel Interface</dt><dd className="fw-cell-mono">{cellSummary(binding.tunnel_interface)}</dd></div>
              <div><dt>Tunnel IP</dt><dd className="fw-cell-mono">{cellSummary(binding.tunnel_ip)}</dd></div>
              <div><dt>Zones</dt><dd>{Array.isArray(binding.zones) && binding.zones.length ? binding.zones.join(', ') : 'None bound'}</dd></div>
              <div><dt>Virtual Router / VRF</dt><dd>{cellSummary(binding.virtual_router)}</dd></div>
              {!isPanos && <div><dt>Underlying Port</dt><dd>{cellSummary(binding.underlying_interface)}</dd></div>}
              {!isPanos && <div><dt>Interface Status</dt><dd>{cellSummary(binding.interface_status)}</dd></div>}
            </dl>
          </div>

          <div className="vpn-inspector-layer">
            <h4>Layer 3 · Static Routes Pointing to Tunnel ({routeRows.length})</h4>
            {routeRows.length > 0 ? (
              <table className="vpn-inspector-subtable">
                <thead>
                  <tr><th>Route</th><th>Destination</th><th>Gateway</th><th>Device</th><th>Distance</th></tr>
                </thead>
                <tbody>
                  {routeRows.map((rt, idx) => (
                    <tr key={idx}>
                      <td>{cellSummary(rt.route_id)}</td>
                      <td className="fw-cell-mono">{cellSummary(rt.destination)}</td>
                      <td className="fw-cell-mono">{cellSummary(rt.gateway)}</td>
                      <td className="fw-cell-mono">{cellSummary(rt.device)}</td>
                      <td>{cellSummary(rt.distance)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="vpn-inspector-muted">No static routes target this tunnel interface.</p>
            )}
          </div>

          <div className="vpn-inspector-layer">
            <h4>Layer 4 · Firewall / Security Policies ({policyRows.length})</h4>
            {policyRows.length > 0 ? (
              <table className="vpn-inspector-subtable">
                <thead>
                  <tr>
                    <th>{isPanos ? 'Rule' : 'Policy'}</th>
                    <th>Source Zone / Intf</th>
                    <th>Dest Zone / Intf</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Action</th>
                    <th>{isPanos ? 'Disabled' : 'NAT / Status'}</th>
                  </tr>
                </thead>
                <tbody>
                  {policyRows.map((pol, idx) => (
                    <tr key={idx}>
                      <td>{cellSummary(pol.name ?? pol.policy_id)}</td>
                      <td>{cellSummary(pol.from_zones ?? pol.srcintf)}</td>
                      <td>{cellSummary(pol.to_zones ?? pol.dstintf)}</td>
                      <td>{cellSummary(pol.source ?? pol.srcaddr)}</td>
                      <td>{cellSummary(pol.destination ?? pol.dstaddr)}</td>
                      <td>{cellSummary(pol.action)}</td>
                      <td>{isPanos ? cellSummary(pol.disabled) : `${cellSummary(pol.nat)} / ${cellSummary(pol.status)}`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="vpn-inspector-muted">No policies reference this tunnel interface or its zones.</p>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
