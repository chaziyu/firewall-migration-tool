import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

test('VPN inspector subsection and labels integrate cleanly in reportPresentation and VpnInspectorView', async () => {
  const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
  try {
    const { reportSections, fieldLabel } = await server.ssrLoadModule('/src/features/report/reportPresentation.ts')
    const { VpnInspectorView } = await server.ssrLoadModule('/src/features/report/VpnInspectorView.tsx')
    const { WhereUsedPanel } = await server.ssrLoadModule('/src/features/report/WhereUsedPanel.tsx')

    assert.equal(fieldLabel('vpn_inspector'), 'Site-to-Site Inspector')
    const sections = reportSections({
      vpn_inspector: [
        {
          health: 'warning',
          name: 'vpn-hq',
          vdom: 'root',
          remote_gateway: '198.51.100.1',
          ike_version: '2',
          tunnel_interface: 'vpn-hq',
          zones: ['VPN-ZONE'],
          phase2_count: 1,
          route_count: 1,
          policy_count: 1,
          finding_count: 1,
          phase1: { ike_version: '2', proposal: ['aes256-sha256'], dh_groups: [14] },
          phase2: [{ name: 'p2', local_selector: '10.10.1.0/24', remote_selector: '172.16.50.0/24' }],
          binding: { tunnel_interface: 'vpn-hq', zones: ['VPN-ZONE'], virtual_router: 'VDOM root' },
          routes: [{ route_id: 1, destination: '172.16.50.0/24', device: 'vpn-hq' }],
          policies: [{ policy_id: 10, name: 'Allow-VPN', action: 'accept', nat: 'enable', status: 'enable' }],
          findings: [{ severity: 'warning', code: 'ACCIDENTAL_NAT', message: 'NAT enabled on VPN policy' }],
        },
      ],
      vpn_tunnels: [{ name: 'vpn-hq' }],
    })
    const vpnGroup = sections.find((item) => item.label === 'VPN')
    assert.ok(vpnGroup)
    assert.equal(vpnGroup.subsections[0].key, 'vpn_inspector')

    const vpnHtml = renderToStaticMarkup(createElement(VpnInspectorView, {
      rows: vpnGroup.subsections[0].rows,
      vendor: 'fortigate',
    }))
    assert.ok(vpnHtml.includes('vpn-hq'))
    assert.ok(vpnHtml.includes('ACCIDENTAL_NAT'))
    assert.ok(vpnHtml.includes('Layer 4'))

    const searchHtml = renderToStaticMarkup(createElement(WhereUsedPanel, {
      vendor: 'fortigate',
      sourceEvidence: { vendor: 'fortigate', source_text: '' },
    }))
    assert.ok(searchHtml.includes('Global IP / Object'))
  } finally {
    await server.close()
  }
})
