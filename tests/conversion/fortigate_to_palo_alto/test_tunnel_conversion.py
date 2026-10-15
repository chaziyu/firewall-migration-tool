from copy import deepcopy
from dataclasses import replace

from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.application.review import build_review_state
from fwmigrate.conversion.fortigate_to_palo_alto.design.deterministic import build_deterministic_draft
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline


SOURCE = '''config system interface
 edit wan
  set type physical
  set ip 192.0.2.1 255.255.255.0
 next
 edit site
  set type tunnel
  set interface wan
 next
 edit ssl.root
  set type tunnel
 next
end
config vpn ipsec phase1-interface
 edit site
  set interface wan
  set remote-gw 192.0.2.2
  set proposal aes256-sha256
  set dhgrp 14
  set keylife 28800
 next
end
config router static
 edit 1
  set dst 198.51.100.0 255.255.255.0
  set device site
 next
end
'''


def test_tunnel_proposal_does_not_bypass_vpn_prerequisites_and_routes_propagate():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    source, derived = analysis.extracted.config, analysis.derived
    original = deepcopy(source)
    state = build_review_state(source, derived, 'source', include_configuration=True)
    draft = build_deterministic_draft(source, derived, state['decisions'], source_digest='source', workflow_mode='offline')
    tunnel = next(row for row in draft.decisions if row.source_name == 'site' and row.target_field == 'target_interface')
    assert tunnel.proposed_value == 'tunnel.1' and not tunnel.approved
    assert next(row for row in draft.decisions if row.source_name == 'ssl.root').status == 'UNSUPPORTED'
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}}, interfaces={'root': {
        'wan': {'target_interface': 'ethernet1/1', 'target_zone': 'outside'},
        'site': {'target_interface': 'tunnel.1', 'target_zone': 'vpn'},
    }})
    blocked = run_migration_pipeline(source, derived, options=options, workflow_mode='OFFLINE_EXPORT')
    assert not any('static-route 1 ' in command for command in blocked.rendered.commands)
    existing = run_migration_pipeline(source, derived, options=replace(options, conversion_settings={'existing_vpns': ['root/site']}), workflow_mode='OFFLINE_EXPORT')
    assert 'set network interface tunnel units tunnel.1' in existing.rendered.commands
    assert 'set network virtual-router VR routing-table ip static-route 1 nexthop none' in existing.rendered.commands
    assert not any('pre-shared-key' in command for command in existing.rendered.commands)
    assert source == original
