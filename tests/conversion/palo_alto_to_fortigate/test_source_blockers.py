from dataclasses import replace

import pytest

from fwmigrate.conversion.palo_alto_to_fortigate.application import approve_design, build_artifact, build_review
from fwmigrate.vendors.palo_alto.relationships.topology import PANRelationshipIssue
from fwmigrate.vendors.palo_alto.source_model import PANScope

from .conftest import SOURCE


def test_router_import_warning_blocks_affected_topology_but_not_independent_objects(analyze):
    router = '<virtual-router><entry name="default"><interface><member>ethernet1/1</member></interface></entry></virtual-router>'
    source = SOURCE.replace('</interface></network>', '</interface>' + router + '</network>', 1)
    source = source.replace('</interface></network></import>', '</interface><virtual-router><member>other</member></virtual-router></network></import>')
    analysis = analyze(source)
    assert len(analysis.derived.relationship_issues) == 1
    assert analysis.derived.relationship_issues[0].message == 'virtual-router member is not imported into this VSYS'
    before = analysis.config.model_dump()
    review = build_review(analysis, {}, 'source')
    rows = {(row['family'], row['source_name']): row for row in review['draft']['configuration']}
    for identity in [('address', 'net'), ('address_group', 'clients'), ('service', 'web'), ('interface', 'ethernet1/2'), ('zone', 'untrust')]:
        assert not rows[identity]['blocking_reasons']
    assert any(reason.startswith('Source topology:') for reason in rows['interface', 'ethernet1/1']['blocking_reasons'])
    assert rows['zone', 'trust']['render_disposition'] == 'BLOCK'
    assert rows['policy', 'allow-web']['render_disposition'] == 'BLOCK'
    assert not review['draft']['findings']
    assert any(issue['category'] == 'SOURCE' for issue in review['issues'])
    approval = approve_design(review, review['draft'], [rows['address', 'net']['key']])
    artifact = build_artifact(analysis, {}, 'source', approval)
    assert 'config firewall address' in artifact['commands']
    assert 'config firewall policy' not in artifact['commands']
    assert 'config system interface' not in artifact['commands']
    assert artifact['report']['plan_status'] == 'PARTIAL'
    assert any('Source topology:' in reason for row in artifact['report']['items'] for reason in row['blocking_reasons'])
    assert analysis.config.model_dump() == before


def test_unmapped_topology_retains_source_evidence_and_blocks_traffic(analysis):
    issue = PANRelationshipIssue('interface-topology', 'Unverified tunnel attachment', 'tunnel.99', analysis.config.interfaces[0].scope)
    analysis = replace(analysis, derived=replace(analysis.derived, relationship_issues=(issue,)))
    review = build_review(analysis, {}, 'source')
    rows = review['draft']['configuration']
    assert not next(row for row in rows if row['family'] == 'address')['blocking_reasons']
    assert all(row['blocking_reasons'] for row in rows if row['family'] in {'interface', 'zone', 'policy'})
    assert any(row['family'] == 'manual' and row['source_name'] == 'tunnel.99' and 'Source topology:' in row['blocking_reasons'][0] for row in rows)


def test_other_device_topology_does_not_block_selected_source(analysis):
    issue = PANRelationshipIssue('interface-topology', 'Unverified attachment', 'ethernet1/1', PANScope(kind='device', name='other', device_name='other'))
    analysis = replace(analysis, derived=replace(analysis.derived, relationship_issues=(issue,)))
    review = build_review(analysis, {}, 'source')
    policy = next(row for row in review['draft']['configuration'] if row['family'] == 'policy')
    assert not policy['blocking_reasons']
    assert any(row['source_scope'] == 'device:other:device:other' and row['render_disposition'] == 'BLOCK' for row in review['draft']['configuration'])


@pytest.mark.parametrize('issue', [PANRelationshipIssue('scope', 'Ambiguous ownership'), PANRelationshipIssue('interface-topology', 'Unknown owner')])
def test_unscoped_or_unknown_relationship_failures_remain_global(analysis, issue):
    analysis = replace(analysis, derived=replace(analysis.derived, relationship_issues=(issue,)))
    review = build_review(analysis, {}, 'source')
    assert review['draft']['findings']
    assert all(row['render_disposition'] == 'BLOCK' for row in review['draft']['configuration'])


def test_unknown_extraction_paths_remain_global(analysis):
    source = analysis.config.model_copy(deep=True)
    source.unknown_paths = ['config/devices/entry/vsys/entry/address/entry']
    review = build_review(replace(analysis, config=source), {}, 'source')
    assert review['draft']['findings']
    assert all(row['render_disposition'] == 'BLOCK' for row in review['draft']['configuration'])
