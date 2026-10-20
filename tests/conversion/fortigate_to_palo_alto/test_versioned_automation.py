from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.planning.vips import vip_port_translation
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.vendors.fortigate.model.ippool import FGIPPool
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP
from fwmigrate.vendors.fortigate.transform.effective_values import effective_value
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import snat_precedence_warnings


@pytest.mark.parametrize('version,expected', [('7.2.13', '0.0.0.0/0'), ('7.4.6', None), (None, None)])
def test_omitted_ipv4_address_value_is_version_verified_and_never_mutates_source(version, expected):
    source = FGConfig(addresses=[FGAddress(name='all'), FGAddress(name='all', address_family='ipv6')])
    before = source.model_dump()
    derived = build_derived_views(source, source_metadata=SimpleNamespace(fortios_version=version))
    plan = FortiGateToPaloAltoPlanner().plan(source, derived,
        PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    assert plan.addresses[0].value == expected
    assert plan.addresses[1].value is None
    assert source.model_dump() == before


def test_derived_deny_does_not_become_a_no_snat_accept_predecessor():
    source = FGConfig(policies=[FGPolicy(policy_id=1, srcintf=['any'], dstintf=['any']),
                                FGPolicy(policy_id=2, action='accept', nat='enable', srcintf=['any'], dstintf=['any'])])
    options = PANMigrationOptions()
    known = build_derived_views(source, source_metadata=SimpleNamespace(fortios_version='7.2.13'))
    assert not snat_precedence_warnings(source, options, known)
    assert ('root', 2) in snat_precedence_warnings(source, options)
    # The unknown/VIP policy itself is still blocked by policy planning; this only corrects NAT precedence classification.
    assert FortiGateToPaloAltoPlanner().plan(source, known, options).security_rules[0].status.value != 'SUPPORTED'


def test_defaults_preserve_explicit_pool_type_and_port_protocol():
    source = FGConfig(ip_pools=[FGIPPool(name='pool'), FGIPPool(name='fixed', type='one-to-one')],
        vips=[FGVIP(name='tcp', portforward='enable', extport='443', mappedport='8443'),
              FGVIP(name='udp', portforward='enable', protocol='udp', extport='53', mappedport='53')])
    before = source.model_dump()
    derived = build_derived_views(source, source_metadata=SimpleNamespace(fortios_version='7.2.13'))
    assert effective_value(derived, 'root', 'ip_pool', 'pool', 'type') == 'overload'
    assert effective_value(derived, 'root', 'ip_pool', 'fixed', 'type') is None
    assert vip_port_translation(source.vips[0], derived) == ('tcp', '443', '8443')
    assert vip_port_translation(source.vips[1], derived) == ('udp', '53', '53')
    assert vip_port_translation(source.vips[0]) is None
    assert source.model_dump() == before
