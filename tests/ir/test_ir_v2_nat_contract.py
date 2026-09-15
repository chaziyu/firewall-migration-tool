from fwmigrate.ir import (
    IRIPPool,
    IRNATPool,
    IRPublishedService,
    IRPublishedServiceGroup,
    IRVirtualIP,
    IRVirtualIPGroup,
)


def test_legacy_nat_python_names_are_aliases():
    assert IRIPPool is IRNATPool
    assert IRVirtualIP is IRPublishedService
    assert IRVirtualIPGroup is IRPublishedServiceGroup
