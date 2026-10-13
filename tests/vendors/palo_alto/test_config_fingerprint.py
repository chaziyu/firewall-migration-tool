import pytest

from fwmigrate.vendors.palo_alto.config_fingerprint import destination_fingerprint


def test_fingerprint_preserves_order_scope_and_leaf_values_and_sanitizes_secrets():
    source = '<config><devices><entry name="fw"><vsys><entry name="vsys1"><rulebase><security><rules><entry name="a"/><entry name="b"/></rules></security></rulebase></entry></vsys><password>secret-a</password><description> value </description></entry></devices></config>'
    digest = destination_fingerprint(source)
    assert digest == destination_fingerprint(source.replace('secret-a', 'secret-b'))
    assert digest == destination_fingerprint('<response><result>' + source + '</result></response>')
    for change in (source.replace('vsys1', 'vsys2'), source.replace(' value ', 'value'),
                   source.replace('<entry name="a"/><entry name="b"/>', '<entry name="b"/><entry name="a"/>')):
        assert digest != destination_fingerprint(change)


@pytest.mark.parametrize('source', ['', '<config>secret', '<config/>', '<not-config/>',
                                   '<!DOCTYPE config><config><devices/></config>'])
def test_fingerprint_rejects_incomplete_or_unsafe_evidence_without_echo(source):
    with pytest.raises(ValueError, match='^Cannot fingerprint complete PAN-OS destination evidence$'):
        destination_fingerprint(source)
