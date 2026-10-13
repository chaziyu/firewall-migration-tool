import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_unknown_interface_ownership_cannot_become_root_migration_input():
    analysis = FortiGateSourceReporter().analyze_source('''config global
    config system interface
        edit unassigned
        next
    end
end
''')
    source = analysis.extracted.config
    assert source.interfaces[0].vdom is None
    with pytest.raises(ValueError, match="VDOM ownership is unresolved"):
        build_mapping_requirements(source, analysis.derived, include_configuration=True)
    with pytest.raises(ValueError, match="VDOM ownership is unresolved"):
        FortiGateToPaloAltoPlanner().plan(source, analysis.derived)
