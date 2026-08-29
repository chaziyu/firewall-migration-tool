from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_applications_and_multi_term():
    fixture_path = JUNIPER_FIXTURES_DIR / "applications.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    svc_dict = {s.name: s for s in ir.services}

    # Standard app
    assert "app_web" in svc_dict
    assert svc_dict["app_web"].ports[0].protocol == ServiceProtocol.TCP
    assert svc_dict["app_web"].ports[0].port == "80"
    assert svc_dict["app_web"].description == "Standard HTTP"

    # Multi term app
    assert "app_multi_term" in svc_dict
    assert len(svc_dict["app_multi_term"].ports) == 2
    protos = {p.protocol for p in svc_dict["app_multi_term"].ports}
    assert protos == {ServiceProtocol.TCP, ServiceProtocol.UDP}

    # ICMP
    assert "app_icmp_echo" in svc_dict
    assert svc_dict["app_icmp_echo"].ports[0].protocol == ServiceProtocol.ICMP
    assert svc_dict["app_icmp_echo"].ports[0].icmptype == 8
    assert svc_dict["app_icmp_echo"].ports[0].icmpcode == 0

    # Application Set
    sg_dict = {sg.name: sg for sg in ir.service_groups}
    assert "set_web_services" in sg_dict
    assert "app_web" in sg_dict["set_web_services"].members
    assert "app_multi_term" in sg_dict["set_web_services"].members

    assert_no_silent_loss(res, total_input_commands=12)
