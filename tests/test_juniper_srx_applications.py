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

def test_application_partial_semantics():
    content = """
    set version 21.4R1.12
    set system host-name SRX-App-Edge
    set applications application app_no_proto destination-port 8080
    set applications application app_gre protocol 47
    set applications application app_bad_icmp protocol icmp icmp-type nonexistent-symbolic-type
    set applications application app_multi_src protocol tcp destination-port 80 source-port 1000-2000
    set applications application app_multi_src protocol tcp source-port 3000-4000
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    svc_dict = {s.name: s for s in ir.services}

    # Missing protocol
    assert "app_no_proto" in svc_dict
    assert svc_dict["app_no_proto"].requires_manual_review is True
    assert svc_dict["app_no_proto"].migration_status == "PARTIALLY_NORMALIZED"
    assert "Missing protocol definition" in (svc_dict["app_no_proto"].audit_note or "")

    # Numeric protocol number
    assert "app_gre" in svc_dict
    assert svc_dict["app_gre"].requires_manual_review is True
    assert svc_dict["app_gre"].migration_status == "PARTIALLY_NORMALIZED"
    assert svc_dict["app_gre"].source_protocol_number == 47
    assert any("protocol-number: 47" in u for u in svc_dict["app_gre"].source_unmodeled_semantic_settings)

    # Unrecognized symbolic ICMP type
    assert "app_bad_icmp" in svc_dict
    assert svc_dict["app_bad_icmp"].requires_manual_review is True
    assert svc_dict["app_bad_icmp"].migration_status == "PARTIALLY_NORMALIZED"
    assert any("icmp-type" in u for u in svc_dict["app_bad_icmp"].source_unmodeled_semantic_settings)

    # Multiple source ports
    assert "app_multi_src" in svc_dict
    assert svc_dict["app_multi_src"].requires_manual_review is True
    assert svc_dict["app_multi_src"].migration_status == "PARTIALLY_NORMALIZED"


def test_application_unknown_icmp_code():
    content = """
    set version 21.4R1.12
    set system host-name SRX-ICMP-Test
    set applications application app_unknown_icmp_code protocol icmp icmp-type echo-request icmp-code unknown-code-symbol
    set applications application app_known_icmp protocol icmp icmp-type echo-request icmp-code 0
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    svc_dict = {s.name: s for s in ir.services}

    # Unknown symbolic ICMP code
    bad_icmp = svc_dict["app_unknown_icmp_code"]
    assert bad_icmp.requires_manual_review is True
    assert bad_icmp.migration_status == "PARTIALLY_NORMALIZED"
    assert any("icmp-code: unknown-code-symbol" in u for u in bad_icmp.source_unmodeled_semantic_settings)

    # Known ICMP
    known_icmp = svc_dict["app_known_icmp"]
    assert known_icmp.requires_manual_review is False
    assert known_icmp.migration_status == "NORMALIZED"
    assert known_icmp.ports[0].icmptype == 8
    assert known_icmp.ports[0].icmpcode == 0

    assert_no_silent_loss(res, total_input_commands=4)

