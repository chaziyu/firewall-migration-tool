from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fwmigrate.generators.checkpoint.cli_generator import CheckPointCLIGenerator
from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fwmigrate.generators.target_helpers import prepare_target_services
from fwmigrate.ir import IRConfig
from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.ir.metadata import IRMetadata
from fwmigrate.ir.service import IRService, IRServiceGroup, IRServicePort
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _ir(services, groups=()):
    return IRConfig(
        metadata=IRMetadata(source_vendor="fortigate"),
        services=list(services),
        service_groups=list(groups),
    )


def test_target_preparation_flattens_nested_groups_without_changing_ir():
    service = IRService(
        name="web",
        ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="80-90")],
    )
    inner = IRServiceGroup(name="inner", members=["web"])
    outer = IRServiceGroup(name="outer", members=["inner"])
    ir = _ir([service], [inner, outer])

    prepared = prepare_target_services(ir.services, ir.service_groups, "cisco_asa")

    assert prepared.members_for(outer) == ("web",)
    assert outer.members == ["inner"]
    assert prepared.group_result(outer).supported

    cli = CiscoASACLIGenerator().generate(ir)
    assert "service tcp destination range 80 90" in cli
    assert "service-object object web" in cli
    assert "service-object object inner" not in cli


def test_target_preparation_withholds_cycles_and_unsupported_members():
    constrained = IRService(
        name="constrained",
        ports=[
            IRServicePort(
                protocol=ServiceProtocol.TCP,
                port="443",
                source_port="1024-65535",
            )
        ],
    )
    first = IRServiceGroup(name="first", members=["second"])
    second = IRServiceGroup(name="second", members=["first", "constrained"])
    prepared = prepare_target_services([constrained], [first, second], "cisco_asa")

    assert not prepared.group_result(first).supported
    assert "cyclic service-group reference" in prepared.group_result(first).reasons
    assert not prepared.service_result(constrained).supported

    missing = IRServiceGroup(name="missing-group", members=["not-defined"])
    missing_prepared = prepare_target_services([], [missing], "cisco_asa")
    assert not missing_prepared.group_result(missing).supported
    assert "unresolved service-group member" in missing_prepared.group_result(missing).reasons[0]

    for generator in (
        CiscoASACLIGenerator(),
        CheckPointCLIGenerator(),
        JuniperSRXCLIGenerator(),
    ):
        output = generator.generate(_ir([constrained]))
        assert "Service constrained withheld" in output
        assert "destination any" not in output


def test_checkpoint_does_not_drop_unsupported_sctp():
    service = IRService(
        name="sctp-service",
        ports=[IRServicePort(protocol=ServiceProtocol.SCTP, port="5000")],
    )
    output = CheckPointCLIGenerator().generate(_ir([service]))

    assert "Service sctp-service withheld" in output
    assert "add service-tcp" not in output
    assert "add service-udp" not in output


def test_fortigate_source_meaning_reaches_canonical_ir_and_target_preparation():
    source = """
config firewall service custom
    edit "web"
        set tcp-portrange "443:1024-65535"
    next
    edit "icmp-web"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
    next
end
config firewall service group
    edit "outer"
        set member "web" "icmp-web"
    next
end
"""

    ir = extract_fortigate_config(source).canonical_ir
    web = next(service for service in ir.services if service.name == "web")
    icmp = next(service for service in ir.services if service.name == "icmp-web")
    group = ir.service_groups[0]

    assert [(port.protocol, port.port, port.source_port) for port in web.ports] == [
        (ServiceProtocol.TCP, "443", "1024-65535")
    ]
    assert [(port.icmptype, port.icmpcode) for port in icmp.ports] == [(8, 0)]

    prepared = prepare_target_services(ir.services, ir.service_groups, "juniper_srx")
    assert not prepared.service_result(web).supported
    assert prepared.service_result(icmp).supported
    assert not prepared.group_result(group).supported
