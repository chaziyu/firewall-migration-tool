from fwmigrate.parsers.fortigate.model import FGConfig, FGService, FGServiceGroup
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_service_transformation_audits_use_machine_readable_codes():
    ir = FGToIRTransformer(
        FGConfig(
            services=[
                FGService(name="range", protocol="TCP", tcp_portrange="90-80"),
                FGService(name="protocol", protocol="QUIC-FUTURE"),
                FGService(
                    name="number",
                    protocol="IP",
                    protocol_number=300,
                ),
                FGService(
                    name="unmodeled",
                    protocol="TCP",
                    tcp_portrange="443",
                    extra_settings={"helper": "sip"},
                ),
            ]
        )
    ).transform()

    assert {
        entry.code
        for entry in ir.audit_entries
        if entry.code is not None
    } >= {
        "FG_SERVICE_INVALID_PORT_RANGE",
        "FG_SERVICE_UNSUPPORTED_PROTOCOL",
        "FG_SERVICE_INVALID_PROTOCOL_NUMBER",
        "FG_SERVICE_UNMODELED_SEMANTIC",
    }
    issue = next(
        entry for entry in ir.audit_entries
        if entry.code == "FG_SERVICE_INVALID_PORT_RANGE"
    )
    assert (issue.object_type, issue.object_name, issue.field) == (
        "service",
        "range",
        "port",
    )


def test_service_group_diagnostics_cover_reference_failures():
    ir = FGToIRTransformer(
        FGConfig(
            services=[FGService(name="duplicate", protocol="TCP", tcp_portrange="443")],
            service_groups=[
                FGServiceGroup(name="duplicate"),
                FGServiceGroup(name="self", member=["self"]),
                FGServiceGroup(name="left", member=["right"]),
                FGServiceGroup(name="right", member=["left"]),
                FGServiceGroup(name="missing", member=["not-defined"]),
                FGServiceGroup(name="ambiguous", member=["duplicate"]),
            ],
        )
    ).transform()

    assert {
        entry.code
        for entry in ir.audit_entries
        if entry.object_type == "service_group"
    } >= {
        "FG_SERVICE_GROUP_SELF_REFERENCE",
        "FG_SERVICE_GROUP_CYCLE",
        "FG_SERVICE_GROUP_UNRESOLVED_MEMBER",
        "FG_SERVICE_GROUP_AMBIGUOUS_MEMBER",
    }
