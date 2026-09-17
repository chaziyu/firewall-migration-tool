import fwmigrate.generators  # noqa: F401 - register built-in target generators
import fwmigrate.parsers  # noqa: F401 - register built-in source parsers
import pytest

from fwmigrate.application import MigrationPipeline, MigrationRequest


SAFE_CONFIG = """\
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "port2"
        set ip 203.0.113.2 255.255.255.0
    next
end
config firewall address
    edit "LAN"
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAN"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set schedule "always"
        set nat disable
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 203.0.113.1
        set device "port2"
    next
end
"""

ZONE_MAPPING = {"port1": "LAN_ZONE", "port2": "WAN_ZONE"}


def _request(content: str) -> MigrationRequest:
    return MigrationRequest(
        source_vendor="fortigate",
        target_vendor="fortigate",
        target_format="cli",
        source_content=content,
        zone_mapping=ZONE_MAPPING,
    )


def test_fortigate_pipeline_analyze_and_run_safe_fixture():
    pipeline = MigrationPipeline()
    analysis = pipeline.analyze(_request(SAFE_CONFIG))

    assert analysis.generation_allowed is True
    assert analysis.blocking_reasons == []
    assert len(analysis.source_ir.addresses) == 1
    assert len(analysis.source_ir.services) == 1
    assert len(analysis.source_ir.policies) == 1

    result = pipeline.run(_request(SAFE_CONFIG))
    assert result.generation_allowed is True
    assert result.artifacts
    generated = result.artifacts[0].content
    assert 'set srcintf "LAN_ZONE"' in generated
    assert 'set srcaddr "LAN"' in generated
    assert "config firewall service custom" in generated


@pytest.mark.parametrize(
    ("content", "reason_fragment"),
    [
        (
            SAFE_CONFIG.replace('set srcaddr "LAN"', 'set srcaddr "MISSING"'),
            "Unresolved FortiGate reference",
        ),
        (
            SAFE_CONFIG.replace(
                'set nat disable',
                'set nat enable\n        set ippool enable\n        set poolname "SNAT_POOL"',
            )
            + """
config firewall ippool
    edit "SNAT_POOL"
        set startip 198.51.100.10
        set endip 198.51.100.20
    next
end
config firewall ippool_grp
    edit "SNAT_POOL"
        set member "SNAT_POOL"
    next
end
""",
                "ippool",
        ),
        (
            SAFE_CONFIG.replace(
                'set action accept',
                'set action accept\n        set inspection-mode proxy',
            ),
                "manual review",
        ),
        (
            """\
config vdom
    edit "root"
    next
    edit "other"
    next
end
""" + SAFE_CONFIG,
            "Multiple FortiGate VDOMs",
        ),
        (
            SAFE_CONFIG
            + """
config firewall central-snat-map
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set orig-addr "LAN"
        set dst-addr "all"
    next
end
""",
                "traffic-affecting",
        ),
    ],
)
def test_fortigate_pipeline_withholds_unsafe_generation(content, reason_fragment):
    pipeline = MigrationPipeline()
    analysis = pipeline.analyze(_request(content))
    assert analysis.generation_allowed is False
    assert analysis.blocking_reasons
    assert any(
        reason_fragment.casefold() in reason.casefold()
        for reason in analysis.blocking_reasons
    )

    result = pipeline.run(_request(content))
    assert result.generation_allowed is False
    assert result.artifacts == []
