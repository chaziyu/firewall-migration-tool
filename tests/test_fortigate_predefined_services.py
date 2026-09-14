from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.predefined_services import (
    FORTIGATE_PREDEFINED_SERVICE_GROUPS,
    FORTIGATE_PREDEFINED_SERVICES,
    is_predefined_service,
    is_predefined_service_group,
)


def _item(path, name, commands=()):
    return SourceInventoryItem(
        domain="firewall",
        source_path=path,
        name=name,
        commands=[
            SourceCommand(
                operation="set",
                key=key,
                values=values,
            )
            for key, values in commands
        ],
    )


def test_predefined_services_are_exact_and_service_specific() -> None:
    assert len(FORTIGATE_PREDEFINED_SERVICES) == 85
    assert all(
        is_predefined_service(name)
        for name in ("HTTP", "HTTPS", "DNS", "SSH", "PING")
    )
    assert not any(
        is_predefined_service(name)
        for name in ("HTPPS", "DNSS", "https", "ALL_ICMP6")
    )

    assert FORTIGATE_PREDEFINED_SERVICE_GROUPS == {
        "Email Access",
        "Exchange Server",
        "Web Access",
        "Windows AD",
    }
    assert all(
        is_predefined_service_group(name)
        for name in FORTIGATE_PREDEFINED_SERVICE_GROUPS
    )
    assert not is_predefined_service_group("web access")

    dependencies = build_dependency_registry([
        _item("firewall service custom", "APP_8443"),
        _item("firewall service group", "WEB_GROUP"),
        _item(
            "firewall policy",
            "1",
            [
                (
                    "service",
                    [
                        "HTTPS",
                        "APP_8443",
                        "WEB_GROUP",
                        "Web Access",
                        "HTPPS",
                    ],
                )
            ],
        ),
        _item(
            "firewall service group",
            "CUSTOM_GROUP",
            [("member", ["HTTPS", "Web Access", "MISSING_GROUP"])],
        ),
        _item(
            "firewall vip",
            "WEB_VIP",
            [("service", ["HTTPS", "HTPPS"])],
        ),
        _item(
            "firewall local-in-policy",
            "2",
            [("service", ["SSH", "Windows AD", "SSHH"])],
        ),
        _item("firewall address", "HTTPS"),
    ])

    assert [
        (
            item.source_path,
            item.reference,
            item.result,
            item.target_path,
        )
        for item in dependencies
    ] == [
        (
            "firewall policy",
            "HTTPS",
            "RESOLVED",
            "fortigate predefined service",
        ),
        (
            "firewall policy",
            "APP_8443",
            "RESOLVED",
            "firewall service custom",
        ),
        (
            "firewall policy",
            "WEB_GROUP",
            "RESOLVED",
            "firewall service group",
        ),
        (
            "firewall policy",
            "Web Access",
            "RESOLVED",
            "fortigate predefined service group",
        ),
        ("firewall policy", "HTPPS", "UNRESOLVED", None),
        (
            "firewall service group",
            "HTTPS",
            "RESOLVED",
            "fortigate predefined service",
        ),
        (
            "firewall service group",
            "Web Access",
            "RESOLVED",
            "fortigate predefined service group",
        ),
        (
            "firewall service group",
            "MISSING_GROUP",
            "UNRESOLVED",
            None,
        ),
        (
            "firewall vip",
            "HTTPS",
            "RESOLVED",
            "fortigate predefined service",
        ),
        ("firewall vip", "HTPPS", "UNRESOLVED", None),
        (
            "firewall local-in-policy",
            "SSH",
            "RESOLVED",
            "fortigate predefined service",
        ),
        (
            "firewall local-in-policy",
            "Windows AD",
            "RESOLVED",
            "fortigate predefined service group",
        ),
        (
            "firewall local-in-policy",
            "SSHH",
            "UNRESOLVED",
            None,
        ),
    ]


def test_predefined_policy_service_does_not_create_a_generation_block() -> None:
    result = extract_fortigate_config('''config system interface
    edit "lan"
    next
    edit "wan"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set service "Web Access"
        set action accept
    next
end
''')

    service_dependency = next(
        item
        for item in result.dependencies
        if item.source_field == "service"
    )
    assert (
        service_dependency.result,
        service_dependency.target_path,
    ) == (
        "RESOLVED",
        "fortigate predefined service group",
    )
    assert result.generation_safe is True
