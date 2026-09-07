from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _item(source_path: str, name: str, *, field: str | None = None) -> SourceInventoryItem:
    commands = []
    if field is not None:
        commands.append(SourceCommand(operation="set", key=field, values=[name]))
    return SourceInventoryItem(
        domain=source_path.split(" ", 1)[0],
        source_path=source_path,
        name=name,
        commands=commands,
    )


def test_policy_dstaddr6_resolves_ipv6_vip_and_vip_group_targets() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall vip6", "VIP6-A"),
            _item("firewall vipgrp6", "VIP6-GRP"),
            SourceInventoryItem(
                domain="firewall",
                source_path="firewall policy",
                name="10",
                commands=[
                    SourceCommand(
                        operation="set",
                        key="dstaddr6",
                        values=["VIP6-A", "VIP6-GRP"],
                    )
                ],
            ),
        ]
    )

    policy_dependencies = [
        dependency
        for dependency in dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "dstaddr6"
    ]

    assert [dependency.reference for dependency in policy_dependencies] == [
        "VIP6-A",
        "VIP6-GRP",
    ]
    assert [dependency.result for dependency in policy_dependencies] == [
        "RESOLVED",
        "RESOLVED",
    ]
    assert [dependency.target_path for dependency in policy_dependencies] == [
        "firewall vip6",
        "firewall vipgrp6",
    ]
    assert all(
        dependency.expected_type == "firewall address6"
        for dependency in policy_dependencies
    )


def test_policy_srcaddr6_does_not_resolve_ipv6_vip_families() -> None:
    for target_path in ("firewall vip6", "firewall vipgrp6"):
        dependency = build_dependency_registry(
            [
                _item(target_path, "same-name"),
                SourceInventoryItem(
                    domain="firewall",
                    source_path="firewall policy",
                    name="20",
                    commands=[
                        SourceCommand(
                            operation="set",
                            key="srcaddr6",
                            values=["same-name"],
                        )
                    ],
                ),
            ]
        )[0]

        assert dependency.result == "UNRESOLVED"
        assert dependency.target_path is None


def test_policy_dstaddr6_ipv6_vip_dependencies_resolve_from_cli() -> None:
    config = '''
config firewall vip6
    edit "VIP6-A"
        set extip 2001:db8:100::10
        set mappedip 2001:db8:200::10
    next
end
config firewall vipgrp6
    edit "VIP6-GRP"
        set member "VIP6-A"
    next
end
config firewall policy
    edit 30
        set srcintf "any"
        set dstintf "any"
        set srcaddr6 "all"
        set dstaddr6 "VIP6-A" "VIP6-GRP"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
'''

    result = extract_fortigate_config(config)
    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "dstaddr6"
    ]

    assert [(item.reference, item.result, item.target_path) for item in dependencies] == [
        ("VIP6-A", "RESOLVED", "firewall vip6"),
        ("VIP6-GRP", "RESOLVED", "firewall vipgrp6"),
    ]
