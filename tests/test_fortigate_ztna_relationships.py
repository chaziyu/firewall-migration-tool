from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry


def _item(
    source_path: str,
    name: str,
    *,
    context: str = "root",
    commands: list[tuple[str, list[str]]] | None = None,
) -> SourceInventoryItem:
    return SourceInventoryItem(
        domain=source_path.split(" ", 1)[0],
        source_path=source_path,
        name=name,
        source_context=context,
        commands=[
            SourceCommand(operation="set", key=field, values=values)
            for field, values in (commands or [])
        ],
    )


def test_access_proxy_relationships_resolve_to_exact_source_families() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "port1"),
            _item("vpn certificate local", "ZTNA_CERT"),
            _item("authentication scheme", "ZTNA_SCHEME"),
            _item("authentication rule", "ZTNA_RULE"),
            _item("firewall access-proxy-virtual-host", "app.example.test"),
            _item("firewall service group", "WEB_SERVICES"),
            _item("vpn ssl web portal", "web-access"),
            _item(
                "firewall access-proxy",
                "ZTNA_APP",
                commands=[
                    ("interface", ["port1"]),
                    ("srcintf", ["port1"]),
                    ("certificate", ["ZTNA_CERT"]),
                    ("ssl-certificate", ["ZTNA_CERT"]),
                    ("auth-method", ["ZTNA_SCHEME"]),
                    ("auth-rule", ["ZTNA_RULE"]),
                    ("auth-virtual-host", ["app.example.test"]),
                    ("service", ["WEB_SERVICES"]),
                    ("ssl-vpn-web-portal", ["web-access"]),
                ],
            ),
        ]
    )

    by_field = {dependency.source_field: dependency for dependency in dependencies}
    assert set(by_field) == {
        "interface",
        "srcintf",
        "certificate",
        "ssl-certificate",
        "auth-method",
        "auth-rule",
        "auth-virtual-host",
        "service",
        "ssl-vpn-web-portal",
    }
    assert all(dependency.result == "RESOLVED" for dependency in dependencies)
    assert by_field["certificate"].target_path == "vpn certificate local"
    assert by_field["auth-method"].target_path == "authentication scheme"
    assert by_field["auth-rule"].target_path == "authentication rule"
    assert by_field["auth-virtual-host"].target_path == "firewall access-proxy-virtual-host"
    assert by_field["service"].target_path == "firewall service group"


def test_missing_access_proxy_references_are_explicitly_unresolved() -> None:
    dependencies = build_dependency_registry(
        [
            _item(
                "firewall access-proxy",
                "ZTNA_APP",
                commands=[
                    ("interface", ["missing-port"]),
                    ("certificate", ["missing-cert"]),
                    ("auth-method", ["missing-scheme"]),
                    ("auth-rule", ["missing-rule"]),
                    ("auth-virtual-host", ["missing-vhost"]),
                ],
            )
        ]
    )

    assert [dependency.result for dependency in dependencies] == [
        "UNRESOLVED",
        "UNRESOLVED",
        "UNRESOLVED",
        "UNRESOLVED",
        "UNRESOLVED",
    ]
    assert all(dependency.target_path is None for dependency in dependencies)


def test_access_proxy_references_do_not_cross_vdom_boundaries() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "port1", context="VDOM_A"),
            _item("vpn certificate local", "ZTNA_CERT", context="VDOM_A"),
            _item("authentication scheme", "ZTNA_SCHEME", context="VDOM_A"),
            _item(
                "firewall access-proxy",
                "ZTNA_APP",
                context="VDOM_B",
                commands=[
                    ("interface", ["port1"]),
                    ("certificate", ["ZTNA_CERT"]),
                    ("auth-method", ["ZTNA_SCHEME"]),
                ],
            ),
        ]
    )

    assert [(dependency.source_field, dependency.result) for dependency in dependencies] == [
        ("interface", "UNRESOLVED"),
        ("certificate", "UNRESOLVED"),
        ("auth-method", "UNRESOLVED"),
    ]


def test_virtual_host_can_reference_ipv6_access_proxy_and_auth_objects() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall access-proxy6", "ZTNA_V6"),
            _item("vpn certificate local", "VHOST_CERT"),
            _item("system interface", "port2"),
            _item("authentication scheme", "SCHEME_V6"),
            _item("firewall auth-portal", "AUTH_PORTAL"),
            _item(
                "firewall access-proxy-virtual-host",
                "v6.example.test",
                commands=[
                    ("access-proxy", ["ZTNA_V6"]),
                    ("certificate", ["VHOST_CERT"]),
                    ("interface", ["port2"]),
                    ("auth-method", ["SCHEME_V6"]),
                    ("auth-portal", ["AUTH_PORTAL"]),
                ],
            ),
        ]
    )

    assert all(dependency.result == "RESOLVED" for dependency in dependencies)
    access_proxy_dependency = next(
        dependency for dependency in dependencies if dependency.source_field == "access-proxy"
    )
    assert access_proxy_dependency.target_path == "firewall access-proxy6"


def test_authentication_rule_scheme_references_are_validated() -> None:
    dependencies = build_dependency_registry(
        [
            _item("authentication scheme", "SCHEME_A"),
            _item("authentication scheme", "SCHEME_B"),
            _item(
                "authentication rule",
                "RULE_A",
                commands=[
                    ("active-auth-method", ["SCHEME_A"]),
                    ("auth-method", ["SCHEME_A", "SCHEME_B", "MISSING_SCHEME"]),
                ],
            ),
        ]
    )

    assert [
        (dependency.source_field, dependency.reference, dependency.result)
        for dependency in dependencies
    ] == [
        ("active-auth-method", "SCHEME_A", "RESOLVED"),
        ("auth-method", "SCHEME_A", "RESOLVED"),
        ("auth-method", "SCHEME_B", "RESOLVED"),
        ("auth-method", "MISSING_SCHEME", "UNRESOLVED"),
    ]


def test_empty_and_redacted_ztna_reference_values_do_not_create_dependencies() -> None:
    dependencies = build_dependency_registry(
        [
            _item(
                "firewall access-proxy",
                "ZTNA_APP",
                commands=[
                    ("certificate", [""]),
                    ("auth-method", ["[REDACTED]"]),
                    ("auth-rule", ["<redacted>"]),
                ],
            )
        ]
    )

    assert dependencies == []
