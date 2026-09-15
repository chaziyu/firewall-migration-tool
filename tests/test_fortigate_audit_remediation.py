from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.parsers.fortigate import extract_fortigate_config


def test_select_command_is_retained_and_blocks_generation():
    result = extract_fortigate_config('''
config firewall address
    edit "A"
        set subnet 10.0.0.1 255.255.255.255
        select member "B"
    next
end
''')

    assert result.generation_safe is False
    assert any("select operation" in reason for reason in result.blocking_reasons)
    item = next(item for item in result.inventory_items if item.source_path == "unsupported select")
    assert item.commands[0].operation == "select"
    assert item.commands[0].line_number == 5


def test_unquoted_inline_comment_blocks_but_quoted_hash_does_not():
    bad = extract_fortigate_config('''
config firewall address
    edit "A"
        set comment "safe value" # unsupported inline comment
    next
end
''')
    assert bad.generation_safe is False
    assert any("inline comment" in reason for reason in bad.blocking_reasons)

    good = extract_fortigate_config('''
config firewall address
    edit "A"
        set comment "safe # value"
    next
end
''')
    assert not any("inline comment" in reason for reason in good.blocking_reasons)


def test_pba_pool_keeps_source_review_status_and_is_capability_gated():
    result = extract_fortigate_config('''
config firewall ippool
    edit "PBA_POOL"
        set type port-block-allocation
        set startip 203.0.113.10
        set endip 203.0.113.20
        set source-startip 10.0.0.10
        set source-endip 10.0.0.20
        set startport 5117
        set endport 65533
        set block-size 128
        set num-blocks-per-user 4
        set pba-timeout 60
    next
end
''')

    pool = result.canonical_ir.ip_pools[0]
    assert pool.migration_status == "PARTIALLY_NORMALIZED"
    assert pool.requires_manual_review is True

    palo_issues = CapabilityAnalyzer().analyze(result.canonical_ir, "palo_alto")
    assert any(issue.feature == "ip-pool-source-completeness" and issue.blocks_generation for issue in palo_issues)

    fortigate_issues = CapabilityAnalyzer().analyze(result.canonical_ir, "fortigate")
    assert any(issue.feature == "ip-pool-source-completeness" and issue.blocks_generation for issue in fortigate_issues)

    cli = FortiGateCLIGenerator().generate(result.canonical_ir)[0].content
    assert "set type port-block-allocation" not in cli


def test_complete_vip_group_is_normalized_and_emitted_for_fortigate():
    result = extract_fortigate_config('''
config firewall vip
    edit "WEB"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
    next
end
config firewall vipgrp
    edit "PUBLISHED"
        set member "WEB"
    next
end
''')

    group = result.canonical_ir.virtual_ip_groups[0]
    assert group.migration_status == "NORMALIZED"
    assert group.requires_manual_review is False

    cli = FortiGateCLIGenerator().generate(result.canonical_ir)[0].content
    assert "config firewall vipgrp" in cli
    assert 'edit "PUBLISHED"' in cli
    assert 'set member "WEB"' in cli


def test_src_vip_filter_is_typed_source_evidence_and_remains_fail_closed():
    result = extract_fortigate_config('''
config firewall vip
    edit "WEB"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
        set src-vip-filter enable
    next
end
''')

    vip = result.canonical_ir.virtual_ips[0]
    assert vip.extra_settings["src_vip_filter"] == "enable"
    assert vip.extra_settings["src_vip_filter_enabled"] is True
    assert vip.requires_manual_review is True
    assert "src-vip-filter" in (vip.audit_note or "")

    palo_issues = CapabilityAnalyzer().analyze(result.canonical_ir, "palo_alto")
    assert any(issue.feature == "src-vip-filter" and issue.blocks_generation for issue in palo_issues)
    fortigate_issues = CapabilityAnalyzer().analyze(result.canonical_ir, "fortigate")
    assert not any(issue.feature == "src-vip-filter" and issue.blocks_generation for issue in fortigate_issues)


def test_ipv6_pool_keeps_extract_only_source_contract():
    result = extract_fortigate_config('''
config firewall ippool6
    edit "POOL6"
        set startip 2001:db8::10
        set endip 2001:db8::20
        set nat46 enable
        set add-nat46-route enable
    next
end
''')

    pool = result.canonical_ir.ip_pools[0]
    assert pool.address_family == "ipv6"
    assert pool.migration_status == "EXTRACT_ONLY"
    assert pool.requires_manual_review is True
    issues = CapabilityAnalyzer().analyze(result.canonical_ir, "fortigate")
    assert any(issue.feature == "ip-pool-source-completeness" and issue.blocks_generation for issue in issues)


def _two_vdom_config() -> str:
    return '''
config vdom
    edit "root"
        config firewall address
            edit "HOST"
                set subnet 10.0.0.1 255.255.255.255
            next
        end
    next
    edit "tenant-a"
        config firewall address
            edit "HOST"
                set subnet 10.1.0.1 255.255.255.255
            next
        end
    next
end
'''


def test_multi_vdom_requires_complete_context_mapping():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="fortigate",
        target_vendor="fortigate",
        source_content=_two_vdom_config(),
        target_format="cli",
    ))
    assert result.generation_allowed is False
    assert any("target-scope mapping" in reason or "scope mapping" in reason for reason in result.blocking_reasons)


def test_multi_vdom_context_mapping_preserves_source_context_and_renders_target_vdoms():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="fortigate",
        target_vendor="fortigate",
        source_content=_two_vdom_config(),
        target_format="cli",
        context_mapping={"root": "target-root", "tenant-a": "target-tenant"},
    ))

    assert result.generation_allowed is True
    assert {address.source_context for address in result.source_ir.addresses} == {"root", "tenant-a"}
    cli = result.artifacts[0].content
    assert "config vdom" in cli
    assert 'edit "target-root"' in cli
    assert 'edit "target-tenant"' in cli
    assert cli.count('edit "HOST"') == 2


def test_multi_vdom_context_mapping_rejects_duplicate_target_scope():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="fortigate",
        target_vendor="fortigate",
        source_content=_two_vdom_config(),
        target_format="cli",
        context_mapping={"root": "same", "tenant-a": "same"},
    ))
    assert result.generation_allowed is False
    assert any("distinct target scope" in reason for reason in result.blocking_reasons)
