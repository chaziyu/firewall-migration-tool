from pathlib import Path

from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def test_security_rule_order_is_retained_per_source_rulebase():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "policies.xml"
    rules = build_panos_config(path.read_text()).security_rules
    assert [rule.name for rule in rules[:5]] == ["Pre-First", "Same-Name", "Allow-Basic", "Deny-Basic", "Drop-Rule"]


def test_nat_rule_source_order_is_preserved():
    config = build_panos_config("""<config><shared><rulebase><nat><rules>
      <entry name='nat-first'/><entry name='nat-second'/>
    </rules></nat></rulebase></shared></config>""")
    assert [rule.name for rule in config.nat_rules] == ["nat-first", "nat-second"]


def test_sdwan_rule_source_order_is_preserved():
    config = build_panos_config("""<config><shared><network><sdwan><rules>
      <entry name='sdwan-first'/><entry name='sdwan-second'/>
    </rules></sdwan></network></shared></config>""")
    assert [rule.name for rule in config.sdwan_rules] == ["sdwan-first", "sdwan-second"]


def test_panorama_effective_pre_and_post_rule_order_follows_device_group_hierarchy():
    config = build_panos_config("""<config>
      <shared>
        <pre-rulebase><security><rules><entry name='shared-pre'/></rules></security></pre-rulebase>
        <post-rulebase><security><rules><entry name='shared-post'/></rules></security></post-rulebase>
      </shared>
      <devices><entry name='panorama'><device-group>
        <entry name='parent'>
          <pre-rulebase><security><rules><entry name='parent-pre'/></rules></security></pre-rulebase>
          <post-rulebase><security><rules><entry name='parent-post'/></rules></security></post-rulebase>
        </entry>
        <entry name='child'>
          <parent-dg>parent</parent-dg>
          <pre-rulebase><security><rules><entry name='child-pre'/></rules></security></pre-rulebase>
          <post-rulebase><security><rules><entry name='child-post'/></rules></security></post-rulebase>
        </entry>
      </device-group></entry></devices>
    </config>""")

    child_scope = next(
        scope
        for scope in config.scopes
        if scope.kind == "device-group" and scope.name == "child"
    )
    target = pan_scope_identity(child_scope)
    order = [
        item.rule_name
        for item in build_derived_views(config).policy_order
        if item.target_scope == target
    ]

    assert order == [
        "shared-pre",
        "parent-pre",
        "child-pre",
        "child-post",
        "parent-post",
        "shared-post",
    ]


def test_managed_vsys_policy_order_uses_assigned_group_chain_and_marks_unknown_incomplete():
    config = build_panos_config("""<config><shared>
      <pre-rulebase><security><rules><entry name='shared-pre'/></rules></security></pre-rulebase>
      <post-rulebase><security><rules><entry name='shared-post'/></rules></security></post-rulebase>
      </shared><devices><entry name='panorama'><device-group>
        <entry name='parent'><pre-rulebase><security><rules><entry name='parent-pre'/></rules></security></pre-rulebase><post-rulebase><security><rules><entry name='parent-post'/></rules></security></post-rulebase></entry>
        <entry name='child'><parent-dg>parent</parent-dg><pre-rulebase><security><rules><entry name='child-pre'/></rules></security></pre-rulebase><post-rulebase><security><rules><entry name='child-post'/></rules></security></post-rulebase>
          <devices><entry name='SER-A'><vsys><entry name='vsys1'><rulebase><security><rules><entry name='local-rule'/></rules></security></rulebase></entry></vsys></entry></devices>
        </entry>
          </device-group></entry><entry name='standalone' serial='SER-B'><vsys><entry name='vsys1'><rulebase><security><rules><entry name='unknown-local'/></rules></security></rulebase></entry></vsys></entry>
        <entry name='pan-b'><device-group><entry name='missing-assignment'><devices><entry name='SER-C'><vsys><entry name='vsys1'><rulebase><security><rules><entry name='ambiguous-local'/></rules></security></rulebase></entry></vsys></entry></devices></entry></device-group></entry>
        </devices></config>""")
    scopes = list(config.scopes)
    managed = next(scope for scope in scopes if scope.kind == "vsys" and scope.device_group == "child")
    managed_id = pan_scope_identity(managed)
    entries = [item for item in build_derived_views(config).policy_order if item.target_scope == managed_id]
    assert [item.rule_name for item in entries] == ["shared-pre", "parent-pre", "child-pre", "local-rule", "child-post", "parent-post", "shared-post"]
    assert all(item.complete for item in entries)

    unknown = next(scope for scope in scopes if scope.kind == "vsys" and scope.device_group == "missing-assignment")
    unknown_id = pan_scope_identity(unknown)
    incomplete = [item for item in build_derived_views(config).policy_order if item.source_scope == unknown]
    assert incomplete and all(item.complete for item in incomplete)
    assert all(item.target_scope == unknown_id for item in incomplete)
