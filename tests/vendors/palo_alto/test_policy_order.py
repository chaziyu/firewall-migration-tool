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
