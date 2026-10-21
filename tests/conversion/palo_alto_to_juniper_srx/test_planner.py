from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from fwmigrate.conversion.palo_alto_to_juniper_srx import PaloAltoToJuniperSRXPlanner
from fwmigrate.conversion.palo_alto_to_juniper_srx.options import SRXInterfaceMapping, SRXMigrationOptions
from fwmigrate.conversion.palo_alto_to_juniper_srx.rendering.renderer import JunosSetRenderer
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "all_targets_explicit.xml"


def _analyze(xml=None):
    return PaloAltoSourceReporter().analyze_source(
        xml if xml is not None else FIXTURE.read_text(encoding="utf-8")
    )


def _options(analysis):
    scope = next(row for row in analysis.config.scopes if row.kind == "vsys")
    return SRXMigrationOptions(
        source_scope=pan_scope_identity(scope),
        interfaces={
            "ethernet1/1": SRXInterfaceMapping("ge-0/0/0"),
            "ethernet1/2": SRXInterfaceMapping("ge-0/0/1"),
        },
        zones={"inside": "inside", "outside": "outside"},
    )


def test_pan_os_scope_objects_services_inactive_nat_and_policy_order_fail_closed():
    analysis = _analyze()
    before = deepcopy(analysis.config.model_dump(mode="json"))
    source_digest = sha256(repr(before).encode()).hexdigest()
    plan = PaloAltoToJuniperSRXPlanner().plan(analysis.config, analysis.derived, _options(analysis))

    assert {row.family for row in plan.items} >= {
        "address", "address_group", "service", "service_group", "interface", "zone", "policy", "inactive_policy", "inactive_nat",
    }
    app_id_deny = next(row for row in plan.items if row.source_name == "deny-app-before-allow")
    later_allow = next(row for row in plan.items if row.source_name == "allow-inside-services")
    assert "PAN_APP_ID_IS_NOT_A_JUNOS_TRANSPORT_APPLICATION" in app_id_deny.blockers
    assert "EARLIER_POLICY_IN_CONTEXT_UNSUPPORTED" in later_allow.blockers
    inactive_nat = next(row for row in plan.items if row.family == "inactive_nat")
    assert "SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED" in inactive_nat.blockers
    inactive_policy = next(row for row in plan.items if row.family == "inactive_policy" and row.source_name == "disabled-predecessor")
    assert "SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED" in inactive_policy.blockers
    assert analysis.config.model_dump(mode="json") == before
    assert sha256(repr(analysis.config.model_dump(mode="json")).encode()).hexdigest() == source_digest


def test_supported_policy_renders_exact_junos_transport_and_zone_commands():
    xml = """<config version='11.1.0'><devices><entry name='fw'><vsys><entry name='vsys1'>
      <address><entry name='inside-net'><ip-netmask>10.1.0.0/24</ip-netmask></entry></address>
      <service><entry name='web'><protocol><tcp><port>443</port></tcp></protocol></entry></service>
      <rulebase><security><rules><entry name='allow-web'><from><member>inside</member></from><to><member>outside</member></to>
      <source><member>inside-net</member></source><destination><member>any</member></destination><source-user><member>any</member></source-user>
      <application><member>any</member></application><service><member>web</member></service><category><member>any</member></category>
      <negate-source>no</negate-source><negate-destination>no</negate-destination><action>allow</action><rule-type>universal</rule-type><log-start>no</log-start><log-end>no</log-end><disabled>no</disabled><schedule>always</schedule>
      </entry></rules></security></rulebase><zone><entry name='inside'><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name='outside'><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone>
      </entry></vsys><network><interface><ethernet><entry name='ethernet1/1'><layer3><ip><entry name='10.1.0.1/24'/></ip></layer3></entry>
      <entry name='ethernet1/2'><layer3><ip><entry name='192.0.2.1/24'/></ip></layer3></entry></ethernet></interface></network></entry></devices></config>"""
    analysis = _analyze(xml)
    options = _options(analysis)
    plan = PaloAltoToJuniperSRXPlanner().plan(analysis.config, analysis.derived, options)
    rendered = JunosSetRenderer().render(plan)

    policy = next(row for row in plan.items if row.family == "policy")
    assert policy.blockers == ()
    assert "set applications application web destination-port 443" in rendered.commands
    assert "set security policies from-zone inside to-zone outside policy allow-web then permit" in rendered.commands
    assert not rendered.blocked_items
    assert len(rendered.command_sha256) == 64


def test_source_scope_ambiguity_and_active_nat_block_rendering():
    analysis = _analyze()
    wrong = SRXMigrationOptions(source_scope="vsys:missing")
    assert PaloAltoToJuniperSRXPlanner().plan(analysis.config, analysis.derived, wrong).items == ()

    xml = """<config><devices><entry name='fw'><vsys><entry name='vsys1'><rulebase><nat><rules>
      <entry name='active'><destination-translation><translated-address>10.0.0.1</translated-address></destination-translation></entry>
      </rules></nat></rulebase></entry></vsys></entry></devices></config>"""
    active = _analyze(xml)
    selected = next(row for row in active.config.scopes if row.kind == "vsys")
    options = SRXMigrationOptions(source_scope=pan_scope_identity(selected))
    plan = PaloAltoToJuniperSRXPlanner().plan(active.config, active.derived, options)
    assert any("ACTIVE_OR_UNKNOWN_NAT_UNSUPPORTED" in row.blockers for row in plan.items)
