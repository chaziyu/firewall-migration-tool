from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


PBF_FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "policy_families.xml"


def _extract(system: str):
    return PANOSSourceParser().extract(f"""
    <config><devices><entry name="pa-fw-01"><deviceconfig><system>
      {system}
    </system></deviceconfig></entry></devices></config>
    """)


def _residual(result, path):
    return [
        item for item in result.inventory_items
        if item.domain == "deviceconfig" and item.source_path == path
    ]


def _policy(rule: str, prefix: str = ""):
    return PANOSSourceParser().extract(f"""
    <config><devices><entry name="fw1"><vsys><entry name="vsys1">
      {prefix}<rulebase><security><rules>{rule}</rules></security></rulebase>
    </entry></vsys></entry></devices></config>
    """)


def test_unhandled_direct_system_child_is_retained_once():
    result = _extract(
        "<future-system-setting><mode>custom</mode></future-system-setting>"
    )

    records = _residual(result, "deviceconfig/system/future-system-setting")
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.UNSUPPORTED
    assert records[0].source_attributes["pan_source_entry"] == {
        "future-system-setting": {"mode": {"text": "custom"}}
    }
    section = next(
        section for section in result.source_sections
        if section.path == "deviceconfig/system/future-system-setting"
    )
    assert (section.object_count_source, section.object_count_parsed,
            section.object_count_normalized) == (1, 1, 0)


def test_phase10_system_child_is_not_duplicated_as_residual():
    result = _extract("<service><disable-ssh>yes</disable-ssh></service>")

    assert any(
        item.domain == "management_access"
        and item.source_path == "deviceconfig/system/service"
        for item in result.inventory_items
    )
    assert not _residual(result, "deviceconfig/system/service")


def test_hostname_remains_metadata_and_is_not_residualized():
    result = _extract("<hostname>pa-fw-01</hostname>")

    assert result.canonical_ir.metadata.hostname == "pa-fw-01"
    assert not _residual(result, "deviceconfig/system/hostname")


def test_handled_and_unhandled_system_siblings_have_separate_owners():
    result = _extract(
        "<service><disable-ssh>yes</disable-ssh></service>"
        "<future-system-setting><mode>custom</mode></future-system-setting>"
    )

    assert any(
        item.domain == "management_access"
        and item.source_path == "deviceconfig/system/service"
        for item in result.inventory_items
    )
    assert len(_residual(result, "deviceconfig/system/future-system-setting")) == 1
    assert not _residual(result, "deviceconfig/system/service")


def test_security_unknown_field_stays_with_policy_owner():
    result = _policy("""
      <entry name="Future-Security-Option">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action><future-security-option><mode>keep</mode></future-security-option>
      </entry>
    """)

    policy = result.canonical_ir.policies[0]
    assert "future-security-option" in policy.source_extra_settings["pan_unknown_fields"]
    assert "unknown-fields" in policy.review_reasons
    assert len([item for item in result.inventory_items if item.domain == "policies"]) == 1
    assert not any(item.domain == "policy:security" for item in result.inventory_items)


def test_qos_unknown_fields_stay_with_policy_owner():
    result = _policy("""
      <entry name="Future-QoS-Option">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action><qos><marking><ip-dscp>ef</ip-dscp>
          <future-marking><value>keep-marking</value></future-marking>
        </marking><future-qos-option><value>keep-qos</value></future-qos-option></qos>
      </entry>
    """)

    policy = result.canonical_ir.policies[0]
    settings = policy.source_extra_settings
    assert settings["pan_qos_ip_dscp"] == "ef"
    assert "future-qos-option" in settings["pan_unknown_qos_fields"]
    assert "future-marking" in settings["pan_unknown_qos_marking_fields"]
    assert "unknown-qos-fields" in policy.review_reasons
    assert not any(item.domain == "policy:security" for item in result.inventory_items)


def test_pbf_unknown_nested_field_stays_with_pbf_owner():
    result = PANOSSourceParser().extract(PBF_FIXTURE.read_text(encoding="utf-8"))
    records = [
        item for item in result.inventory_items
        if item.domain == "policy:pbf" and item.name == "pbf-unknown-field"
    ]

    assert len(records) == 1
    assert records[0].source_attributes["pan_unknown_pbf_forward_fields"] == {
        "future-forward-option": "keep"
    }
    assert not any(
        item.domain == "policy"
        and "pbf-unknown-field" in item.source_path
        for item in result.inventory_items
    )


def test_management_profile_unknown_field_stays_with_management_owner():
    result = PANOSSourceParser().extract("""
    <config><devices><entry name="fw1"><network><profiles>
      <interface-management-profile><entry name="mgmt-profile">
        <ssh>yes</ssh><future-profile-setting><mode>keep</mode></future-profile-setting>
      </entry></interface-management-profile>
    </profiles></network></entry></devices></config>
    """)
    records = [
        item for item in result.inventory_items
        if item.domain == "management_access" and item.name == "mgmt-profile"
    ]

    assert len(records) == 1
    assert "future-profile-setting" in records[0].source_attributes[
        "pan_management_profile_unknown_fields"
    ]
    assert not any(
        item.domain == "network"
        and item.source_path.startswith("network/profiles/interface-management-profile")
        for item in result.inventory_items
    )


def test_phase10_service_unknown_field_stays_with_management_owner():
    result = _extract(
        "<service><disable-ssh>yes</disable-ssh>"
        "<future-service-control><mode>custom</mode></future-service-control></service>"
    )
    records = [
        item for item in result.inventory_items
        if item.domain == "management_access"
        and item.source_path == "deviceconfig/system/service"
    ]

    assert len(records) == 1
    assert records[0].source_attributes[
        "pan_system_management_service_disable"
    ]["disable-ssh"] is True
    assert "future-service-control" in records[0].source_attributes[
        "pan_system_management_unknown_service_fields"
    ]
    assert not _residual(result, "deviceconfig/system/service")
