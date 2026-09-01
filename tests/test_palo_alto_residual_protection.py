from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


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
