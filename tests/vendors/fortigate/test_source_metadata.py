from fwmigrate.vendors.fortigate.extraction.source_metadata import capture_source_metadata
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config


def test_capture_source_metadata_from_config_version_header():
    tree = parse_fortigate_config(
        "# unrelated\n"
        "#config-version=FG100E-7.2.13-FW-build1762-260128:opmode=0:vdom=0\n"
    )

    assert capture_source_metadata(tree).fortios_version == "7.2.13"


def test_capture_source_metadata_rejects_missing_or_malformed_header():
    for source in (
        "# unrelated\n",
        "#config-version=FG100E-7.2.13-build1762\n",
        "#config-version=7.2.13\n",
    ):
        assert capture_source_metadata(
            parse_fortigate_config(source)
        ).fortios_version is None

