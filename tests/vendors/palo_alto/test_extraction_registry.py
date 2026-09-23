from fwmigrate.vendors.palo_alto.extraction.extractor import registered_typed_collections
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_registered_collections_are_unique_and_initialized():
    names = list(registered_typed_collections())
    assert len(names) == len(set(names))
    config = build_panos_config("<config><shared/></config>")
    assert all(hasattr(config, name) for name in names)
