from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATTranslationMode, NATType


def test_dynamic_ip_nat_mode_is_distinct_from_pat():
    dynamic = IRNATRule(
        name="dynamic-ip",
        type=NATType.SOURCE,
        source=["inside-net"],
        destination=["any"],
        services=["any"],
        translated_sources=["public-pool"],
        source_translation_mode=NATTranslationMode.DYNAMIC_IP,
    )
    pat = dynamic.model_copy(update={
        "name": "dynamic-pat",
        "source_translation_mode": NATTranslationMode.DYNAMIC_IP_AND_PORT,
    })

    assert dynamic.source_translation_mode.value == "dynamic-ip"
    assert pat.source_translation_mode.value == "dynamic-ip-and-port"
    assert dynamic.model_dump(mode="json")["source_translation_mode"] == "dynamic-ip"
