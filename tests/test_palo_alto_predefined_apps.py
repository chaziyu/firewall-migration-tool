from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(custom_ssl=False):
    ssl_object = "<entry name='ssl'><category>custom</category></entry>" if custom_ssl else ""
    xml = f"""<config><devices><entry name='fw1'><vsys><entry name='vsys1'>
      <application>{ssl_object}<entry name='custom-app'><category>business-systems</category></entry></application>
      <application-group><entry name='app-group'><members><member>custom-app</member></members></entry></application-group>
      <application-filter><entry name='app-filter'><category><member>business-systems</member></category></entry></application-filter>
      <rulebase><security><rules><entry name='apps'><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>ssl</member><member>web-browsing</member><member>custom-app</member><member>app-group</member><member>app-filter</member><member>web-browsng</member></application>
        <service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase>
    </entry></vsys></entry></devices></config>"""
    return PANOSSourceParser().extract(xml)


def _classifications(result):
    policy = next(policy for policy in result.canonical_ir.policies if policy.name == "apps")
    return {item["original_name"]: item for item in
            policy.source_extra_settings["pan_application_reference_classification"]}


def test_predefined_custom_group_filter_and_unknown_references_are_distinguished():
    result = _extract()
    states = {name: value["classification"] for name, value in _classifications(result).items()}
    assert states == {
        "ssl": "PREDEFINED_REFERENCE", "web-browsing": "PREDEFINED_REFERENCE",
        "custom-app": "CUSTOM_RESOLVED", "app-group": "APPLICATION_GROUP_RESOLVED",
        "app-filter": "APPLICATION_FILTER_REFERENCE", "web-browsng": "UNKNOWN_REFERENCE",
    }


def test_original_names_are_preserved_and_no_app_metadata_is_fabricated():
    result = _extract()
    classifications = _classifications(result)
    assert all(name == item["original_name"] for name, item in classifications.items())
    predefined = classifications["ssl"]
    assert set(predefined) == {"original_name", "classification", "resolved_name", "resolved_scope"}
    policy = result.canonical_ir.policies[0]
    assert policy.source_extra_settings["pan_unresolved_applications"] == ["web-browsng"]


def test_configured_custom_name_takes_precedence_over_predefined_classifier():
    states = _classifications(_extract(custom_ssl=True))
    assert states["ssl"]["classification"] == "CUSTOM_RESOLVED"
    assert states["ssl"]["resolved_scope"] == "vsys:vsys1"
