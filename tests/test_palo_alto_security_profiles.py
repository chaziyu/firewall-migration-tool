from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.report.excel_exporter import IRExcelExporter
from openpyxl import load_workbook
import io


XML = """
<config version="10.2.0"><vsys><entry name="vsys1"><profiles>
  <file-blocking><entry name="monitor"><rules><entry><name>Monitor mode</name><application><member>any</member></application><file-type><member>any</member></file-type><direction>both</direction><action><alert/></action></entry></rules><future><x>kept</x></future></entry></file-blocking>
  <url-filtering><entry name="web"><allow><member>allow-custom</member></allow><block><member>malware</member></block><credential-enforcement><mode><domain-credentials/></mode><log-severity>informational</log-severity><block><member>adult</member></block></credential-enforcement><log-http-hdr-xff>yes</log-http-hdr-xff></entry></url-filtering>
  <vulnerability><entry name="strict"><rules><entry><name>r1</name><action><reset-both/></action><severity><member>high</member></severity><host>client</host><packet-capture>disable</packet-capture></entry></rules></entry></vulnerability>
  <custom-url-category><entry name="allow-custom"><type>URL List</type><list><member>example.org</member></list></entry></custom-url-category>
</profiles><profile-group><entry name="Incoming Protection"><vulnerability><member>strict</member></vulnerability></entry></profile-group></entry></vsys></config>
"""


def test_security_profiles_are_typed_and_keep_references_separate():
    extraction = PANOSSourceParser().extract(XML)
    ir = extraction.canonical_ir
    assert [item.name for item in ir.security_profile_definitions] == ["monitor", "web", "strict"]
    assert ir.security_profile_definitions[0].rules[0].action == "alert"
    assert ir.security_profile_definitions[1].credential_enforcement.mode == "domain-credentials"
    assert ir.security_profile_definitions[1].source_attributes["pan_custom_url_category_references"] == ["allow-custom"]
    assert ir.security_profile_definitions[2].rules[0].action == "reset-both"
    assert ir.custom_url_categories[0].entries == ["example.org"]
    assert ir.security_profile_definitions[0].source_attributes["pan_profile_settings"]
    assert len(ir.security_profile_groups) == 1
    assert ir.security_profile_groups[0].vulnerability == "strict"
    assert all(item.migration_status == "EXTRACT_ONLY" for item in ir.security_profile_definitions)


def test_security_profile_excel_sheets_are_additive():
    ir = PANOSSourceParser().extract(XML).canonical_ir
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    assert workbook["Security Profiles"][4][0].value == "Incoming Protection"
    assert workbook["Security Profile Definitions"][4][0].value == "monitor"
    assert workbook["Security Profile Rules"][4][0].value == "monitor"
    assert workbook["Custom URL Categories"][4][0].value == "allow-custom"


def test_same_profile_name_is_kept_separate_by_family():
    xml = XML.replace(
        "</profiles>",
        '<spyware><entry name="strict"><description>different family</description></entry></spyware></profiles>',
    )
    definitions = PANOSSourceParser().extract(xml).canonical_ir.security_profile_definitions
    assert {(item.family, item.name) for item in definitions} >= {
        ("vulnerability", "strict"), ("anti-spyware", "strict")
    }
