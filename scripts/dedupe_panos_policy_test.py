from pathlib import Path

path = Path("tests/test_multi_vendor_matrix.py")
text = path.read_text(encoding="utf-8")
needle = '''def test_palo_alto_generator_applies_target_defaults_for_partial_ir_profiles():\n    """Verify that IR with partial profiles receives target-required defaults from PAN-OS transformer."""\n    ir = IRConfig(\n        metadata=IRMetadata(hostname="HQ-FW", source_vendor="fortigate"),\n        policies=[\n            IRPolicy(\n                name="Allow_Web",\n                from_zone=["trust"],\n                to_zone=["untrust"],\n                source=["any"],\n                destination=["any"],\n                service=["any"],\n                action=PolicyAction.ALLOW,\n                security_profile_group="SPG_IPS_default",\n                ips_sensor="default",\n                antivirus=None,\n                webfilter=None,\n            )\n        ],\n        security_profile_groups=[\n            IRSecurityProfileGroup(\n                name="SPG_IPS_default",\n                vulnerability="default",\n                antivirus=None,\n                anti_spyware=None,\n                url_filtering=None,\n                file_blocking=None,\n                wildfire=None,\n                ssl_decryption="certificate-inspection",\n            )\n        ],\n    )\n\n    pa_gen = PluginRegistry.get_generator("palo_alto")\n    artifacts = pa_gen.generate(ir, format="xml")\n    xml_content = artifacts[0].content\n\n\n'''
count = text.count(needle)
if count != 1:
    raise RuntimeError(f"expected exactly one incomplete duplicate test block, found {count}")
path.write_text(text.replace(needle, "", 1), encoding="utf-8")
print("Removed incomplete duplicate PAN-OS generator regression test")
