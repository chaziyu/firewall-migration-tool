from fwmigrate.parsers.palo_alto import PANOSSourceParser

def test_pan_logging_is_source_only_and_secret_safe():
    xml = '<config><shared><log-settings><syslog><entry name="s"><server><entry name="x"><address>1.2.3.4</address><community>SECRET</community></entry></server></entry></syslog></log-settings></shared></config>'
    ir = PANOSSourceParser().extract(xml).canonical_ir
    assert ir.pan_log_server_profiles[0].migration_status == "EXTRACT_ONLY"
    assert "SECRET" not in str(ir.model_dump())
