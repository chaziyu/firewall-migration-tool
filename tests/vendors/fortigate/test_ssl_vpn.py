from fwmigrate.vendors.fortigate.config import ExtractionConfig
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.export import export_excel
from fwmigrate.vendors.fortigate.extraction.coverage import typed_source_paths
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.section_registry import registered_sections
from fwmigrate.vendors.fortigate.validation.validator import validate_config


def test_ssl_vpn_realms_and_clients_keep_explicit_source_state():
    source = """config vpn ssl web realm
    edit /partner
        set login-page <html>custom login page</html>
        set radius-server radius1
        set radius-port 1812
        set virtual-host-only enable
    next
end
config vpn ssl client
    edit remote
        set server vpn.example.test
        set psk never-export-this
        set status enable
    next
end
"""
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    realm = analysis.extracted.config.ssl_vpn_realms[0]
    client = analysis.extracted.config.ssl_vpn_clients[0]
    assert realm.url_path == "/partner"
    assert realm.radius_port == 1812
    assert client.psk_configured
    assert "vpn ssl web realm" in typed_source_paths()
    assert "vpn ssl client" in typed_source_paths()

def test_ssl_vpn_user_and_group_bookmarks_keep_nested_source_fields():
    source = """config vpn ssl web user-bookmark
    edit alice
        set custom-lang en
        config bookmarks
            edit app
                set apptype rdp
                set host 192.0.2.20
                set logon-user alice
                set logon-password never-export-bookmark-secret
                set sso-password another-never-export-secret
                config form-data
                    edit token
                        set value form-field
                    next
                end
            next
        end
    next
end
config vpn ssl web user-group-bookmark
    edit remote-users
        config bookmarks
            edit web
                set apptype web
                set url https://example.test
            next
        end
    next
end
"""
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    user_bookmark = analysis.extracted.config.ssl_vpn_user_bookmarks[0].bookmarks[0]
    group_bookmark = analysis.extracted.config.ssl_vpn_user_group_bookmarks[0].bookmarks[0]
    assert user_bookmark.form_data[0].value == "form-field"
    assert user_bookmark.logon_password_configured and user_bookmark.sso_password_configured
    assert group_bookmark.apptype == "web"
    assert "vpn ssl web user-bookmark bookmarks form-data" in typed_source_paths()
