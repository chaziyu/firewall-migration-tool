from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_admin_user_references_login_class():
    c = JuniperSRXParser("""
    set system login class readonly permissions view
    set system login user alice class readonly
    """).parse_raw()
    assert c.admin_users["alice"].login_class == "readonly"
    assert c.login_classes["readonly"].settings
    assert not c.admin_users["alice"].settings
