from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_identity_xml_reaches_typed_users_groups_and_mappings():
    config = build_panos_config("""<config><shared>
      <local-user><entry name='alice'><disabled>no</disabled><password>secret</password></entry></local-user>
      <local-user-group><entry name='admins'><members><member>alice</member></members></entry></local-user-group>
      <group-mapping><entry name='ldap-groups'><server-profile>ldap-main</server-profile><disabled>no</disabled></entry></group-mapping>
    </shared></config>""")

    user = config.local_users[0]
    group = config.local_user_groups[0]
    mapping = config.group_mappings[0]
    assert user.name == "alice"
    assert user.password_configured is True
    assert group.name == "admins"
    assert group.members == ["alice"]
    assert mapping.name == "ldap-groups"
    assert mapping.server_profile == "ldap-main"


def test_admin_xml_reaches_typed_administrators_and_roles():
    config = build_panos_config("""<config><shared>
      <administrators><entry name='admin'><role-type>custom</role-type><custom-admin-role>operator</custom-admin-role><password>secret</password></entry></administrators>
      <admin-role><entry name='operator'><role-scope>device</role-scope><permissions><entry><channel>web</channel><permission-path>network</permission-path><setting>read</setting></entry></permissions></entry></admin-role>
    </shared></config>""")

    administrator = config.administrators[0]
    role = config.admin_roles[0]
    assert administrator.name == "admin"
    assert administrator.role_type == "custom"
    assert administrator.custom_admin_role == "operator"
    assert administrator.password_configured is True
    assert role.name == "operator"
    assert role.role_scope == "device"
    assert role.permissions[0].permission_path == "network"


def test_admin_role_missing_and_empty_permissions_preserve_source_presence():
    config = build_panos_config("""<config><shared><admin-role>
      <entry name='missing'/><entry name='empty'><permissions/></entry>
    </admin-role></shared></config>""")

    missing, empty = config.admin_roles
    assert missing.permissions is None
    assert "permissions" not in missing.explicit_fields
    assert empty.permissions == []
    assert "permissions" in empty.explicit_fields


def test_identity_admin_unknown_source_is_retained_separately():
    config = build_panos_config("<config><shared><administrators><entry name='admin'><future-setting>retain-me</future-setting></entry></administrators></shared></config>")
    assert config.source_inventory
    assert config.administrators[0].raw_extra["future-setting"] == "retain-me"
