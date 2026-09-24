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


def test_selected_identity_roots_group_mapping_names_and_phash_redaction():
    config = build_panos_config("""<config><shared>
      <mgt-config><users><entry name='ops'><permissions><role-based><deviceadmin>yes</deviceadmin></role-based></permissions><password>ADMIN-SECRET</password></entry></users></mgt-config>
      <local-user-database><user><entry name='alice'><phash>HASH-SECRET</phash></entry></user>
        <user-group><entry name='admins'><user><member>alice</member></user></entry></user-group></local-user-database>
      <group-mapping><entry name='ldap'><use-ldap-for-serialno-check>yes</use-ldap-for-serialno-check>
        <group-object><member>objectClass</member></group-object><group-member><member>member</member></group-member><group-name><member>cn</member></group-name>
        <user-object><member>person</member></user-object><user-name><member>uid</member></user-name><user-email><member>mail</member></user-email><group-email><member>groupMail</member></group-email>
        <alternate-user-name-1>uid</alternate-user-name-1><alternate-user-name-2>mail</alternate-user-name-2><alternate-user-name-3>cn</alternate-user-name-3>
        <container-object><member>organizationalUnit</member></container-object><last-modify-attr>modifyTimestamp</last-modify-attr><group-include-list><member>CN=NetOps</member></group-include-list>
      </entry></group-mapping>
    </shared></config>""")
    admin, = config.administrators
    user, = config.local_users
    group, = config.local_user_groups
    mapping, = config.group_mappings
    assert (admin.role_type, admin.built_in_role, admin.password_configured) == ("built-in", "deviceadmin", True)
    assert user.password_configured is True and "HASH-SECRET" not in config.model_dump_json()
    assert group.members == ["alice"]
    assert mapping.ldap_serial_number_check == "yes"
    assert mapping.group_object_attributes == ["objectClass"]
    assert mapping.group_member_attributes == ["member"]
    assert mapping.group_name_attributes == ["cn"]
    assert mapping.user_object_attributes == ["person"]
    assert mapping.user_name_attributes == ["uid"]
    assert mapping.user_email_attributes == ["mail"]
    assert mapping.group_email_attributes == ["groupMail"]
    assert mapping.alternate_username_1 == "uid" and mapping.alternate_username_3 == "cn"
    assert mapping.container_object_attributes == ["organizationalUnit"]
    assert mapping.last_modify_attribute == "modifyTimestamp"
    assert mapping.group_include_list == ["CN=NetOps"]
    assert "ADMIN-SECRET" not in config.model_dump_json()


def test_admin_custom_role_subtree_is_preserved_without_guessing_profile_leaf():
    config = build_panos_config("""<config><shared><mgt-config><users><entry name='ops'>
      <permissions><role-based><custom><role-profile>ops-profile</role-profile></custom></role-based></permissions>
    </entry></users></mgt-config></shared></config>""")
    admin, = config.administrators
    assert admin.role_type == "custom"
    assert admin.custom_admin_role is None
    assert admin.raw_extra["permissions"]["role-based"]["custom"]["role-profile"] == "ops-profile"


def test_selected_admin_role_nested_channel_permissions_keep_order_and_values():
    config = build_panos_config("""<config><shared><admin-role><entry name='ops'><role><device>
      <webui><policies><security>read-only</security></policies></webui>
      <xmlapi><objects><addresses>enable</addresses></objects></xmlapi>
      <restapi><network><interfaces>disable</interfaces></network></restapi>
      <cli><config>read-only</config></cli>
    </device></role></entry></admin-role></shared></config>""")
    role, = config.admin_roles
    assert role.role_scope == "device"
    assert [(item.channel, item.permission_path, item.setting, item.value) for item in role.permissions] == [
        ("webui", "policies", "security", "read-only"),
        ("xmlapi", "objects", "addresses", "enable"),
        ("restapi", "network", "interfaces", "disable"),
        ("cli", None, "config", "read-only"),
    ]
