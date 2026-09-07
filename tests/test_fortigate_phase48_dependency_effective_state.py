from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_profile_group_dependencies_ignore_replaced_and_unset_references() -> None:
    result = extract_fortigate_config('''
config firewall profile-group
    edit "corp"
        set av-profile "old-av"
        set av-profile "new-av"
        set cifs-profile "old-cifs"
        unset cifs-profile
    next
end
''')

    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall profile-group"
        and dependency.source_object == "corp"
    ]

    assert [
        (dependency.source_field, dependency.reference)
        for dependency in dependencies
    ] == [("av-profile", "new-av")]

    group = result.canonical_ir.security_profile_groups[0]
    assert group.source_profile_references["av_profile"] == "new-av"
    assert "cifs_profile" not in group.source_profile_references
