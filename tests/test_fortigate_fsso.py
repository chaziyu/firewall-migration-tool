from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


SYSTEM_SECRET = "SYSTEM_FSSO_PASSWORD_SENTINEL"
USER_SECRET = "USER_FSSO_PASSWORD_SENTINEL"


FSSO_CONFIG = f'''config user fsso-polling
    edit "dc-poller"
        set status enable
        set server "192.0.2.10"
        set port 445
        set user "EXAMPLE\\svc-fsso"
        set password "{USER_SECRET}"
        config adgrp
            edit "Domain Users"
                set server-name "dc-poller"
            next
            edit "Firewall Admins"
                set server-name "dc-poller"
            next
        end
    next
end
config system fsso-polling
    set status enable
    set listening-port 8000
    set authentication enable
    set auth-password "{SYSTEM_SECRET}"
end
'''


def test_user_and_system_fsso_polling_are_typed_independently() -> None:
    parsed = parse_fortigate_config(FSSO_CONFIG)

    assert len(parsed.fsso_polling) == 1
    user_polling = parsed.fsso_polling[0]
    assert user_polling.name == "dc-poller"
    assert user_polling.server == "192.0.2.10"
    assert user_polling.port == 445
    assert user_polling.has_password is True
    assert [group.name for group in user_polling.ad_groups] == [
        "Domain Users",
        "Firewall Admins",
    ]

    system_polling = parsed.system_fsso_polling
    assert system_polling is not None
    assert system_polling.status == "enable"
    assert system_polling.listening_port == 8000
    assert system_polling.authentication == "enable"
    assert system_polling.has_auth_password is True
    assert system_polling.source_explicit_fields == {
        "status",
        "listening_port",
        "authentication",
        "auth_password",
    }

    serialized = parsed.model_dump_json()
    assert SYSTEM_SECRET not in serialized
    assert USER_SECRET not in serialized


def test_system_fsso_polling_preserves_redacted_recursive_source_evidence() -> None:
    parsed = parse_fortigate_config(FSSO_CONFIG)

    source_object = next(
        item
        for item in parsed.structured_source_objects
        if item.source_path == "system fsso-polling"
    )
    commands = {
        command.key: command.values
        for command in source_object.root.commands
    }

    assert commands["auth-password"] == ["[REDACTED]"]
    assert SYSTEM_SECRET not in source_object.model_dump_json()


def test_system_fsso_polling_retains_malformed_port_and_unknown_fields() -> None:
    parsed = parse_fortigate_config('''config system fsso-polling
    set status enable
    set listening-port not-a-port
    set authentication disable
    set future-setting preserve-me
end
''')

    system_polling = parsed.system_fsso_polling
    assert system_polling is not None
    assert system_polling.listening_port is None
    assert system_polling.extra_settings == {
        "future_setting": "preserve-me",
        "unparsed_listening_port": "not-a-port",
    }


def test_system_fsso_polling_unset_clears_secret_presence() -> None:
    parsed = parse_fortigate_config(f'''config system fsso-polling
    set auth-password "{SYSTEM_SECRET}"
    unset auth-password
end
''')

    system_polling = parsed.system_fsso_polling
    assert system_polling is not None
    assert system_polling.has_auth_password is False
    assert SYSTEM_SECRET not in parsed.model_dump_json()


def test_system_fsso_polling_is_typed_extract_only_and_secret_safe() -> None:
    result = extract_fortigate_config(FSSO_CONFIG)
    section = next(
        item
        for item in result.source_sections
        if item.path == "system fsso-polling"
    )

    assert section.status == ExtractionStatus.EXTRACT_ONLY
    assert section.parser_handler == "FortiGateParser._build_structured_typed_parents"
    assert section.object_count_source == 1
    assert section.object_count_parsed == 1
    assert section.object_count_normalized is None
    assert "TYPED_EXTRACT_ONLY" in " ".join(section.notes)

    serialized = result.model_dump_json()
    assert SYSTEM_SECRET not in serialized
    assert USER_SECRET not in serialized
