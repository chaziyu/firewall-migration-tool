from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _interface(password=""):
    return f'''\
config system interface
    edit "wan1"
        set mode pppoe
        set username "test-user"
{password}    next
    end
'''


def test_pppoe_password_metadata_is_safe_and_redacted():
    for password, expected_format, secret in (
        ('        set password ENC SuperSecretEncryptedBlob\n', "encrypted", "SuperSecretEncryptedBlob"),
        ('        set password ActualPlaintextSecret\n', "plaintext", "ActualPlaintextSecret"),
    ):
        parsed = parse_fortigate_config(_interface(password))
        interface = parsed.interfaces[0]
        assert interface.has_pppoe_password is True
        assert interface.pppoe_password_format == expected_format
        assert interface.source_attributes["password"] == "[REDACTED]"
        assert secret not in str(interface.model_dump())

        extracted = extract_fortigate_config(_interface(password))
        assert secret not in str(extracted.model_dump())
        ir = FGToIRTransformer(parsed).transform()
        assert ir.interfaces[0].requires_manual_review is False


def test_pppoe_password_absence_is_explicit_false():
    interface = parse_fortigate_config(_interface()).interfaces[0]

    assert interface.has_pppoe_password is False
    assert interface.pppoe_password_format is None


def test_pppoe_password_metadata_reaches_ir_without_secret():
    ir = FGToIRTransformer(
        parse_fortigate_config(_interface('        set password ENC SecretBlob\n'))
    ).transform()

    interface = ir.interfaces[0]
    assert interface.has_pppoe_password is True
    assert interface.pppoe_password_format == "encrypted"
    assert "SecretBlob" not in str(ir.model_dump())
