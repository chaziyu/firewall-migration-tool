import pytest

from fwmigrate.parsers.fortigate.tokenizer import (
    FortiGateTokenizer,
    TokenType,
)


@pytest.mark.parametrize(
    ("field", "marker"),
    [
        ("certificate", "CERTIFICATE"),
        ("remote", "CERTIFICATE"),
        ("private-key", "ENCRYPTED PRIVATE KEY"),
    ],
)
def test_multiline_quoted_values_are_one_logical_set_command(
    field: str,
    marker: str,
) -> None:
    config = f'''config vpn certificate local
    edit "example"
        set {field} "-----BEGIN {marker}-----
AAAA
BBBB
-----END {marker}-----"
        set range global
    next
end
'''

    tokens = list(FortiGateTokenizer(config).tokenize())
    field_index = next(
        index
        for index, token in enumerate(tokens)
        if (
            token.type == TokenType.STRING
            and token.value == field
            and tokens[index - 1].type == TokenType.SET
        )
    )

    value = tokens[field_index + 1]
    assert value.type == TokenType.STRING
    assert value.value == (
        f"-----BEGIN {marker}-----\n"
        "AAAA\n"
        "BBBB\n"
        f"-----END {marker}-----"
    )
    assert value.line_number == 3

    range_index = next(
        index
        for index, token in enumerate(tokens)
        if token.type == TokenType.STRING and token.value == "range"
    )
    assert tokens[range_index + 1].value == "global"
    assert any(token.type == TokenType.NEXT for token in tokens)
    assert tokens[-1].type == TokenType.END


def test_normal_single_line_values_are_unchanged() -> None:
    config = '''set member "a" "b"
set subnet 10.0.0.0 255.255.255.0
set comment "some comment"
'''

    tokens = list(FortiGateTokenizer(config).tokenize())
    strings = [token.value for token in tokens if token.type == TokenType.STRING]

    assert strings == [
        "member",
        "a",
        "b",
        "subnet",
        "10.0.0.0",
        "255.255.255.0",
        "comment",
        "some comment",
    ]
