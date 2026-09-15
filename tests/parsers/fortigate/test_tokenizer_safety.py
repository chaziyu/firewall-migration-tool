import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.tokenizer import (
    FortiGateTokenizer,
    TokenType,
    TokenizerError,
)


@pytest.mark.parametrize("keyword", ["select", "SELECT", "Select"])
def test_select_mutation_command_is_rejected(keyword: str) -> None:
    text = f"\n{keyword} member \"A\"\n"

    with pytest.raises(
        TokenizerError,
        match=r"Unsupported FortiOS mutation command 'select' at line 2",
    ):
        list(FortiGateTokenizer(text).tokenize())


def test_parser_propagates_select_rejection() -> None:
    text = """config firewall addrgrp
    edit "group-a"
        select member "host-a"
    next
end
"""

    with pytest.raises(TokenizerError, match="expected show full-configuration input"):
        parse_fortigate_config(text)


def test_select_as_object_name_or_value_is_not_rejected() -> None:
    text = """config firewall address
    edit "select"
        set comment "select member A"
    next
end
"""

    tokens = list(FortiGateTokenizer(text).tokenize())

    assert any(
        token.type == TokenType.STRING and token.value == "select"
        for token in tokens
    )
    assert any(
        token.type == TokenType.STRING and token.value == "select member A"
        for token in tokens
    )


def test_append_tokenization_is_unchanged() -> None:
    tokens = list(
        FortiGateTokenizer('append member "A" "B"').tokenize()
    )

    assert [token.type for token in tokens] == [
        TokenType.APPEND,
        TokenType.STRING,
        TokenType.STRING,
        TokenType.STRING,
    ]
    assert [token.value for token in tokens[1:]] == ["member", "A", "B"]


def test_multiline_quoted_value_containing_select_is_not_rejected() -> None:
    text = 'set comment "first line\nselect member A\nlast line"'

    tokens = list(FortiGateTokenizer(text).tokenize())

    assert tokens[0].type == TokenType.SET
    assert tokens[1].value == "comment"
    assert tokens[2].value == "first line\nselect member A\nlast line"
