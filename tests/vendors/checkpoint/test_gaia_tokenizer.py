from fwmigrate.vendors.checkpoint.gaia.parser import parse_gaia
from fwmigrate.vendors.checkpoint.gaia.tokenizer import GaiaTokenType, tokenize_gaia


def test_tokenizer_preserves_quotes_comments_and_lines():
    tokens = tokenize_gaia('# header\nset user admin real-name "Admin User" # tail\n')
    assert tokens[0][0].type is GaiaTokenType.COMMENT
    assert tokens[1][4].value == "Admin User"
    assert tokens[1][0].line_number == 2


def test_tokenizer_preserves_malformed_syntax_as_evidence():
    tokens = tokenize_gaia('set user admin real-name "unterminated\n')
    assert tokens[0][0].type is GaiaTokenType.UNKNOWN
    assert "malformed syntax" in tokens[0][0].value


def test_parser_keeps_variable_grammar_structural():
    tree = parse_gaia("set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.1 on\n")
    assert tree.commands[0].operation == "set"
    assert tree.commands[0].arguments == ("static-route", "10.0.0.0/8", "nexthop", "gateway", "address", "192.0.2.1", "on")
