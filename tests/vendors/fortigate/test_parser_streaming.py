import shlex

import pytest

from fwmigrate.vendors.fortigate.nodes import UnknownCommandNode
from fwmigrate.vendors.fortigate.parser import (
    FortiGateParser,
    ParserError,
    parse_fortigate_config,
)
from fwmigrate.vendors.fortigate.tokenizer import (
    FortiGateTokenizer,
    TokenType,
)


def test_simple_commands_use_split_without_changing_tokens(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("shlex should not run for simple commands")

    monkeypatch.setattr("fwmigrate.vendors.fortigate.tokenizer.shlex.shlex", fail_if_called)

    tokens = list(FortiGateTokenizer("set hostname edge01\n").tokenize())

    assert [(token.type, token.value, token.line_number) for token in tokens] == [
        (TokenType.SET, "set", 1),
        (TokenType.STRING, "hostname", 1),
        (TokenType.STRING, "edge01", 1),
    ]


@pytest.mark.parametrize(
    "command",
    [
        'set hostname edge01',
        'set member port1 port2',
        'set comment "hello world"',
        'set comment "escaped \\\" quote"',
        'set value ""',
    ],
)
def test_fast_and_shlex_paths_have_the_same_parts(command):
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""

    assert FortiGateTokenizer._split_command(command) == list(lexer)


def test_lf_and_crlf_produce_the_same_tree():
    source = """# comment
config firewall address
    edit web
        set subnet 192.0.2.10 255.255.255.255
    next
end
"""

    lf = parse_fortigate_config(source)
    crlf = parse_fortigate_config(source.replace("\n", "\r\n"))

    assert lf == crlf
    assert lf.comments[0].line_number == 1
    assert lf.configs[0].edits[0].commands[0].line_number == 4


def test_streaming_parser_preserves_comments_quotes_escapes_and_unknowns():
    source = """config system global
    edit admin
    set hostname "edge\\\"one"
    set description "first
second"
    unknown-command raw-value
    next
end
"""

    tree = parse_fortigate_config(source)
    edit = tree.configs[0].edits[0]

    assert edit.commands[0].values == ['edge"one']
    assert edit.commands[1].values == ["first\nsecond"]
    assert isinstance(edit.commands[2], UnknownCommandNode)
    assert edit.commands[2].line_number == 6


def test_blank_lines_and_comments_do_not_change_command_lines():
    tree = parse_fortigate_config(
        "\n# header\n\nconfig system global\n  # inside\n  set hostname fg\nend\n"
    )

    assert tree.comments[0].line_number == 2
    assert tree.configs[0].start_line_number == 4
    assert tree.configs[0].commands[0].line_number == 6


def test_unterminated_quote_is_preserved_as_unknown_source():
    tokens = list(FortiGateTokenizer('set comment "unterminated\n').tokenize())

    assert tokens[0].type is TokenType.UNKNOWN
    assert tokens[0].line_number == 1


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("config system global\n", "Unterminated config 'system global' starting at line 1"),
        (
            "config system global\n    edit admin\n",
            "Unterminated edit 'admin' starting at line 2",
        ),
    ],
)
def test_unterminated_blocks_keep_parser_errors(source, message):
    with pytest.raises(ParserError, match=message):
        parse_fortigate_config(source)


def test_peek_is_repeatable_and_next_token_consumes_one_token():
    parser = FortiGateParser(FortiGateTokenizer("config system global\nend\n"))

    first = parser.peek()
    assert first == parser.peek()
    assert parser.next_token() == first
    assert parser.peek().type is TokenType.STRING
