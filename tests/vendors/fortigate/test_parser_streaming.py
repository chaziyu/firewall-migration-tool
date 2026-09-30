import random
import shlex
from itertools import product

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
    monkeypatch.setattr("fwmigrate.vendors.fortigate.tokenizer.FortiGateTokenizer._scan_lexical_state", fail_if_called)

    tokens = list(FortiGateTokenizer("set hostname edge01\n").tokenize())

    assert [(token.type, token.value, token.line_number) for token in tokens] == [
        (TokenType.SET, "set", 1),
        (TokenType.STRING, "hostname", 1),
        (TokenType.STRING, "edge01", 1),
    ]


def test_simple_unquoted_configuration_keeps_the_same_tree_shape():
    tree = parse_fortigate_config(
        "config system interface\n"
        "edit port1\n"
        "set ip 192.0.2.1 255.255.255.0\n"
        "append alias edge\n"
        "unset description\n"
        "next\n"
        "end\n"
    )

    config = tree.configs[0]
    edit = config.edits[0]
    assert (config.name, config.start_line_number, config.end_line_number) == ("system interface", 1, 7)
    assert (edit.name, edit.start_line_number, edit.end_line_number) == ("port1", 2, 6)
    assert [(command.operation, command.key, command.values, command.line_number) for command in edit.commands] == [
        ("set", "ip", ["192.0.2.1", "255.255.255.0"], 3),
        ("append", "alias", ["edge"], 4),
        ("unset", "description", [], 5),
    ]


@pytest.mark.parametrize(
    "command",
    [
        'set hostname edge01',
        'set member port1 port2',
        'set comment "hello world"',
        'set comment "escaped \\\" quote"',
        'set value ""',
        '\tset\tmember\t"a b"  "" "中文 café"\t',
        'set comment "literal # hash" #suffix',
        'set comment "literal\t tab"',
        'set comment "unicode" unquoted\u00a0space',
        'set comment "vertical" unquoted\vspace',
        "set comment 'single quote'",
        'set comment "double"\'single\'',
        'set comment "prefix"suffix',
        'set comment prefix"suffix"',
        'set comment "one""two"',
        'set comment "first\nsecond"',
        'set comment "first\r\nsecond"',
        r'set comment "escaped \\ slash"',
        r'set comment escaped\ space',
    ],
)
def test_fast_and_shlex_paths_have_the_same_parts(command):
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""

    assert FortiGateTokenizer._split_command(command) == list(lexer)


def _shlex_parts(command):
    lexer = shlex.shlex(command, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def test_ordinary_double_quotes_skip_shlex(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("ordinary double quotes should not need shlex")
    monkeypatch.setattr("fwmigrate.vendors.fortigate.tokenizer.shlex.shlex", fail_if_called)
    assert FortiGateTokenizer._split_command('set member "" "a b" "中文" #literal') == ['set', 'member', '', 'a b', '中文', '#literal']


def test_quoted_fast_path_differential_combinations_and_malformed_commands():
    fragments = ['""', '"a b"', '"中文\t#"', 'plain', '"a"b', 'a"b"', '"a""b"', "'a b'", r'"a\"b"', r'a\ b', '"first\nsecond"', '"open', '"closed"\\']
    commands = ['set member ' + left + separator + right for left, separator, right in product(fragments, ['', ' ', '\t'], fragments)]
    rng = random.Random(0)
    commands += ['set value "' + ''.join(rng.choices('ab \t#é中文"\'\\\n\r', k=30)) + '"' for _ in range(500)]
    for command in commands:
        try:
            expected = _shlex_parts(command)
        except ValueError as error:
            with pytest.raises(ValueError) as actual:
                FortiGateTokenizer._split_command(command)
            assert str(actual.value) == str(error)
        else:
            assert FortiGateTokenizer._split_command(command) == expected


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_quoted_parser_tree_and_line_provenance_match_shlex(monkeypatch, newline):
    source = '''config vdom
edit "branch 中文"
config firewall addrgrp
edit "group #1"
set member "" "a b"
append member "c"
unset comment
set comment "first
second"
future-command "preserve me"
next
end
next
end
'''.replace('\n', newline)
    actual = parse_fortigate_config(source)
    monkeypatch.setattr(FortiGateTokenizer, '_split_command', staticmethod(_shlex_parts))
    assert actual == parse_fortigate_config(source)
    commands = actual.configs[0].edits[0].children[0].edits[0].commands
    assert [(command.operation, command.line_number) for command in commands[:4]] == [('set', 5), ('append', 6), ('unset', 7), ('set', 8)]


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
