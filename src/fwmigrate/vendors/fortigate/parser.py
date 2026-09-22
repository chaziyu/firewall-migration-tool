from __future__ import annotations

from .nodes import (
    CommandNode,
    CommentNode,
    ConfigNode,
    EditNode,
    FortiGateConfigTree,
    UnknownCommandNode,
)

from .tokenizer import (
    FortiGateTokenizer,
    Token,
    TokenType,
)


class ParserError(Exception):
    """Raised when FortiGate CLI structure is malformed."""


class FortiGateParser:
    """
    Parse FortiGate CLI tokens into a structural source tree.

    Responsibilities:
        - config / edit hierarchy
        - set / unset / append commands
        - comments
        - source line information

    Non-responsibilities:
        - FortiOS defaults
        - semantic normalization
        - typed FortiGate model construction
        - reference resolution
        - validation
        - secret interpretation
    """

    def __init__(self, tokenizer: FortiGateTokenizer):
        self.tokens = list(tokenizer.tokenize())
        self.pos = 0

    def parse(self) -> FortiGateConfigTree:
        tree = FortiGateConfigTree()

        while self.peek() is not None:
            token = self.peek()

            if token.type == TokenType.COMMENT:
                comment = self.consume(TokenType.COMMENT)

                tree.comments.append(
                    CommentNode(
                        value=comment.value,
                        line_number=comment.line_number,
                    )
                )
                continue

            if token.type == TokenType.CONFIG:
                tree.configs.append(self.parse_config())
                continue

            if token.type == TokenType.UNKNOWN:
                tree.unknown_commands.append(
                    self.parse_unknown_command()
                )
                continue

            raise ParserError(
                f"Unexpected token {token.type.value!r} "
                f"at line {token.line_number}: {token.value!r}"
            )

        return tree

    # ------------------------------------------------------------------
    # Config hierarchy
    # ------------------------------------------------------------------

    def parse_config(self) -> ConfigNode:
        config_token = self.consume(TokenType.CONFIG)

        name = self.read_line_values(
            line_number=config_token.line_number
        )

        if not name:
            raise ParserError(
                f"Missing section name after 'config' "
                f"at line {config_token.line_number}"
            )

        node = ConfigNode(
            name=" ".join(name),
            start_line_number=config_token.line_number,
        )

        while self.peek() is not None:
            token = self.peek()

            if token.type == TokenType.END:
                node.end_line_number = self.consume(
                    TokenType.END
                ).line_number
                return node

            if token.type == TokenType.EDIT:
                node.edits.append(self.parse_edit())
                continue

            if token.type == TokenType.CONFIG:
                node.children.append(self.parse_config())
                continue

            if token.type in {
                TokenType.SET,
                TokenType.UNSET,
                TokenType.APPEND,
            }:
                node.commands.append(self.parse_command())
                continue

            if token.type == TokenType.COMMENT:
                comment = self.consume(TokenType.COMMENT)

                node.comments.append(
                    CommentNode(
                        value=comment.value,
                        line_number=comment.line_number,
                    )
                )
                continue

            if token.type == TokenType.UNKNOWN:
                node.commands.append(self.parse_unknown_command())
                continue

            raise ParserError(
                f"Unexpected token inside config {node.name!r}: "
                f"{token.type.value!r} at line {token.line_number}"
            )

        raise ParserError(
            f"Unterminated config {node.name!r} "
            f"starting at line {node.start_line_number}"
        )

    def parse_edit(self) -> EditNode:
        edit_token = self.consume(TokenType.EDIT)

        values = self.read_line_values(
            line_number=edit_token.line_number
        )

        if not values:
            raise ParserError(
                f"Missing identifier after 'edit' "
                f"at line {edit_token.line_number}"
            )

        # FortiGate edit identifiers are normally a single shlex value,
        # but joining keeps malformed/unusual input recoverable.
        name = " ".join(values)

        node = EditNode(
            name=name,
            start_line_number=edit_token.line_number,
        )

        while self.peek() is not None:
            token = self.peek()

            if token.type == TokenType.NEXT:
                node.end_line_number = self.consume(
                    TokenType.NEXT
                ).line_number
                return node

            if token.type == TokenType.CONFIG:
                node.children.append(self.parse_config())
                continue

            if token.type in {
                TokenType.SET,
                TokenType.UNSET,
                TokenType.APPEND,
            }:
                node.commands.append(self.parse_command())
                continue

            if token.type == TokenType.COMMENT:
                comment = self.consume(TokenType.COMMENT)

                node.comments.append(
                    CommentNode(
                        value=comment.value,
                        line_number=comment.line_number,
                    )
                )
                continue

            if token.type == TokenType.EDIT:
                raise ParserError(
                    f"Nested 'edit' without closing previous edit "
                    f"at line {token.line_number}"
                )

            if token.type == TokenType.END:
                raise ParserError(
                    f"Expected 'next' before 'end' for edit "
                    f"{node.name!r} started at "
                    f"line {node.start_line_number}"
                )

            if token.type == TokenType.UNKNOWN:
                node.commands.append(self.parse_unknown_command())
                continue

            raise ParserError(
                f"Unexpected token inside edit {node.name!r}: "
                f"{token.type.value!r} at line {token.line_number}"
            )

        raise ParserError(
            f"Unterminated edit {node.name!r} "
            f"starting at line {node.start_line_number}"
        )

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def parse_command(self) -> CommandNode:
        token = self.next_token()

        if token is None:
            raise ParserError("Unexpected end of token stream")

        if token.type not in {
            TokenType.SET,
            TokenType.UNSET,
            TokenType.APPEND,
        }:
            raise ParserError(
                f"Expected command token, got {token.type.value!r}"
            )

        values = self.read_line_values(
            line_number=token.line_number
        )

        if not values:
            raise ParserError(
                f"Missing key after {token.value!r} "
                f"at line {token.line_number}"
            )

        key = values[0]
        command_values = values[1:]

        return CommandNode(
            operation=token.type.value,
            key=key,
            values=command_values,
            line_number=token.line_number,
        )

    def parse_unknown_command(self) -> UnknownCommandNode:
        token = self.consume(TokenType.UNKNOWN)

        values = self.read_line_values(
            line_number=token.line_number
        )

        return UnknownCommandNode(
            keyword=token.value,
            values=values,
            line_number=token.line_number,
        )

    # ------------------------------------------------------------------
    # Token helpers
    # ------------------------------------------------------------------

    def peek(self) -> Token | None:
        if self.pos >= len(self.tokens):
            return None

        return self.tokens[self.pos]

    def next_token(self) -> Token | None:
        token = self.peek()

        if token is not None:
            self.pos += 1

        return token

    def consume(self, expected: TokenType) -> Token:
        token = self.next_token()

        if token is None:
            raise ParserError(
                f"Expected {expected.value!r}, "
                "but reached end of input"
            )

        if token.type != expected:
            raise ParserError(
                f"Expected {expected.value!r} at "
                f"line {token.line_number}, "
                f"got {token.type.value!r} ({token.value!r})"
            )

        return token

    def read_line_values(
        self,
        *,
        line_number: int,
    ) -> list[str]:
        values: list[str] = []

        while (
            self.peek() is not None
            and self.peek().type == TokenType.STRING
            and self.peek().line_number == line_number
        ):
            values.append(self.next_token().value)

        return values


def parse_fortigate_config(
    text: str,
) -> FortiGateConfigTree:
    tokenizer = FortiGateTokenizer(text)
    parser = FortiGateParser(tokenizer)

    return parser.parse()