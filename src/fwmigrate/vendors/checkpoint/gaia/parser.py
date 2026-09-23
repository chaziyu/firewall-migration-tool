from __future__ import annotations

from .nodes import GaiaCommandNode, GaiaCommentNode, GaiaConfigTree, GaiaUnknownCommandNode
from .tokenizer import GaiaTokenType, tokenize_gaia


def parse_gaia(text: str) -> GaiaConfigTree:
    tree = GaiaConfigTree()
    for tokens in tokenize_gaia(text):
        if not tokens:
            continue
        first = tokens[0]
        values = tuple(token.value for token in tokens[1:])
        if first.type is GaiaTokenType.COMMENT:
            tree.comments.append(GaiaCommentNode(first.value, first.line_number))
        elif first.type in {GaiaTokenType.SET, GaiaTokenType.ADD, GaiaTokenType.SHOW,
                            GaiaTokenType.CREATE, GaiaTokenType.DELETE}:
            tree.commands.append(GaiaCommandNode(first.value.lower(), values, first.line_number))
        else:
            reason = "malformed syntax" if first.value.startswith("malformed syntax") else "unsupported"
            tree.unknown_commands.append(GaiaUnknownCommandNode(first.value, values, first.line_number, reason))
    return tree
