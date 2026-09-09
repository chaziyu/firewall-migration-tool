class IRSchemaError(ValueError):
    """Base error for malformed or incompatible serialized IR schemas."""


class UnsupportedIRSchemaError(IRSchemaError):
    """Raised when a declared IR schema version is not supported."""
