"""Lazy public exports for vendor-native source reporting."""

from importlib import import_module

_EXPORTS = {
    'PaloAltoSourceReporter': ('.source_report', 'PaloAltoSourceReporter'),
    'PaloAltoSourceResult': ('.source_report', 'PaloAltoSourceResult'),
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    try:
        module, attribute = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    value = getattr(import_module(module, __name__), attribute)
    globals()[name] = value
    return value
