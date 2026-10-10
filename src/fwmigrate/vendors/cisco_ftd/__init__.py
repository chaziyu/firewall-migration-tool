"""Lazy public exports for vendor-native source reporting."""

from importlib import import_module

_EXPORTS = {
    'CiscoFTDSourceReporter': ('.source_report', 'CiscoFTDSourceReporter'),
    'extract_cisco_ftd_source': ('.source_report', 'extract_cisco_ftd_source'),
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
