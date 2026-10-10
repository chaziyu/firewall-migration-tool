"""Lazy public exports for vendor-native source reporting."""

from importlib import import_module

_EXPORTS = {
    'JuniperSRXConfig': ('.model', 'JuniperSRXConfig'),
    'JuniperSRXParser': ('.parser', 'JuniperSRXParser'),
    'JuniperSRXSourceReporter': ('.source_report', 'JuniperSRXSourceReporter'),
    'JuniperSourceResult': ('.source_report', 'JuniperSourceResult'),
    'extract_juniper_source': ('.source_report', 'extract_juniper_source'),
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
