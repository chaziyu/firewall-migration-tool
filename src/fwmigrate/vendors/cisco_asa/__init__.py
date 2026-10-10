"""Lazy public exports for vendor-native source reporting."""

from importlib import import_module

_EXPORTS = {
    'ASADerivedViews': ('.derived', 'ASADerivedViews'),
    'ASAValidationResult': ('.validation', 'ASAValidationResult'),
    'ASASourceResult': ('.source_report', 'ASASourceResult'),
    'CiscoASASourceReporter': ('.source_report', 'CiscoASASourceReporter'),
    'build_asa_derived_views': ('.derived', 'build_asa_derived_views'),
    'extract_cisco_asa_source': ('.source_report', 'extract_cisco_asa_source'),
    'validate_asa_config': ('.validation', 'validate_asa_config'),
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
