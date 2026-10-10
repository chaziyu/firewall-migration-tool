"""Lazy public exports for vendor-native source reporting."""

from importlib import import_module

_EXPORTS = {
    'DerivedViews': ('.derived', 'DerivedViews'),
    'ExtractionResult': ('.extraction.result', 'ExtractionResult'),
    'FGConfig': ('.model.source', 'FGConfig'),
    'build_derived_views': ('.derived', 'build_derived_views'),
    'export_excel': ('.export', 'export_excel'),
    'extract_fortigate_config': ('.extraction.extractor', 'extract_fortigate_config'),
    'parse_fortigate_config': ('.parser', 'parse_fortigate_config'),
    'validate_config': ('.validation.validator', 'validate_config'),
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
