"""Lookup structure reserved for future pair-specific converters."""

from .contracts import PairConverter


class ConversionRegistry:
    """Register and look up directional converters when pairs exist."""

    def __init__(self) -> None:
        self._converters: dict[tuple[str, str], PairConverter] = {}

    def register(self, converter: PairConverter) -> PairConverter:
        key = (converter.source_vendor.casefold(), converter.target_vendor.casefold())
        if key in self._converters:
            raise ValueError(f"Converter '{key[0]}_to_{key[1]}' is already registered")
        self._converters[key] = converter
        return converter

    def get(self, source_vendor: str, target_vendor: str) -> PairConverter:
        key = (source_vendor.strip().casefold(), target_vendor.strip().casefold())
        try:
            return self._converters[key]
        except KeyError as exc:
            raise KeyError(
                f"Converter '{key[0]}_to_{key[1]}' is not implemented"
            ) from exc


conversion_registry = ConversionRegistry()
