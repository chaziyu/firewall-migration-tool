"""FortiOS 7.4.6 multi-value ``system dns server-hostname`` support.

FortiOS 7.4.6 allows ``server-hostname`` to contain multiple ordered values.
The historical FortiGate DNS model/parser treated the field as a scalar, which
silently discarded every value after the first.  Keep this compatibility fix
scoped to ``config system dns`` and preserve the existing extension pattern
used by other FortiOS 7.4.6 parser corrections.
"""

from typing import Any, List

from pydantic import Field

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import FGDns


class FGDnsMultiValue746(FGDns):
    """FortiGate DNS source model with ordered server hostnames."""

    server_hostname: List[str] = Field(default_factory=list)


def install_dns_multivalue_fix(parser_module: Any) -> None:
    """Install ordered set/append/unset semantics for ``server-hostname``."""

    # parser.py resolves FGDns at runtime when ``config system dns`` is first
    # encountered.  Rebinding it to a compatible subclass keeps the fix local
    # while giving parsed DNS objects the corrected list-shaped field.
    parser_module.FGDns = FGDnsMultiValue746

    original_apply_global_set = parser_module.FortiGateParser.apply_global_set
    original_apply_global_unset = parser_module.FortiGateParser.apply_global_unset
    original_parse_config_contents = parser_module.FortiGateParser.parse_config_contents
    original_parse_key_values = parser_module.FortiGateParser.parse_key_values

    def apply_global_set(
        self: Any,
        section_path: str,
        key: str,
        values: List[str],
    ) -> None:
        clean_key = key.replace("-", "_")
        if section_path == "system dns" and clean_key == "server_hostname":
            if not self.config.dns:
                self.config.dns = FGDnsMultiValue746()
            parsed_value = list(values)
            self.config.dns.source_explicit_fields.add(clean_key)
            self.config.dns.server_hostname = parsed_value
            self.config.dns.extra_settings.update(
                sanitize_source_attributes({clean_key: parsed_value})
            )
            return
        original_apply_global_set(self, section_path, key, values)

    def apply_global_unset(self: Any, section_path: str, key: str) -> None:
        clean_key = key.replace("-", "_")
        if section_path == "system dns" and clean_key == "server_hostname":
            if self.config.dns:
                self.config.dns.source_explicit_fields.discard(clean_key)
                self.config.dns.server_hostname = []
                self.config.dns.extra_settings.pop(clean_key, None)
            return
        original_apply_global_unset(self, section_path, key)

    def parse_config_contents(self: Any, full_path: str) -> None:
        # The base global-block parser records APPEND commands but does not
        # apply them to global typed models.  Track the active path only while
        # delegating so parse_key_values can safely apply the DNS-specific
        # append without changing APPEND behavior for unrelated global blocks.
        previous_path = getattr(self, "_dns_multivalue_active_path", None)
        self._dns_multivalue_active_path = full_path
        try:
            return original_parse_config_contents(self, full_path)
        finally:
            self._dns_multivalue_active_path = previous_path

    def parse_key_values(self: Any, command_type: Any):
        key, values = original_parse_key_values(self, command_type)
        clean_key = key.replace("-", "_")
        if (
            command_type == parser_module.TokenType.APPEND
            and getattr(self, "_dns_multivalue_active_path", None) == "system dns"
            and clean_key == "server_hostname"
        ):
            if not self.config.dns:
                self.config.dns = FGDnsMultiValue746()
            current = self.config.dns.server_hostname
            if not isinstance(current, list):
                current = [current] if current else []
            current.extend(values)
            self.config.dns.server_hostname = current
            self.config.dns.source_explicit_fields.add(clean_key)
            self.config.dns.extra_settings.update(
                sanitize_source_attributes({clean_key: list(current)})
            )
        return key, values

    parser_module.FortiGateParser.apply_global_set = apply_global_set
    parser_module.FortiGateParser.apply_global_unset = apply_global_unset
    parser_module.FortiGateParser.parse_config_contents = parse_config_contents
    parser_module.FortiGateParser.parse_key_values = parse_key_values
