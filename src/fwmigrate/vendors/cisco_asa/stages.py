"""Explicit stages for the vendor-native ASA source parser."""

from functools import lru_cache

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from . import phase10_17 as phase
from . import phase10_17_safety as safety


def _parse_management_command(self, line: str, line_number: int) -> None:
    return safety._wrap_management(phase._parse_management_command_phase)(
        self, line, line_number
    )


def _parse_class_map_block(self, lines, index):
    return safety._wrap_class_map_block(phase._parse_class_map_block_phase)(
        self, lines, index
    )


def _parse_threat_detection(self, line: str, line_number: int) -> None:
    return safety._wrap_threat_detection(phase._parse_threat_detection_phase)(
        self, line, line_number
    )


def _parse_raw(self):
    config = CiscoASAParser.parse_raw(self)
    phase._postprocess_dns(self)
    phase._postprocess_interface_dhcprelay(self)
    phase._postprocess_trustpoints(self)
    phase._postprocess_contexts(self)
    phase._postprocess_failover_groups(self)
    phase._postprocess_no_service_policies(self)
    phase._postprocess_http_server(self)
    return config


@lru_cache(maxsize=1)
def get_asa_parser_class():
    """Return the isolated ASA extraction parser with explicit stages."""

    # The phase parser uses this callback only for syntax it does not own.
    # Store it as stage metadata, without replacing the public parser method.
    phase._ORIGINALS["management"] = CiscoASAParser._parse_management_command

    class ASAExtractionParser(CiscoASAParser):
        """Source parser with normal class-method stage composition."""

        _build_context_ownership = staticmethod(phase._build_context_ownership_phase)
        _parse_class_map_block = _parse_class_map_block
        _parse_policy_map_block = phase._parse_policy_map_block_phase
        _parse_mpf_action = phase._parse_mpf_action_phase
        _parse_connection_action = phase._parse_connection_action_phase
        _parse_police_action = phase._parse_police_action_phase
        _parse_tcp_map_block = phase._parse_tcp_map_block_phase
        _parse_service_policy_line = phase._parse_service_policy_line_phase
        _parse_threat_detection = _parse_threat_detection
        _parse_dhcpd_command = phase._parse_dhcpd_command_phase
        _parse_management_command = _parse_management_command
        _parse_global_conn = safety._parse_unverified_global_conn
        parse_raw = _parse_raw


    return ASAExtractionParser


__all__ = ["get_asa_parser_class"]

