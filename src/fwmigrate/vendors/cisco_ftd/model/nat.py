"""Vendor-native cisco_ftd nat models."""

from __future__ import annotations
from typing import Any, List, Optional
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDFDMNATRule(CiscoFTDSourceRecord):
    """FDM-native NAT source record."""
    source_interface: Optional[CiscoFTDReference] = None
    destination_interface: Optional[CiscoFTDReference] = None
    original_source: Optional[CiscoFTDReference] = None
    translated_source: Optional[CiscoFTDReference] = None
    original_destination: Optional[CiscoFTDReference] = None
    translated_destination: Optional[CiscoFTDReference] = None
    service: Optional[CiscoFTDReference] = None
    rule_type: Optional[str] = None
    sequence: Optional[int] = None
    observed_collection_order: Optional[int] = None
    enabled: Optional[bool] = None
    source_translation_mode: Optional[str] = None
    destination_translation_mode: Optional[str] = None


class CiscoFTDManualNATRule(CiscoFTDSourceRecord):
    source_interface: Optional[CiscoFTDReference] = None
    destination_interface: Optional[CiscoFTDReference] = None
    original_source: Any = None
    translated_source: Any = None
    original_destination: Any = None
    translated_destination: Any = None
    original_source_port: Any = None
    translated_source_port: Any = None
    original_destination_port: Any = None
    translated_destination_port: Any = None
    original_source_service: Any = None
    translated_source_service: Any = None
    original_destination_service: Any = None
    translated_destination_service: Any = None
    nat_type: Optional[str] = None
    enabled: Optional[bool] = None
    section: Optional[str] = None
    position: Optional[int] = None
    observed_collection_order: Optional[int] = None
    identity_nat: Optional[bool] = None
    interface_pat: Optional[bool] = None
    dns: Optional[bool] = None
    route_lookup: Optional[bool] = None
    no_proxy_arp: Optional[bool] = None
    proxy_arp: Optional[bool] = None


class CiscoFTDAutoNATRule(CiscoFTDSourceRecord):
    source_interface: Optional[CiscoFTDReference] = None
    destination_interface: Optional[CiscoFTDReference] = None
    original_network: Any = None
    translated_network: Any = None
    owning_network: Any = None
    nat_type: Optional[str] = None
    enabled: Optional[bool] = None
    position: Optional[int] = None
    observed_collection_order: Optional[int] = None
    interface_pat: Optional[bool] = None
    dns: Optional[bool] = None
    route_lookup: Optional[bool] = None
    no_proxy_arp: Optional[bool] = None
    proxy_arp: Optional[bool] = None
    identity_nat: Optional[bool] = None


class CiscoFTDNATPolicy(CiscoFTDSourceRecord):
    manual_rules_before_auto: Optional[List[CiscoFTDManualNATRule]] = None
    auto_rules: Optional[List[CiscoFTDAutoNATRule]] = None
    manual_rules_after_auto: Optional[List[CiscoFTDManualNATRule]] = None
    unclassified_manual_rules: Optional[List[CiscoFTDManualNATRule]] = None
    # FDM exposes a different aggregate shape; keep it source-native and separate.
    rules: Optional[List[CiscoFTDFDMNATRule]] = None
