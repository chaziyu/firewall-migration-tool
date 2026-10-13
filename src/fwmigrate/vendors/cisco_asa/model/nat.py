from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import Field
from .base import CiscoSourceModel


class CiscoNATRule(CiscoSourceModel):
    """Parsed ASA NAT source rule and source-order provenance."""

    name: str
    source_context: Optional[str] = None
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    section: str = "manual"
    syntax_family: Optional[str] = None
    sequence: Optional[int] = None
    type: str = "source"
    source_mode: Optional[str] = None
    mapped_source_mode: Optional[str] = None
    mapped_source_address_family: Optional[str] = None
    pat_pool: Optional[str] = None
    pat_pool_options: List[str] = Field(default_factory=list)
    real_source: Optional[str] = None
    mapped_source: Optional[str] = None
    destination_mode: Optional[str] = None
    real_destination: Optional[str] = None
    mapped_destination: Optional[str] = None
    original_service: Optional[str] = None
    translated_service: Optional[str] = None
    service_protocol: Optional[str] = None
    service_operand_1: Optional[str] = None
    service_operand_2: Optional[str] = None
    owning_object: Optional[str] = None
    access_list: Optional[str] = None
    identity_nat: bool = False
    nat_exemption: bool = False
    options: List[str] = Field(default_factory=list)
    raw_options: List[str] = Field(default_factory=list)
    net_to_net: bool = False
    dns: bool = False
    no_proxy_arp: bool = False
    route_lookup: bool = False
    unidirectional: bool = False
    inactive: bool = False
    source_sequence: Optional[int] = None
    source_order: Optional[int] = None
    source_order_within_section: Optional[int] = None
    section_order: Optional[int] = None
    raw_line: str = ""
    description: Optional[str] = None
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
