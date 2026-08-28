from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRNATRule, NATType
from fwmigrate.extraction.models import SourceInventoryItem, ExtractionStatus

class PANSourceTranslation(BaseModel):
    method: str  # e.g., 'dynamic-ip-and-port', 'static-ip', 'dynamic-ip'
    translated_address: Optional[List[str]] = None
    interface_address: Optional[str] = None

class PANDestinationTranslation(BaseModel):
    translated_address: Optional[str] = None
    translated_port: Optional[str] = None

class PANDynamicDestinationTranslation(BaseModel):
    translated_address: Optional[str] = None
    translated_port: Optional[str] = None

class PANNatRuleExtractor:
    @staticmethod
    def extract_source_translation(snat_elem: ET.Element) -> Optional[PANSourceTranslation]:
        if snat_elem is None:
            return None
            
        dip = snat_elem.find("dynamic-ip-and-port")
        if dip is not None:
            if_ip = dip.find("interface-address/ip")
            if_ip_val = if_ip.text.strip() if if_ip is not None and if_ip.text else None
            
            # Translated address can be a list in PAN-OS
            trans_addr_elems = dip.findall("translated-address/member")
            trans_addrs = [m.text.strip() for m in trans_addr_elems if m.text]
            
            return PANSourceTranslation(
                method="dynamic-ip-and-port",
                interface_address=if_ip_val,
                translated_address=trans_addrs if trans_addrs else None
            )
            
        static_ip = snat_elem.find("static-ip")
        if static_ip is not None:
            trans_addr = static_ip.find("translated-address")
            trans_addrs = [trans_addr.text.strip()] if trans_addr is not None and trans_addr.text else None
            return PANSourceTranslation(
                method="static-ip",
                translated_address=trans_addrs
            )
            
        dyn_ip = snat_elem.find("dynamic-ip")
        if dyn_ip is not None:
            trans_addr_elems = dyn_ip.findall("translated-address/member")
            trans_addrs = [m.text.strip() for m in trans_addr_elems if m.text]
            return PANSourceTranslation(
                method="dynamic-ip",
                translated_address=trans_addrs if trans_addrs else None
            )
            
        return PANSourceTranslation(method="unknown")

    @staticmethod
    def extract_destination_translation(dnat_elem: ET.Element) -> Optional[PANDestinationTranslation]:
        if dnat_elem is None:
            return None
            
        trans_addr = dnat_elem.find("translated-address")
        trans_port = dnat_elem.find("translated-port")
        
        return PANDestinationTranslation(
            translated_address=trans_addr.text.strip() if trans_addr is not None and trans_addr.text else None,
            translated_port=trans_port.text.strip() if trans_port is not None and trans_port.text else None
        )

    @staticmethod
    def extract_dynamic_destination_translation(dyn_dnat_elem: ET.Element) -> Optional[PANDynamicDestinationTranslation]:
        if dyn_dnat_elem is None:
            return None
            
        trans_addr = dyn_dnat_elem.find("translated-address")
        trans_port = dyn_dnat_elem.find("translated-port")
        
        return PANDynamicDestinationTranslation(
            translated_address=trans_addr.text.strip() if trans_addr is not None and trans_addr.text else None,
            translated_port=trans_port.text.strip() if trans_port is not None and trans_port.text else None
        )
