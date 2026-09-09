import pytest
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser

def test_panos_parser_rejects_empty():
    parser = PANOSSourceParser()
    with pytest.raises(ValueError, match="Empty configuration"):
        parser.extract("   ")

def test_panos_parser_rejects_set_commands():
    parser = PANOSSourceParser()
    with pytest.raises(ValueError, match="PAN-OS CLI 'set' format is not supported"):
        parser.extract("set deviceconfig system type static\nset deviceconfig system ip-address 1.1.1.1")

def test_panos_parser_rejects_generic_xml():
    parser = PANOSSourceParser()
    with pytest.raises(ValueError, match="Unsupported XML format: expected root element '<config>'"):
        parser.extract("<notconfig><devices></devices></notconfig>")

def test_panos_parser_rejects_malformed_xml():
    parser = PANOSSourceParser()
    with pytest.raises(ValueError, match="Malformed XML input"):
        parser.extract("<config><devices></config>")
