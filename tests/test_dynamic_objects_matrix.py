import pytest
from lxml import etree
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.checkpoint.cli_generator import CheckPointCLIGenerator
from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fwmigrate.ir.core import IRConfig, IRAddressGroup, IRAddress, IRPolicy
from fwmigrate.ir.enums import AddressType, PolicyAction

def test_fortigate_ems_to_panos_dag_xml():
    fg_conf = """
    config system global
        set hostname "FG-EMS-TEST"
    end
    config firewall address
        edit "EMS_ALL_UNKNOWN_CLIENTS"
            set type dynamic
            set sub-type ems-tag
            set ems-tag-name "EMS-Unknown"
            set comment "FortiClient EMS Dynamic Tag"
        next
    end
    config firewall policy
        edit 1
            set name "Block-Unknown-EMS"
            set srcintf "port1"
            set dstintf "port2"
            set srcaddr "EMS_ALL_UNKNOWN_CLIENTS"
            set dstaddr "all"
            set action deny
            set schedule "always"
            set service "ALL"
        next
    end
    """
    fg_model = parse_fortigate_config(fg_conf)
    ir = FGToIRTransformer(fg_model).transform()
    
    # Verify IR contains the dynamic address group
    dag = next((ag for ag in ir.address_groups if ag.name == "EMS_ALL_UNKNOWN_CLIENTS"), None)
    assert dag is not None
    assert dag.is_dynamic is True
    assert dag.dynamic_filter == "'EMS-Unknown'"
    
    # Generate PAN-OS XML
    xml_gen = PANOSXMLGenerator()
    artifacts = xml_gen.generate(ir)
    assert len(artifacts) == 1
    
    root = etree.fromstring(artifacts[0].content.encode('utf-8'))
    dag_elem = root.find(".//vsys/entry/address-group/entry[@name='EMS_ALL_UNKNOWN_CLIENTS']")
    assert dag_elem is not None
    dyn_filter = dag_elem.find(".//dynamic/filter")
    assert dyn_filter is not None
    assert dyn_filter.text == "'EMS-Unknown'"

def test_fortigate_ems_to_panos_terraform():
    ir = IRConfig(
        metadata={"hostname": "PAN-TF-TEST", "source_vendor": "fortigate"},
        address_groups=[
            IRAddressGroup(
                name="EMS_ALL_UNMANAGEABLE_CLIENTS",
                is_dynamic=True,
                dynamic_filter="'EMS-Unmanageable'",
                description="Auto-migrated EMS tag"
            )
        ]
    )
    tf_gen = PANOSTerraformGenerator()
    artifacts = tf_gen.generate(ir)
    main_tf = next(a for a in artifacts if a.filename == "main.tf")
    
    assert 'resource "panos_address_group" "grp_EMS_ALL_UNMANAGEABLE_CLIENTS"' in main_tf.content
    assert 'dynamic_match = "\'EMS-Unmanageable\'"' in main_tf.content

def test_panos_dag_to_fortios_cli():
    pan_xml = """
    <config version="10.2.0">
      <devices>
        <entry name="localhost.localdomain">
          <vsys>
            <entry name="vsys1">
              <address-group>
                <entry name="Quarantine_DAG">
                  <dynamic>
                    <filter>'quarantine-tag'</filter>
                  </dynamic>
                  <description>Dynamic quarantine group</description>
                </entry>
              </address-group>
            </entry>
          </vsys>
        </entry>
      </devices>
    </config>
    """
    ir = PANOSSourceParser().parse(pan_xml)
    dag = next((ag for ag in ir.address_groups if ag.name == "Quarantine_DAG"), None)
    assert dag is not None
    assert dag.is_dynamic is True
    assert dag.dynamic_filter == "'quarantine-tag'"
    
    # Generate FortiOS CLI
    fg_cli = FortiGateCLIGenerator().generate(ir)[0].content
    assert 'config firewall addrgrp' in fg_cli
    assert 'edit "Quarantine_DAG"' in fg_cli
    assert 'set type dynamic' in fg_cli
    assert 'set ems-tag-name "quarantine-tag"' in fg_cli

def test_dynamic_objects_multi_vendor_matrix():
    ir = IRConfig(
        metadata={"hostname": "MULTI-VENDOR-DAG", "source_vendor": "palo_alto"},
        address_groups=[
            IRAddressGroup(
                name="Compliance_Failures",
                is_dynamic=True,
                dynamic_filter="'non-compliant'",
                description="Endpoints failing posture check"
            )
        ]
    )
    
    # 1. Check Point CLI
    cp_cli = CheckPointCLIGenerator().generate(ir)
    assert 'mgmt_cli add dynamic-object name "Compliance_Failures"' in cp_cli
    
    # 2. Juniper SRX CLI
    junos_cli = JuniperSRXCLIGenerator().generate(ir)
    assert 'set security address-book global dynamic-address Compliance_Failures' in junos_cli
    
    # 3. Cisco ASA CLI
    cisco_cli = CiscoASACLIGenerator().generate(ir)
    assert 'object-group network Compliance_Failures' in cisco_cli
    assert 'description Dynamic Tag: non-compliant' in cisco_cli
