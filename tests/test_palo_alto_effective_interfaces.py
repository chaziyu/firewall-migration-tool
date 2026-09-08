import xml.etree.ElementTree as ET

from fwmigrate.parsers.palo_alto.panorama import PANPanoramaExtractor


def _effective_layer3(xml: str):
    root = ET.fromstring(xml)
    device = root.find("./devices/entry")
    assert device is not None
    effective, provenance, stack_names = PANPanoramaExtractor.effective_device_entry(root, device)
    layer3 = effective.find(
        "./network/interface/ethernet/entry[@name='ethernet1/1']/layer3"
    )
    assert layer3 is not None
    return layer3, provenance, stack_names


def test_template_stack_higher_template_has_priority_for_duplicate_interface_fields():
    layer3, provenance, stack_names = _effective_layer3(
        """
        <config>
          <template>
            <entry name="top"><config><devices><entry name="localhost.localdomain">
              <network><interface><ethernet><entry name="ethernet1/1"><layer3>
                <comment>top</comment>
              </layer3></entry></ethernet></interface></network>
            </entry></devices></config></entry>
            <entry name="middle"><config><devices><entry name="localhost.localdomain">
              <network><interface><ethernet><entry name="ethernet1/1"><layer3>
                <comment>middle</comment><mtu>1400</mtu>
              </layer3></entry></ethernet></interface></network>
            </entry></devices></config></entry>
            <entry name="bottom"><config><devices><entry name="localhost.localdomain">
              <network><interface><ethernet><entry name="ethernet1/1"><layer3>
                <comment>bottom</comment><mtu>1500</mtu>
              </layer3></entry></ethernet></interface></network>
            </entry></devices></config></entry>
          </template>
          <template-stack><entry name="branch-stack">
            <templates>
              <member>top</member><member>middle</member><member>bottom</member>
            </templates>
            <devices><entry name="001122334455"/></devices>
          </entry></template-stack>
          <devices><entry name="001122334455"/></devices>
        </config>
        """
    )

    assert layer3.findtext("./comment") == "top"
    assert layer3.findtext("./mtu") == "1400"
    assert stack_names == ["branch-stack"]

    comment_path = next(path for path in provenance if path.endswith("/layer3/comment"))
    mtu_path = next(path for path in provenance if path.endswith("/layer3/mtu"))
    assert [entry["source"] for entry in provenance[comment_path]] == [
        "bottom", "middle", "top"
    ]
    assert provenance[comment_path][-1]["overrides"] == ["bottom", "middle"]
    assert [entry["source"] for entry in provenance[mtu_path]] == [
        "bottom", "middle"
    ]
    assert provenance[mtu_path][-1]["overrides"] == ["bottom"]


def test_template_stack_and_local_device_values_override_inherited_templates():
    layer3, provenance, stack_names = _effective_layer3(
        """
        <config>
          <template>
            <entry name="base"><config><devices><entry name="localhost.localdomain">
              <network><interface><ethernet><entry name="ethernet1/1"><layer3>
                <comment>template</comment><mtu>1500</mtu>
              </layer3></entry></ethernet></interface></network>
            </entry></devices></config></entry>
          </template>
          <template-stack><entry name="branch-stack">
            <templates><member>base</member></templates>
            <devices><entry name="001122334455">
              <network><interface><ethernet><entry name="ethernet1/1"><layer3>
                <comment>stack</comment><mtu>1400</mtu>
              </layer3></entry></ethernet></interface></network>
            </entry></devices>
          </entry></template-stack>
          <devices><entry name="001122334455">
            <network><interface><ethernet><entry name="ethernet1/1"><layer3>
              <comment>device</comment><mtu>1300</mtu>
            </layer3></entry></ethernet></interface></network>
          </entry></devices>
        </config>
        """
    )

    assert layer3.findtext("./comment") == "device"
    assert layer3.findtext("./mtu") == "1300"
    assert stack_names == ["branch-stack"]

    comment_path = next(path for path in provenance if path.endswith("/layer3/comment"))
    mtu_path = next(path for path in provenance if path.endswith("/layer3/mtu"))
    assert [entry["source"] for entry in provenance[comment_path]] == [
        "base", "branch-stack", "device"
    ]
    assert provenance[comment_path][-1]["overrides"] == ["base", "branch-stack"]
    assert [entry["source"] for entry in provenance[mtu_path]] == [
        "base", "branch-stack", "device"
    ]
    assert provenance[mtu_path][-1]["overrides"] == ["base", "branch-stack"]
