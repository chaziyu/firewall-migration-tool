from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def test_security_and_nat_same_source_id_shape_do_not_cross_contaminate_order_metadata():
    result = PANOSSourceParser().extract("""
    <config>
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
              <rules>
                <entry name="same-name">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <source-user><member>any</member></source-user>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="same-name">
                  <from><member>any</member></from>
                  <to><member>any</member></to>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <service>any</service>
                  <source-translation>
                    <static-ip><translated-address>203.0.113.50</translated-address></static-ip>
                  </source-translation>
                </entry>
              </rules>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </config>
    """)

    policy = next(policy for policy in result.canonical_ir.policies if policy.name == "same-name")
    nat = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "same-name")

    assert policy.source_rule_id == nat.source_rule_id
    assert policy.source_extra_settings["effective_policy_layer"] == "local-firewall-rules"
    assert nat.source_attributes["effective_policy_layer"] == "local-nat-rules"
