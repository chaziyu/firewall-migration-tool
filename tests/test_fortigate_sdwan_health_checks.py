from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _sdwan(text: str):
    result = extract_fortigate_config(text)
    assert result.canonical_ir.sdwan is not None
    return result.canonical_ir.sdwan, result


def test_health_check_fields_servers_sla_and_review_state():
    sdwan, result = _sdwan('''
config system sdwan
    config health-check
        edit "probe"
            set server "1.1.1.1" "dns.example.com"
            set members 2 1
            set addr-mode ipv6
            set interval 1000
            set source6 2001:db8::10
            set password ENC synthetic-secret
            set future-health-option retained
            config sla
                edit 1
                    set jitter-threshold 20
                    set latency-threshold 30
                    set link-cost-factor latency jitter packet-loss
                    set mos-threshold 4.2
                    set packetloss-threshold 5
                    set priority-in-sla 1
                    set priority-out-sla 2
                    set future-sla-option retained
                next
            end
        next
    end
end
''')
    check = sdwan.health_checks[0]
    sla = check.sla[0]
    assert check.servers == ["1.1.1.1", "dns.example.com"]
    assert check.server is None
    assert check.member_ids == [2, 1]
    assert check.has_password is True
    assert check.password_format == "encrypted"
    assert sla.link_cost_factors == ["latency", "jitter", "packet-loss"]
    assert sla.mos_threshold == "4.2"
    assert {"jitter_threshold", "link_cost_factor", "mos_threshold"} <= set(sla.source_explicit_fields)
    ir_check = sdwan.health_checks[0]
    assert ir_check.servers == check.servers
    assert ir_check.sla[0].link_cost_factors == sla.link_cost_factors
    assert ir_check.migration_status == "EXTRACT_ONLY"
    assert ir_check.requires_manual_review is True
    assert ir_check.sla[0].requires_manual_review is True
    serialized = result.canonical_ir.model_dump_json()
    assert "synthetic-secret" not in serialized
    assert "future_health_option" in serialized
    assert "future_sla_option" in serialized


def test_health_check_single_server_compatibility_and_defaults():
    sdwan, _ = _sdwan('''
config system sdwan
    config health-check
        edit "single"
            set server "192.0.2.1"
        next
        edit "defaulted"
        next
    end
end
''')
    single, defaulted = sdwan.health_checks
    assert single.servers == ["192.0.2.1"]
    assert single.server == "192.0.2.1"
    assert (defaulted.interval, defaulted.probe_timeout, defaulted.port, defaulted.vrf) == (500, 500, 0, 0)
    assert "interval" not in defaulted.source_explicit_fields


def test_health_check_unset_restores_defaults_and_preserves_commands():
    sdwan, result = _sdwan('''
config system sdwan
    config health-check
        edit "unset"
            set interval 1000
            unset interval
            set update-static-route disable
            unset update-static-route
        next
    end
end
''')
    check = sdwan.health_checks[0]
    assert check.interval == 500
    assert check.update_static_route == "enable"
    assert "interval" not in check.source_explicit_fields
    raw = result.model_dump_json()
    assert '"operation":"unset"' in raw
