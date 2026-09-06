from pathlib import Path


MODEL = Path("src/fwmigrate/parsers/fortigate/model.py")
TEST = Path("tests/test_fortigate_phase16_20_remediation.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


text = MODEL.read_text(encoding="utf-8")

text = replace_once(
    text,
    "from fwmigrate.parsers.fortigate.source_tree import FGSourceNode, FGStructuredSourceObject\n\n\nclass FGContextualModel(BaseModel):",
    '''from fwmigrate.parsers.fortigate.source_tree import FGSourceNode, FGStructuredSourceObject\n\n\ndef _preserve_malformed_int_fields(value: Any, fields: Set[str]) -> Any:\n    \"\"\"Normalize numeric source fields without repairing malformed input.\n\n    Invalid values remain available in ``extra_settings`` under an\n    ``unparsed_<field>`` key so extraction remains zero-silent-loss while the\n    typed field is left unresolved.\n    \"\"\"\n    if not isinstance(value, dict):\n        return value\n\n    normalized = dict(value)\n    extra_settings = dict(normalized.get(\"extra_settings\") or {})\n    for field in fields:\n        if field not in normalized or normalized[field] is None:\n            continue\n\n        raw_value = normalized[field]\n        if isinstance(raw_value, bool):\n            extra_settings[f\"unparsed_{field}\"] = raw_value\n            normalized[field] = None\n            continue\n\n        try:\n            normalized[field] = int(raw_value)\n        except (TypeError, ValueError):\n            extra_settings[f\"unparsed_{field}\"] = raw_value\n            normalized[field] = None\n\n    normalized[\"extra_settings\"] = extra_settings\n    return normalized\n\n\nclass FGContextualModel(BaseModel):''',
    "numeric helper",
)

text = replace_once(
    text,
    '''    utilization_alarm_clear: Optional[int] = None\n    utilization_alarm_raise: Optional[int] = None\n\n    comments: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n\nclass FGScheduleGroup''',
    '''    utilization_alarm_clear: Optional[int] = None\n    utilization_alarm_raise: Optional[int] = None\n\n    comments: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_numeric_source_fields(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(\n            value,\n            {\n                \"startport\",\n                \"endport\",\n                \"block_size\",\n                \"num_blocks_per_user\",\n                \"pba_timeout\",\n                \"pba_interim_log\",\n                \"port_per_user\",\n                \"client_prefix_length\",\n                \"tcp_session_quota\",\n                \"udp_session_quota\",\n                \"icmp_session_quota\",\n                \"cgn_block_size\",\n                \"cgn_client_ipv6shift\",\n                \"cgn_port_start\",\n                \"cgn_port_end\",\n                \"utilization_alarm_clear\",\n                \"utilization_alarm_raise\",\n            },\n        )\n\n\nclass FGScheduleGroup''',
    "FGIPPool numeric validation",
)

text = replace_once(
    text,
    '''    monitor: List[str] = Field(default_factory=list)\n    client_ip: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n\nclass FGVIP(FGContextualModel):''',
    '''    monitor: List[str] = Field(default_factory=list)\n    client_ip: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_numeric_source_fields(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(\n            value, {\"port\", \"weight\", \"holddown_interval\", \"max_connections\"}\n        )\n\n\nclass FGVIP(FGContextualModel):''',
    "FGVIPRealServer numeric validation",
)

text = replace_once(
    text,
    '''    comment: Optional[str] = None\n    color: Optional[int] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\nclass FGVIPGroup(FGContextualModel):''',
    '''    comment: Optional[str] = None\n    color: Optional[int] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_numeric_source_fields(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(\n            value, {\"id\", \"gratuitous_arp_interval\", \"max_embryonic_connections\", \"color\"}\n        )\n\nclass FGVIPGroup(FGContextualModel):''',
    "FGVIP numeric validation",
)

text = replace_once(
    text,
    '''    comments: Optional[str] = None\n    comment: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n\nclass FGVIP6(FGContextualModel):''',
    '''    comments: Optional[str] = None\n    comment: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_numeric_source_fields(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(value, {\"color\"})\n\n\nclass FGVIP6(FGContextualModel):''',
    "FGVIPGroup numeric validation",
)

text = replace_once(
    text,
    '''    comment: Optional[str] = None\n    color: Optional[int] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n\nclass FGVIPGroup6(FGContextualModel):''',
    '''    comment: Optional[str] = None\n    color: Optional[int] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_numeric_source_fields(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(value, {\"id\", \"color\"})\n\n\nclass FGVIPGroup6(FGContextualModel):''',
    "FGVIP6 numeric validation",
)

text = replace_once(
    text,
    '''    member: List[str] = Field(default_factory=list)\n    comments: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\nclass FGPolicy(FGContextualModel):''',
    '''    member: List[str] = Field(default_factory=list)\n    comments: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_numeric_source_fields(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(value, {\"color\"})\n\nclass FGPolicy(FGContextualModel):''',
    "FGVIPGroup6 numeric validation",
)

text = replace_once(
    text,
    "    protocol: Optional[str] = None\n    orig_port: Optional[str] = None\n",
    "    protocol: Optional[int] = None\n    orig_port: Optional[str] = None\n",
    "central SNAT protocol type",
)

text = replace_once(
    text,
    '''    port_preserve: str = \"enable\"\n    comments: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n\nclass FGIPTranslation''',
    '''    port_preserve: str = \"enable\"\n    comments: Optional[str] = None\n    extra_settings: Dict[str, Any] = Field(default_factory=dict)\n\n    @model_validator(mode=\"before\")\n    @classmethod\n    def _normalize_protocol(cls, value: Any) -> Any:\n        return _preserve_malformed_int_fields(value, {\"protocol\"})\n\n\nclass FGIPTranslation''',
    "central SNAT protocol normalization",
)

text = replace_once(
    text,
    '''    schedule: Optional[str] = None\n    action: Optional[str] = None\n    srcaddr_negate: Optional[str] = None\n''',
    '''    schedule: Optional[str] = None\n    action: Optional[str] = None\n    comments: Optional[str] = None\n    uuid: Optional[str] = None\n    virtual_patch: Optional[str] = None\n    # FortiOS exposes this only on IPv4 local-in-policy. IPv6 input is\n    # retained as source evidence but is not treated as IPv6 typed semantics.\n    ha_mgmt_intf_only: Optional[str] = None\n    srcaddr_negate: Optional[str] = None\n''',
    "local-in typed metadata",
)

text = replace_once(
    text,
    '''    internet_service6_src_name: List[str] = Field(default_factory=list)\n    internet_service6_src_negate: Optional[str] = None\n\n\nclass FGPolicyRoute''',
    '''    internet_service6_src_name: List[str] = Field(default_factory=list)\n    internet_service6_src_negate: Optional[str] = None\n\n    @model_validator(mode=\"after\")\n    def _keep_ipv4_only_fields_family_safe(self) -> \"FGLocalInPolicy\":\n        if self.address_family == \"ipv6\" and self.ha_mgmt_intf_only is not None:\n            self.extra_settings.setdefault(\"ha_mgmt_intf_only\", self.ha_mgmt_intf_only)\n            self.ha_mgmt_intf_only = None\n        return self\n\n\nclass FGPolicyRoute''',
    "local-in IPv4-only guard",
)

compile(text, str(MODEL), "exec")
MODEL.write_text(text, encoding="utf-8")

TEST.write_text(
    '''import pytest\n\nfrom fwmigrate.parsers.fortigate.extractor import extract_fortigate_config\nfrom fwmigrate.parsers.fortigate.parser import parse_fortigate_config\n\n\ndef test_phase16_local_in_metadata_is_typed_and_stays_source_only():\n    content = \"\"\"\nconfig firewall local-in-policy\n    edit 10\n        set status disable\n        set intf \"wan2\" \"wan1\"\n        set srcaddr \"ADMIN1\" \"ADMIN2\"\n        set dstaddr \"all\"\n        set service \"HTTPS\" \"SSH\"\n        set schedule \"always\"\n        set action accept\n        set comments \"IPv4 management rule\"\n        set uuid \"local-in-v4-uuid\"\n        set virtual-patch enable\n        set ha-mgmt-intf-only enable\n    next\nend\nconfig firewall local-in-policy6\n    edit 20\n        set intf \"wan6\"\n        set srcaddr \"ADMIN6\"\n        set dstaddr \"all\"\n        set service \"HTTPS\"\n        set comments \"IPv6 management rule\"\n        set uuid \"local-in-v6-uuid\"\n        set virtual-patch disable\n    next\nend\n\"\"\"\n    parsed = parse_fortigate_config(content)\n    ipv4, ipv6 = parsed.local_in_policies\n\n    assert ipv4.address_family == \"ipv4\"\n    assert ipv4.intf == [\"wan2\", \"wan1\"]\n    assert ipv4.comments == \"IPv4 management rule\"\n    assert ipv4.uuid == \"local-in-v4-uuid\"\n    assert ipv4.virtual_patch == \"enable\"\n    assert ipv4.ha_mgmt_intf_only == \"enable\"\n    assert ipv4.status == \"disable\"\n\n    assert ipv6.address_family == \"ipv6\"\n    assert ipv6.comments == \"IPv6 management rule\"\n    assert ipv6.uuid == \"local-in-v6-uuid\"\n    assert ipv6.virtual_patch == \"disable\"\n    assert ipv6.ha_mgmt_intf_only is None\n\n    result = extract_fortigate_config(content)\n    assert [rule.family for rule in result.canonical_ir.local_in_policies] == [\n        \"local-in-policy-ipv4\",\n        \"local-in-policy-ipv6\",\n    ]\n    assert result.canonical_ir.policies == []\n    assert result.canonical_ir.nat_rules == []\n    assert result.generation_safe is False\n\n\n@pytest.mark.parametrize(\"ngfw_mode\", [\"policy-based\", \"profile-based\", None])\ndef test_phase17_security_policy_survives_all_ngfw_context_states(ngfw_mode):\n    settings = (\n        f\"config system settings\\n    set ngfw-mode {ngfw_mode}\\nend\\n\"\n        if ngfw_mode is not None\n        else \"\"\n    )\n    content = settings + \"\"\"\nconfig firewall security-policy\n    edit 7\n        set srcintf \"lan\"\n        set dstintf \"wan\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set service \"HTTPS\"\n        set application \"Web.Client\"\n        set groups \"engineering\"\n        set action accept\n    next\nend\n\"\"\"\n\n    parsed = parse_fortigate_config(content)\n    assert len(parsed.security_policies) == 1\n    assert parsed.security_policies[0].ngfw_mode == ngfw_mode\n    assert parsed.policies == []\n\n    result = extract_fortigate_config(content)\n    assert result.canonical_ir.policies == []\n    assert len(result.canonical_ir.security_policies) == 1\n    assert result.canonical_ir.security_policies[0].family == \"security-policy\"\n    assert result.generation_safe is False\n\n\ndef test_phase17_ngfw_mode_is_scoped_per_vdom():\n    content = \"\"\"\nconfig vdom\nedit root\n    config system settings\n        set ngfw-mode policy-based\n    end\n    config firewall security-policy\n        edit 1\n            set srcintf \"any\"\n            set dstintf \"any\"\n            set srcaddr \"all\"\n            set dstaddr \"all\"\n            set service \"ALL\"\n        next\n    end\nnext\nedit tenant\n    config system settings\n        set ngfw-mode profile-based\n    end\n    config firewall security-policy\n        edit 2\n            set srcintf \"any\"\n            set dstintf \"any\"\n            set srcaddr \"all\"\n            set dstaddr \"all\"\n            set service \"ALL\"\n        next\n    end\nnext\nend\n\"\"\"\n    parsed = parse_fortigate_config(content)\n    assert [(p.source_context, p.ngfw_mode) for p in parsed.security_policies] == [\n        (\"root\", \"policy-based\"),\n        (\"tenant\", \"profile-based\"),\n    ]\n\n\n@pytest.mark.parametrize(\n    (\"protocol_line\", \"expected_protocol\", \"expected_unparsed\"),\n    [\n        (\"set protocol 6\", 6, None),\n        (\"\", None, None),\n        (\"set protocol not-a-number\", None, \"not-a-number\"),\n    ],\n)\ndef test_phase18_central_snat_protocol_is_safe_integer(\n    protocol_line, expected_protocol, expected_unparsed\n):\n    content = f\"\"\"\nconfig firewall central-snat-map\n    edit 1\n        set srcintf \"lan\"\n        set dstintf \"wan\"\n        set orig-addr \"all\"\n        set dst-addr \"all\"\n        {protocol_line}\n        set orig-port \"100-200\"\n        set dst-port \"443\"\n        set nat-port \"1024-2048\"\n    next\nend\n\"\"\"\n    parsed = parse_fortigate_config(content)\n    rule = parsed.central_snat_rules[0]\n\n    assert rule.protocol == expected_protocol\n    assert rule.orig_port == \"100-200\"\n    assert rule.dst_port == \"443\"\n    assert rule.nat_port == \"1024-2048\"\n    if expected_unparsed is None:\n        assert \"unparsed_protocol\" not in rule.extra_settings\n    else:\n        assert rule.extra_settings[\"unparsed_protocol\"] == expected_unparsed\n        result = extract_fortigate_config(content)\n        assert len(result.canonical_ir.central_snat_rules) == 1\n        assert result.generation_safe is False\n\n\ndef test_phase19_ip_pool_malformed_numeric_values_are_preserved():\n    content = \"\"\"\nconfig firewall ippool\n    edit \"CGN_POOL\"\n        set type port-block-allocation\n        set startip 203.0.113.10\n        set endip 203.0.113.20\n        set block-size broken\n        set num-blocks-per-user 8\n        set pba-timeout 300\n        set port-per-user 256\n        set cgn-port-start invalid-port\n        set cgn-port-end 65535\n        set exclude-ip 203.0.113.11 203.0.113.12\n    next\nend\n\"\"\"\n    parsed = parse_fortigate_config(content)\n    pool = parsed.ip_pools[0]\n\n    assert pool.type == \"port-block-allocation\"\n    assert pool.block_size is None\n    assert pool.num_blocks_per_user == 8\n    assert pool.pba_timeout == 300\n    assert pool.port_per_user == 256\n    assert pool.cgn_port_start is None\n    assert pool.cgn_port_end == 65535\n    assert pool.exclude_ip == [\"203.0.113.11\", \"203.0.113.12\"]\n    assert pool.extra_settings[\"unparsed_block_size\"] == \"broken\"\n    assert pool.extra_settings[\"unparsed_cgn_port_start\"] == \"invalid-port\"\n\n    result = extract_fortigate_config(content)\n    assert len(result.canonical_ir.ip_pools) == 1\n    assert result.canonical_ir.ip_pools[0].requires_manual_review is True\n\n\ndef test_phase20_vip_realserver_malformed_numbers_do_not_drop_backends():\n    content = \"\"\"\nconfig firewall vip\n    edit \"LB_VIP\"\n        set type server-load-balance\n        set extip 203.0.113.50\n        set color invalid-color\n        config realservers\n            edit 1\n                set ip 10.0.0.10\n                set port bad-port\n                set weight 10\n                set holddown-interval 30\n            next\n            edit 2\n                set ip 10.0.0.11\n                set port 8443\n                set weight bad-weight\n            next\n        end\n    next\nend\nconfig firewall vipgrp\n    edit \"ORDERED\"\n        set member \"VIP_A\" \"VIP_B\" \"VIP_C\"\n    next\nend\n\"\"\"\n    parsed = parse_fortigate_config(content)\n    vip = parsed.vips[0]\n\n    assert vip.color is None\n    assert vip.extra_settings[\"unparsed_color\"] == \"invalid-color\"\n    assert [server.id for server in vip.realservers] == [1, 2]\n    assert vip.realservers[0].port is None\n    assert vip.realservers[0].extra_settings[\"unparsed_port\"] == \"bad-port\"\n    assert vip.realservers[0].weight == 10\n    assert vip.realservers[1].port == 8443\n    assert vip.realservers[1].weight is None\n    assert vip.realservers[1].extra_settings[\"unparsed_weight\"] == \"bad-weight\"\n    assert parsed.vip_groups[0].member == [\"VIP_A\", \"VIP_B\", \"VIP_C\"]\n\n    result = extract_fortigate_config(content)\n    assert len(result.canonical_ir.virtual_ips) == 1\n    assert len(result.canonical_ir.virtual_ips[0].real_servers) == 2\n    assert result.canonical_ir.virtual_ips[0].requires_manual_review is True\n    assert result.canonical_ir.virtual_ip_groups[0].members == [\n        \"VIP_A\",\n        \"VIP_B\",\n        \"VIP_C\",\n    ]\n''',
    encoding="utf-8",
)
