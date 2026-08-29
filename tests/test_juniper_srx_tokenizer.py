import pytest
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JuniperSetTokenizer,
    JunosOperation,
    extract_value_list,
    validate_input_mode,
)

def test_tokenizer_quoted_descriptions_and_bracket_lists():
    content = """
    # Comment line
    /* Multi-line
       block comment */
    set system host-name "SRX-DC-Branch"
    set interfaces ge-0/0/0 description "Core Uplink Port"
    set security address-book global address-set grp1 address [ host1 host2 host3 ]
    set security address-book global address host_secret pre-shared-key ascii-text "SuperSecretPass123"
    set security address-book global address restricted ACCESS-DENIED
    """
    tokenizer = JuniperSetTokenizer()
    cmds = tokenizer.tokenize(content)

    assert len(cmds) == 5
    assert cmds[0].operation == JunosOperation.SET
    assert cmds[0].tokens == ["set", "system", "host-name", "SRX-DC-Branch"]

    assert cmds[1].tokens[4] == "Core Uplink Port"

    # Bracket list
    val_list = extract_value_list(cmds[2].tokens[7:])
    assert val_list == ["host1", "host2", "host3"]

    # Secret sanitization
    assert "SuperSecretPass123" not in cmds[3].raw_sanitized
    assert "[REDACTED]" in cmds[3].raw_sanitized

    # ACCESS-DENIED detection
    assert cmds[4].access_denied is True
    assert cmds[4].requires_manual_review is True

def test_tokenizer_relative_input_rejection():
    # Subordinate tokens starting the command should raise ValueError
    relative_content = "set unit 0 family inet address 10.0.0.1/24"
    tokenizer = JuniperSetTokenizer()
    cmds = tokenizer.tokenize(relative_content)
    with pytest.raises(ValueError, match="relative display-set input detected"):
        validate_input_mode(cmds)

def test_tokenizer_case_preservation_for_names():
    content = "set security address-book global address My_CamelCase_Host 10.1.1.1/32"
    tokenizer = JuniperSetTokenizer()
    cmds = tokenizer.tokenize(content)
    assert cmds[0].tokens[5] == "My_CamelCase_Host"
