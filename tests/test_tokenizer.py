import pytest
from fg2pan.parser.tokenizer import FortiGateTokenizer, TokenType, TokenizerError

def test_tokenize_basic_block():
    config = """
config system global
    set hostname "GENE-FW2"
    set admin-sport 8443
end
    """
    tokenizer = FortiGateTokenizer(config)
    tokens = list(tokenizer.tokenize())
    
    assert tokens[0].type == TokenType.CONFIG
    assert tokens[0].value == "config"
    assert tokens[1].type == TokenType.STRING
    assert tokens[1].value == "system"
    assert tokens[2].type == TokenType.STRING
    assert tokens[2].value == "global"
    
    assert tokens[3].type == TokenType.SET
    assert tokens[4].type == TokenType.STRING
    assert tokens[4].value == "hostname"
    assert tokens[5].type == TokenType.STRING
    assert tokens[5].value == "GENE-FW2"
    
    assert tokens[6].type == TokenType.SET
    assert tokens[7].type == TokenType.STRING
    assert tokens[7].value == "admin-sport"
    assert tokens[8].type == TokenType.STRING
    assert tokens[8].value == "8443"
    
    assert tokens[9].type == TokenType.END

def test_tokenize_quotes_and_spaces():
    config = """
config firewall vip
    edit "deleumeform.com_60.53.219.68"
        set extip 60.53.219.68
        set mappedip "192.168.42.26"
    next
end
    """
    tokenizer = FortiGateTokenizer(config)
    tokens = list(tokenizer.tokenize())
    
    assert tokens[3].type == TokenType.EDIT
    assert tokens[4].type == TokenType.STRING
    assert tokens[4].value == "deleumeform.com_60.53.219.68"  # Quotes removed by shlex
    
    assert tokens[10].type == TokenType.STRING
    assert tokens[10].value == "192.168.42.26"

def test_tokenize_comments():
    config = """
# This is a comment
config system global # Inline comments are not supported by shlex in this simple way usually
    set hostname "FW1"
end
    """
    tokenizer = FortiGateTokenizer(config)
    tokens = list(tokenizer.tokenize())
    
    assert tokens[0].type == TokenType.COMMENT
    assert tokens[1].type == TokenType.CONFIG

def test_tokenize_multivalue_set():
    config = 'set member "A" "B" "C"'
    tokenizer = FortiGateTokenizer(config)
    tokens = list(tokenizer.tokenize())
    
    assert tokens[0].type == TokenType.SET
    assert tokens[1].value == "member"
    assert tokens[2].value == "A"
    assert tokens[3].value == "B"
    assert tokens[4].value == "C"

def test_tokenize_encrypted_string():
    config = 'set password ENC Pap7dAApUjN6xDPLgkKfd3/Db4p8osP8yCrVOBV4ut5E+zZ/r2ay72BcO97MgrjwsG5stTtqs/JYkVGdFZpayM5L7LUiGwYBFA0ftTSBUNLjfneWJWi+qywA4o6jbvsujcgZFU9vKq3MzCoPsrUDVK5CYsCxP74++GigxeGFUWsaM0EV5Qlqu9JZIbLsEmzUVtMTl1lmMjY3dkVA'
    tokenizer = FortiGateTokenizer(config)
    tokens = list(tokenizer.tokenize())
    
    assert tokens[0].type == TokenType.SET
    assert tokens[1].value == "password"
    assert tokens[2].value == "ENC"
    assert tokens[3].value.startswith("Pap7d")
