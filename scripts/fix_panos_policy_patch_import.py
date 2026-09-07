from pathlib import Path

path = Path("src/fwmigrate/generators/cisco_asa/cli_generator.py")
text = path.read_text(encoding="utf-8")
old = (
    "from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction\n"
    "from fwmigrate.generators.policy_capabilities import policy_capabilities, NATType"
)
new = (
    "from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType\n"
    "from fwmigrate.generators.policy_capabilities import policy_capabilities"
)
if text.count(old) != 1:
    raise RuntimeError("Expected generated Cisco ASA import form exactly once")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Corrected Cisco ASA policy capability import")
