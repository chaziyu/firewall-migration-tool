from pathlib import Path

for name in [
    "documentation/IR_DATA_STRUCTURE.md",
    "documentation/PANOS_PHASE2_FAIL_CLOSED.md",
]:
    path = Path(name)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.rstrip() + "\n", encoding="utf-8")

print("Normalized PAN-OS remediation documentation EOFs")
