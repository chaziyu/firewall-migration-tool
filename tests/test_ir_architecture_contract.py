from pathlib import Path

from fwmigrate.ir import IRConfig
from fwmigrate.ir.address import IRAddress
from fwmigrate.ir.config import IRConfig as ConfigRoot
from fwmigrate.ir.core import IRConfig as CoreRoot
from fwmigrate.ir.network import IRZone
from fwmigrate.ir.policy import IRPolicy
from fwmigrate.ir.service import IRService


def test_production_ir_has_one_canonical_root_and_domain_imports():
    assert IRConfig is ConfigRoot is CoreRoot
    assert IRAddress.__name__ == "IRAddress"
    assert IRZone.__name__ == "IRZone"
    assert IRPolicy.__name__ == "IRPolicy"
    assert IRService.__name__ == "IRService"


def test_v2_package_is_not_a_runtime_source():
    source_root = Path(__file__).parents[1] / "src" / "fwmigrate"
    production_python = "\n".join(
        path.read_text(encoding="utf-8")
        for path in source_root.rglob("*.py")
        if "\\v2\\" not in str(path)
    )
    assert "IRConfigV2" not in production_python
    assert "fwmigrate.ir.v2" not in production_python
