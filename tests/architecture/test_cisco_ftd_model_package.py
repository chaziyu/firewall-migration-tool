import ast
import hashlib
import json
import typing
import subprocess
import sys
from pathlib import Path

from pydantic_core import PydanticUndefined

from fwmigrate.vendors.cisco_ftd import model


CONTRACT = Path(__file__).parents[1] / "fixtures" / "cisco_ftd_model_contract.json"


def _type_name(value):
    if isinstance(value, typing.ForwardRef):
        return ast.unparse(ast.parse(value.__forward_arg__, mode="eval").body)
    origin = typing.get_origin(value)
    if origin:
        return getattr(origin, "__name__", str(origin)) + "[" + ",".join(
            _type_name(item) for item in typing.get_args(value)
        ) + "]"
    return getattr(value, "__name__", str(value).replace("typing.", ""))


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _model_metadata(cls):
    cls.model_rebuild(_types_namespace=vars(model))
    return [
        (key, _type_name(field.annotation), field.is_required(),
         None if field.default is PydanticUndefined else repr(field.default),
         None if field.default_factory is None else getattr(field.default_factory, "__name__", repr(field.default_factory)),
         field.alias)
        for key, field in cls.model_fields.items()
    ]


def test_model_package_preserves_public_schema_and_serialization():
    expected = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert model.__all__ == list(expected["models"])
    for name, snapshot in expected["models"].items():
        cls = getattr(model, name)
        if "fields" not in snapshot:
            assert ("enum" if hasattr(cls, "__members__") else "other") == snapshot["kind"]
            continue
        metadata = _model_metadata(cls)
        fields = cls.model_fields
        assert list(fields) == snapshot["fields"], name
        if expected.get("nullable_source_record_name") and issubclass(cls, model.CiscoFTDSourceRecord):
            name_field = fields["name"]
            assert not name_field.is_required() and name_field.default is None
            assert type(None) in typing.get_args(name_field.annotation)
            metadata[0] = ("name", "str", True, None, None, None)
        assert _digest(metadata) == snapshot["sha256"], name
    config = model.CiscoFTDConfig(network_addresses=[model.CiscoFTDNetworkAddress(name="host", source_plane="fmc-rest-bundle", value="192.0.2.1")])
    assert _digest(config.model_dump(mode="json")) == expected["serialized_config_sha256"]


def test_contract_is_independent_of_ipv6_parser_initialization():
    script = (
        "import runpy\n"
        f"contract = runpy.run_path({str(Path(__file__).resolve())!r})\n"
        "check = contract['test_model_package_preserves_public_schema_and_serialization']\n"
        "check()\n"
        "from fwmigrate.vendors.cisco_ftd.source_analysis import extract_cisco_ftd_source\n"
        "extract_cisco_ftd_source('interface inside\\n ipv6 address 2001:db8::1/64\\n')\n"
        "check()\n"
    )
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_model_package_has_one_definition_per_public_class():
    package = Path(model.__file__).parent
    assert not (package.parent / "model.py").exists()
    definitions = [
        node.name
        for path in package.glob("*.py") if path.name != "__init__.py"
        for node in ast.parse(path.read_text(encoding="utf-8")).body
        if isinstance(node, ast.ClassDef)
    ]
    assert len(definitions) == len(set(definitions))
    assert set(definitions) == set(model.__all__)
    assert all(getattr(model, name).__module__.startswith(model.__name__ + ".")
               for name in model.__all__)
