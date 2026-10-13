import ast
import hashlib
import inspect
import json
from pathlib import Path
from typing import ForwardRef, get_args, get_origin

from pydantic import BaseModel
from pydantic_core import PydanticUndefined

from fwmigrate.vendors.cisco_asa import model


CONTRACT = Path(__file__).parents[1] / "fixtures" / "cisco_asa_model_contract.json"


def _type_name(value):
    if isinstance(value, ForwardRef):
        node = ast.parse(value.__forward_arg__, mode="eval").body

        def normalize(item):
            if isinstance(item, ast.Name):
                return {"List": "list", "Dict": "dict", "Tuple": "tuple", "Set": "set"}.get(item.id, item.id)
            if isinstance(item, ast.Attribute):
                return normalize(item.value) + "." + item.attr
            if isinstance(item, ast.Constant):
                return normalize(ast.parse(item.value, mode="eval").body) if isinstance(item.value, str) else str(item.value)
            if isinstance(item, ast.Subscript):
                base = normalize(item.value)
                args = [normalize(arg) for arg in (item.slice.elts if isinstance(item.slice, ast.Tuple) else [item.slice])]
                if base == "Optional":
                    return f"{args[0]}|None"
                return f"{base}[{','.join(args)}]"
            if isinstance(item, ast.BinOp) and isinstance(item.op, ast.BitOr):
                return f"{normalize(item.left)}|{normalize(item.right)}"
            return ast.unparse(item)

        return normalize(node)
    origin = get_origin(value)
    if origin:
        args = [_type_name(arg) for arg in get_args(value)]
        name = getattr(origin, "__name__", str(origin))
        if name in {"Union", "UnionType"}:
            return "|".join(args)
        return f"{name}[{','.join(args)}]"
    if inspect.isclass(value) and issubclass(value, BaseModel):
        return value.__name__
    if value is type(None):
        return "None"
    return getattr(value, "__name__", str(value).replace("typing.", ""))


def _model_fields(cls):
    return {
        name: {
            "type": _type_name(field.annotation),
            "required": field.is_required(),
            "default": None if field.default is PydanticUndefined else field.default,
            "factory": None if field.default_factory is None else getattr(field.default_factory, "__name__", repr(field.default_factory)),
        }
        for name, field in cls.model_fields.items()
    }


def _digest(value):
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def test_model_package_preserves_public_schema_and_serialization():
    expected = json.loads(CONTRACT.read_text(encoding="utf-8"))
    actual_models = {}
    for name, snapshot in expected["models"].items():
        cls = getattr(model, name)
        assert issubclass(cls, BaseModel), name
        fields = _model_fields(cls)
        assert list(fields) == snapshot["fields"], name
        actual_models[name] = {"fields": list(fields), "sha256": _digest(fields)}
    assert actual_models == expected["models"]

    config = model.CiscoASAConfig(
        hostname="asa-contract",
        interfaces=[model.CiscoInterface(name="GigabitEthernet0/0", nameif="outside")],
        network_objects=[model.CiscoNetworkObject(name="host-a", type="host", value="192.0.2.10")],
        static_routes=[model.CiscoStaticRoute(interface="outside", destination="0.0.0.0", mask="0.0.0.0", gateway="192.0.2.1")],
        nat_rules=[model.CiscoNATRule(name="nat-a", real_source="host-a", mapped_source="interface")],
    )
    assert _digest(config.model_dump(mode="json")) == expected["serialized_config_sha256"]


def test_model_package_keeps_aggregate_root_and_domain_boundaries():
    package = Path(model.__file__).parent
    expected = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert not (package.parent / "model.py").exists()
    assert model.CiscoASAConfig.__module__ == f"{model.__name__}.source"
    assert model.CiscoInterface.__module__ == f"{model.__name__}.interface"
    assert model.CiscoNATRule.__module__ == f"{model.__name__}.nat"
    assert set(model.__all__) == set(expected["models"])

    source = (package / "source.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert [node.name for node in tree.body if isinstance(node, ast.ClassDef)] == ["CiscoASAConfig"]
    definitions = []
    for path in package.glob("*.py"):
        if path.name in {"__init__.py", "source.py"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        definitions.extend(node.name for node in tree.body if isinstance(node, ast.ClassDef))
        imports = [
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        ]
        assert not any(
            module.startswith(("relationships", "transform")) or module.endswith(("validation", "source"))
            for module in imports
        ), path.name
    assert len(definitions) == len(set(definitions))
    assert set(definitions) | {"CiscoASAConfig"} == set(expected["models"])
