from copy import deepcopy
from dataclasses import fields, is_dataclass
from enum import Enum


def snapshot_source(config):
    return deepcopy(config.model_dump(mode="python"))


def assert_source_unchanged(config, snapshot):
    assert config.model_dump(mode="python") == snapshot


def snapshot_value(value, active=None):
    if isinstance(value, (str, int, float, bool, bytes, type(None), type, Enum)):
        return value
    active = set() if active is None else active
    identity = id(value)
    if identity in active:
        return ("cycle", type(value).__qualname__)
    active.add(identity)
    if hasattr(value, "model_dump"):
        result = snapshot_value(value.model_dump(mode="python"), active)
    elif is_dataclass(value):
        result = {field.name: snapshot_value(getattr(value, field.name), active) for field in fields(value)}
    elif isinstance(value, dict):
        result = {key: snapshot_value(item, active) for key, item in value.items()}
    elif isinstance(value, (list, tuple)):
        result = type(value)(snapshot_value(item, active) for item in value)
    elif hasattr(value, "__dict__"):
        result = {key: snapshot_value(item, active) for key, item in vars(value).items()}
    else:
        result = deepcopy(value)
    active.remove(identity)
    return result


def assert_secret_absent(value, *secret_values):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")
    if isinstance(value, dict):
        values = (*value.keys(), *value.values())
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = (value,)
    for item in values:
        if isinstance(item, (dict, list, tuple, set)) or hasattr(item, "model_dump"):
            assert_secret_absent(item, *secret_values)
        else:
            for secret in secret_values:
                assert secret not in str(item)
