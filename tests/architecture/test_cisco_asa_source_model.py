import inspect

from pydantic import BaseModel

from fwmigrate.vendors.cisco_asa import model


def _source_models():
    return [
        value
        for value in vars(model).values()
        if inspect.isclass(value)
        and issubclass(value, model.CiscoSourceModel)
        and value is not model.CiscoSourceModel
    ]


def test_asa_source_models_share_explicit_and_unknown_field_contract():
    source_models = _source_models()
    assert source_models
    assert all(issubclass(item, BaseModel) for item in source_models)
    assert all({"explicit_fields", "raw_extra"} <= set(item.model_fields) for item in source_models)
    assert all(item.model_fields["explicit_fields"].annotation == set[str] for item in source_models)


def test_asa_source_models_do_not_store_relationship_or_effective_state():
    for source_model in _source_models():
        for name in source_model.model_fields:
            assert name != "resolved" and not name.startswith("resolved_")
            assert not name.endswith("_resolved") and not name.startswith("effective_")
