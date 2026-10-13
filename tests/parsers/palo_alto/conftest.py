import pytest
from pydantic import BaseModel


@pytest.fixture
def assert_source_contract():
    def check(model, config):
        assert isinstance(model, BaseModel)
        assert isinstance(model.raw_extra, dict)
        assert isinstance(model.explicit_fields, set)
        assert model.source_path
        assert model.scope is not None
        assert config.source_inventory
        assert any(record.source_path == model.source_path for record in config.source_inventory)

    return check
