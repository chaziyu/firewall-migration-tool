from fwmigrate.ir.core import IRIPPool


def test_ippool_audit_fields_are_unique_and_serialized_once():
    field_names = tuple(IRIPPool.model_fields)
    pool = IRIPPool(name="POOL1")
    serialized = pool.model_dump()

    for field_name, default in (
        ("migration_status", "NORMALIZED"),
        ("requires_manual_review", False),
        ("audit_note", None),
    ):
        assert field_names.count(field_name) == 1
        assert list(serialized).count(field_name) == 1
        assert serialized[field_name] == default
