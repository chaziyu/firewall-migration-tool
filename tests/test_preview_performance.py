import io
import pytest

from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.web import create_app
import fwmigrate.web as web


@pytest.fixture(autouse=True)
def _clear_preview_cache():
    web._PREVIEW_CACHE.clear()
    yield
    web._PREVIEW_CACHE.clear()


def _policy(name, **overrides):
    values = {
        "name": name,
        "from_zone": ["lan"],
        "to_zone": ["wan"],
        "source": ["src"],
        "destination": ["dst"],
        "service": ["https"],
        "action": PolicyAction.ALLOW,
    }
    values.update(overrides)
    return IRPolicy(**values)


def _extraction():
    ir = IRConfig(
        metadata=IRMetadata(hostname="test-firewall", source_vendor="fortigate"),
        policies=[_policy("allow-web")],
    )
    return ExtractionResult(canonical_ir=ir)


def _post_file(client, path="/api/preview", **fields):
    return client.post(
        path,
        data={
            "file": (io.BytesIO(b"config"), "firewall.conf"),
            "source_vendor": "fortigate",
            **fields,
        },
        content_type="multipart/form-data",
    )


def _post_excel(client, *, preview_id=None, source_vendor="fortigate", content=b"config", profile=None):
    data = {
        "file": (io.BytesIO(content), "firewall.conf"),
        "source_vendor": source_vendor,
    }
    if preview_id is not None:
        data["preview_id"] = preview_id
    if profile is not None:
        data["excel_profile"] = profile
    return client.post(
        "/api/extract/excel",
        data=data,
        content_type="multipart/form-data",
    )


def test_preview_extracts_without_full_analysis_or_optimizer(monkeypatch):
    extraction = _extraction()

    class Parser:
        def extract(self, content):
            assert content == "config"
            return extraction

    monkeypatch.setattr(web.PluginRegistry, "get_parser", lambda vendor: Parser())
    monkeypatch.setattr(
        web.MigrationPipeline,
        "analyze",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("full analysis called")),
    )
    monkeypatch.setattr(
        web.PluginRegistry,
        "get_generator_spec",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("target resolution called")),
    )
    response = _post_file(create_app({"TESTING": True}).test_client())

    assert response.status_code == 200
    data = response.get_json()
    assert data["stats"]["policies"] == 1
    assert data["generation_allowed"] == "not_evaluated"
    assert data["extraction"]["generation_safe"] is True


def test_preview_metrics_are_diagnostics_only(monkeypatch):
    extraction = _extraction()
    monkeypatch.setattr(
        web.PluginRegistry,
        "get_parser",
        lambda vendor: type("Parser", (), {"extract": lambda self, content: extraction})(),
    )

    data = _post_file(
        create_app({"TESTING": True}).test_client(),
        collect_metrics="true",
    ).get_json()

    metrics = data["diagnostics"]["metrics"]
    stages = {stage["stage"] for stage in metrics["stages"]}
    assert {"decode", "extraction", "preview_total"} <= stages
    assert "optimization_analysis" not in stages


def test_preview_then_excel_extracts_once_and_returns_preview_id(monkeypatch):
    extraction = _extraction()
    parser_calls = []
    exporter_calls = []

    class Parser:
        def extract(self, content):
            parser_calls.append(content)
            return extraction

    class Exporter:
        def __init__(self, ir, extraction_result=None, options=None):
            exporter_calls.append((ir, extraction_result, options))

        def generate_to(self, output):
            output.write(b"xlsx")

    monkeypatch.setattr(web.PluginRegistry, "get_parser", lambda vendor: Parser())
    monkeypatch.setattr(web, "IRExcelExporter", Exporter)
    monkeypatch.setattr(web, "StreamingFastExcelExporter", Exporter)
    client = create_app({"TESTING": True}).test_client()

    preview = _post_file(client).get_json()
    response = _post_excel(client, preview_id=preview["preview_id"])

    assert response.status_code == 200
    assert parser_calls == ["config"]
    assert exporter_calls[0][2].profile.value == "fast"


def test_excel_profile_routes_fast_to_streaming_and_full_to_existing(monkeypatch):
    extraction = _extraction()
    calls = []

    class Exporter:
        def __init__(self, ir, extraction_result=None, options=None):
            calls.append(options.profile.value)

        def generate_to(self, output):
            output.write(b"xlsx")

    monkeypatch.setattr(web.PluginRegistry, "get_parser", lambda vendor: type(
        "Parser", (), {"extract": lambda self, content: extraction}
    )())
    monkeypatch.setattr(web, "StreamingFastExcelExporter", Exporter)
    monkeypatch.setattr(web, "IRExcelExporter", Exporter)
    client = create_app({"TESTING": True}).test_client()

    assert _post_excel(client, profile="fast").status_code == 200
    assert _post_excel(client, profile="full").status_code == 200
    assert calls == ["fast", "full"]


def test_expired_preview_cache_falls_back_to_extraction(monkeypatch):
    extraction = _extraction()
    calls = []

    class Parser:
        def extract(self, content):
            calls.append(content)
            return extraction

    class Exporter:
        def __init__(self, ir, extraction_result=None, options=None):
            pass

        def generate_to(self, output):
            output.write(b"xlsx")

    monkeypatch.setattr(web.PluginRegistry, "get_parser", lambda vendor: Parser())
    monkeypatch.setattr(web, "IRExcelExporter", Exporter)
    monkeypatch.setattr(web, "StreamingFastExcelExporter", Exporter)
    client = create_app({"TESTING": True}).test_client()
    preview = _post_file(client).get_json()
    monkeypatch.setattr(web, "_PREVIEW_CACHE_TTL_SECONDS", -1)

    response = _post_excel(client, preview_id=preview["preview_id"])

    assert response.status_code == 200
    assert calls == ["config", "config"]


def test_preview_cache_rejects_wrong_vendor_and_unknown_id(monkeypatch):
    extraction = _extraction()
    calls = []

    class Parser:
        def extract(self, content):
            calls.append(content)
            return extraction

    class Exporter:
        def __init__(self, ir, extraction_result=None, options=None):
            pass

        def generate_to(self, output):
            output.write(b"xlsx")

    monkeypatch.setattr(web.PluginRegistry, "get_parser", lambda vendor: Parser())
    monkeypatch.setattr(web, "IRExcelExporter", Exporter)
    monkeypatch.setattr(web, "StreamingFastExcelExporter", Exporter)
    client = create_app({"TESTING": True}).test_client()
    preview = _post_file(client).get_json()

    wrong_vendor = _post_excel(
        client,
        preview_id=preview["preview_id"],
        source_vendor="palo_alto",
    )
    unknown_id = _post_excel(client, preview_id="unknown-preview-id")

    assert wrong_vendor.status_code == 200
    assert unknown_id.status_code == 200
    assert calls == ["config", "config", "config"]


def test_cached_ir_is_not_mutated_by_excel_export(monkeypatch):
    extraction = _extraction()

    class Parser:
        def extract(self, content):
            return extraction

    class Exporter:
        def __init__(self, ir, extraction_result=None, options=None):
            self.ir = ir
            self.extraction_result = extraction_result

        def generate_to(self, output):
            self.ir.metadata.hostname = "mutated"
            self.extraction_result.canonical_ir.metadata.hostname = "also-mutated"
            output.write(b"xlsx")

    monkeypatch.setattr(web.PluginRegistry, "get_parser", lambda vendor: Parser())
    monkeypatch.setattr(web, "IRExcelExporter", Exporter)
    monkeypatch.setattr(web, "StreamingFastExcelExporter", Exporter)
    client = create_app({"TESTING": True}).test_client()
    preview = _post_file(client).get_json()
    entry = web._PREVIEW_CACHE[preview["preview_id"]]
    before_ir = entry.ir_config.model_dump(mode="json")
    before_extraction = entry.extraction_result.model_dump(mode="json")

    response = _post_excel(client, preview_id=preview["preview_id"])

    assert response.status_code == 200
    assert entry.ir_config.model_dump(mode="json") == before_ir
    assert entry.extraction_result.model_dump(mode="json") == before_extraction


def test_real_fast_export_does_not_mutate_cached_preview(monkeypatch):
    extraction = _extraction()

    monkeypatch.setattr(
        web.PluginRegistry,
        "get_parser",
        lambda vendor: type("Parser", (), {"extract": lambda self, content: extraction})(),
    )
    monkeypatch.setattr(
        web,
        "_clone_preview",
        lambda entry: pytest.fail("FAST cache hit should not deep-copy the preview"),
    )
    client = create_app({"TESTING": True}).test_client()
    preview = _post_file(client).get_json()
    entry = web._PREVIEW_CACHE[preview["preview_id"]]
    before_ir = entry.ir_config.model_dump(mode="json")
    before_extraction = entry.extraction_result.model_dump(mode="json")

    response = _post_excel(client, preview_id=preview["preview_id"], profile="fast")

    assert response.status_code == 200
    assert entry.ir_config.model_dump(mode="json") == before_ir
    assert entry.extraction_result.model_dump(mode="json") == before_extraction


def test_invalid_excel_profile_fails_safely(monkeypatch):
    response = _post_excel(create_app({"TESTING": True}).test_client(), profile="not-a-profile")

    assert response.status_code == 400
    assert "excel_profile" in response.get_json()["error"]
