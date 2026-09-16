import io

from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.application.models import MigrationAnalysisResult
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.web import create_app
import fwmigrate.web as web


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
    monkeypatch.setattr(
        web,
        "RuleOptimizer",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("optimizer called")),
    )

    response = _post_file(create_app({"TESTING": True}).test_client())

    assert response.status_code == 200
    data = response.get_json()
    assert data["stats"]["policies"] == 1
    assert data["optimization"] == {"status": "not_analyzed"}
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


def test_explicit_analysis_reuses_pipeline_derived_structures(monkeypatch):
    extraction = _extraction()
    ir = extraction.canonical_ir
    ir_index = object()
    dependency_graph = object()
    metrics = PipelineMetrics()
    metrics.add("extraction", 1.0)
    analysis = MigrationAnalysisResult(
        extraction=extraction,
        source_ir=ir,
        final_ir=ir,
        generation_allowed=True,
        metrics=metrics,
        _ir_index=ir_index,
        _dependency_graph=dependency_graph,
    )
    seen_request = []
    optimizer_args = {}

    class Pipeline:
        def analyze(self, request):
            seen_request.append(request)
            return analysis

    class Optimizer:
        def __init__(self, config, **kwargs):
            assert config is ir
            optimizer_args.update(kwargs)

        def find_unused_objects(self):
            return {"unused_addresses": ["unused"], "unused_services": []}

        def find_duplicate_objects(self):
            return {"duplicate_addresses": [["a", "b"]]}

        def find_shadowed_rules(self):
            return [{"rule": "allow-web"}]

    monkeypatch.setattr(web, "MigrationPipeline", Pipeline)
    monkeypatch.setattr(web, "RuleOptimizer", Optimizer)

    data = _post_file(
        create_app({"TESTING": True}).test_client(),
        path="/api/analyze",
        target_vendor="palo_alto",
        analyze_unused="true",
        analyze_duplicates="true",
        analyze_shadowing="true",
        analyze_capabilities="true",
    ).get_json()

    assert seen_request[0].target_vendor == "palo_alto"
    assert seen_request[0].collect_metrics is True
    assert optimizer_args == {
        "ir_index": ir_index,
        "dependency_graph": dependency_graph,
    }
    assert data["optimization"]["status"] == "analyzed"
    stages = {stage["stage"] for stage in data["diagnostics"]["metrics"]["stages"]}
    assert {"preview_unused", "preview_duplicates", "preview_shadowed", "preview_total"} <= stages


def test_analysis_target_vendor_enables_capabilities_by_default(monkeypatch):
    extraction = _extraction()
    seen_request = []
    analysis = MigrationAnalysisResult(
        extraction=extraction,
        source_ir=extraction.canonical_ir,
        final_ir=extraction.canonical_ir,
        metrics=PipelineMetrics(),
    )

    class Pipeline:
        def analyze(self, request):
            seen_request.append(request)
            return analysis

    monkeypatch.setattr(web, "MigrationPipeline", Pipeline)

    data = _post_file(
        create_app({"TESTING": True}).test_client(),
        path="/api/analyze",
        target_vendor="palo_alto",
    ).get_json()

    assert data["success"] is True
    assert seen_request[0].target_vendor == "palo_alto"
    stages = {stage["stage"] for stage in data["diagnostics"]["metrics"]["stages"]}
    assert "analysis_total" in stages
