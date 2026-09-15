from copy import deepcopy
from time import perf_counter

from fwmigrate.application.context import MigrationContext
from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.application.models import MigrationRequest, MigrationResult
from fwmigrate.application.safety import evaluate_generation_safety
from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.capabilities.schema import CapabilityAnalysisResult


class MigrationPipeline:
    """Run the source-to-target migration workflow."""

    def __init__(self, capability_analyzer: CapabilityAnalyzer | None = None):
        self.capability_analyzer = capability_analyzer or CapabilityAnalyzer()

    def run(self, request: MigrationRequest) -> MigrationResult:
        metrics = PipelineMetrics() if request.collect_metrics else None
        started = perf_counter()

        def timed(stage, operation):
            if metrics is None:
                return operation()
            stage_started = perf_counter()
            try:
                return operation()
            finally:
                metrics.add(stage, (perf_counter() - stage_started) * 1000)

        def finish(result: MigrationResult) -> MigrationResult:
            if metrics is not None:
                metrics.total_duration_ms = (perf_counter() - started) * 1000
                result.metrics = metrics
            return result

        parser = PluginRegistry.get_parser(request.source_vendor)
        extraction = timed(
            "extraction",
            lambda: parser.extract(
                request.source_content,
                zone_mapping=request.zone_mapping,
            ),
        )
        context = MigrationContext(request, extraction=extraction, metrics=metrics)
        extracted_ir = extraction.canonical_ir
        if request.source_name and extracted_ir is not None:
            extracted_ir.metadata.input_type = "Configuration File"

        source_ir = timed(
            "source_copy",
            lambda: deepcopy(extracted_ir) if extracted_ir is not None else None,
        )
        source_safety = timed(
            "source_safety",
            lambda: evaluate_generation_safety(extraction, source_ir),
        )
        if not source_safety.allowed:
            return finish(MigrationResult(
                extraction=extraction,
                source_ir=source_ir,
                final_ir=None,
                generation_allowed=False,
                blocking_reasons=source_safety.blocking_reasons,
                requires_manual_review=source_safety.requires_manual_review,
            ))

        ir = timed("working_copy", lambda: deepcopy(source_ir))
        normalization = timed("normalization", lambda: IRNormalizer().normalize(ir))
        ir = normalization.ir
        if normalization.requires_manual_review:
            ir.requires_manual_review = True
        if normalization.blocking_issues:
            ir.generation_safe = False
            ir.generation_blocking_reasons.extend(normalization.blocking_issues)

        timed("index_build", lambda: context.set_ir(ir))
        unused_objects = {}
        if request.optimize or request.prune_unused:
            optimizer = RuleOptimizer(
                ir,
                ir_index=context.ir_index,
                dependency_graph=context.dependency_graph,
            )
            unused_objects = timed("optimization_analysis", optimizer.find_unused_objects)
            ir = timed("optimization_prune", optimizer.prune_unused_objects)
            timed("index_rebuild", lambda: context.set_ir(ir))

        target_spec = timed(
            "target_resolution",
            lambda: PluginRegistry.get_generator_spec(request.target_vendor),
        )
        capability_result = timed(
            "capability_analysis",
            lambda: self.capability_analyzer.analyze(ir, target_spec.vendor_id),
        )
        if not isinstance(capability_result, CapabilityAnalysisResult):
            capability_result = CapabilityAnalysisResult(list(capability_result))
        final_safety = timed(
            "final_safety",
            lambda: evaluate_generation_safety(extraction, ir),
        )
        capability_reasons = [issue.reason for issue in capability_result if issue.blocks_generation]
        if not final_safety.allowed or capability_reasons:
            return finish(MigrationResult(
                extraction=extraction,
                source_ir=source_ir,
                final_ir=ir,
                normalization=normalization,
                unused_objects=unused_objects,
                generation_allowed=False,
                blocking_reasons=list(dict.fromkeys(final_safety.blocking_reasons + capability_reasons)),
                requires_manual_review=(
                    source_safety.requires_manual_review
                    or final_safety.requires_manual_review
                    or capability_result.requires_manual_review
                ),
                capability_analysis=capability_result,
            ))

        if request.target_options:
            generator = PluginRegistry.get_generator(
                request.target_vendor,
                **request.target_options,
            )
        else:
            generator = PluginRegistry.get_generator(request.target_vendor)
        artifacts = timed(
            "generation",
            lambda: generator.generate(ir, format=request.target_format),
        )
        return finish(MigrationResult(
            extraction=extraction,
            source_ir=source_ir,
            final_ir=ir,
            normalization=normalization,
            artifacts=artifacts,
            target_display_name=generator.display_name,
            unused_objects=unused_objects,
            generation_allowed=True,
            requires_manual_review=(
                source_safety.requires_manual_review
                or final_safety.requires_manual_review
                or capability_result.requires_manual_review
            ),
            capability_analysis=capability_result,
        ))
