from copy import deepcopy
from time import perf_counter

from fwmigrate.application.context import MigrationContext
from fwmigrate.application.context_mapping import apply_context_mapping
from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.application.models import (
    MigrationAnalysisResult,
    MigrationRequest,
    MigrationResult,
)
from fwmigrate.application.safety import evaluate_generation_safety
from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.capabilities.loader import CapabilityLoader
from fwmigrate.capabilities.schema import CapabilityAnalysisResult
from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.validation.validators import validate_ir


class MigrationPipeline:
    """Run the source-to-target migration workflow."""

    def __init__(
        self,
        capability_analyzer: CapabilityAnalyzer | None = None,
        capability_loader: CapabilityLoader | None = None,
    ):
        self.capability_analyzer = capability_analyzer
        self.capability_loader = (
            capability_loader if capability_loader is not None else CapabilityLoader()
        )

    def _resolve_capability_analyzer(
        self, vendor_id: str, target_version: str | None,
    ) -> CapabilityAnalyzer:
        if self.capability_analyzer is not None:
            return self.capability_analyzer
        try:
            profile = self.capability_loader.load_profile(vendor_id, target_version)
        except FileNotFoundError:
            # Phase 8 enables fail-closed enforcement once reviewed profiles exist.
            return CapabilityAnalyzer()
        return CapabilityAnalyzer(profile)

    def analyze(self, request: MigrationRequest) -> MigrationAnalysisResult:
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

        def finish(result: MigrationAnalysisResult) -> MigrationAnalysisResult:
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
        timed("context_mapping", lambda: apply_context_mapping(request, extraction))
        context = MigrationContext(request, extraction=extraction, metrics=metrics)
        extracted_ir = extraction.canonical_ir
        if request.source_name and extracted_ir is not None:
            extracted_ir.metadata.input_type = "Configuration File"

        source_ir = extracted_ir
        source_safety = timed(
            "source_safety",
            lambda: evaluate_generation_safety(extraction, source_ir),
        )
        if not source_safety.allowed:
            return finish(MigrationAnalysisResult(
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

        validation_result = timed(
            "validation",
            lambda: validate_ir(ir, ir_index=context.ir_index),
        )
        context.validation_result = validation_result

        capability_result = None
        if request.target_vendor:
            target_spec = timed(
                "target_resolution",
                lambda: PluginRegistry.get_generator_spec(request.target_vendor),
            )
            capability_analyzer = self._resolve_capability_analyzer(
                target_spec.vendor_id, request.target_version,
            )
            capability_result = timed(
                "capability_analysis",
                lambda: capability_analyzer.analyze(ir, target_spec.vendor_id),
            )
            if not isinstance(capability_result, CapabilityAnalysisResult):
                capability_result = CapabilityAnalysisResult(list(capability_result))

        final_safety = timed(
            "final_safety",
            lambda: evaluate_generation_safety(
                extraction, ir, validation_result.blocking_reasons,
            ),
        )
        capability_reasons = [
            issue.reason
            for issue in capability_result or []
            if issue.blocks_generation
        ]
        return finish(MigrationAnalysisResult(
            extraction=extraction,
            source_ir=source_ir,
            final_ir=ir,
            normalization=normalization,
            unused_objects=unused_objects,
            generation_allowed=final_safety.allowed and not capability_reasons,
            blocking_reasons=list(dict.fromkeys(
                final_safety.blocking_reasons + capability_reasons
            )),
            requires_manual_review=(
                source_safety.requires_manual_review
                or final_safety.requires_manual_review
                or bool(capability_result and capability_result.requires_manual_review)
            ),
            capability_analysis=capability_result,
            validation_result=validation_result,
        ))

    def run(self, request: MigrationRequest) -> MigrationResult:
        analysis = self.analyze(request)
        if not analysis.generation_allowed:
            return MigrationResult(
                extraction=analysis.extraction,
                source_ir=analysis.source_ir,
                final_ir=analysis.final_ir,
                normalization=analysis.normalization,
                unused_objects=analysis.unused_objects,
                generation_allowed=False,
                blocking_reasons=analysis.blocking_reasons,
                requires_manual_review=analysis.requires_manual_review,
                capability_analysis=analysis.capability_analysis,
                validation_result=analysis.validation_result,
                metrics=analysis.metrics,
            )

        generator_options = dict(request.target_options)
        if request.context_mapping:
            generator_options["context_mapping"] = dict(request.context_mapping)
        if generator_options:
            generator = PluginRegistry.get_generator(
                request.target_vendor,
                **generator_options,
            )
        else:
            generator = PluginRegistry.get_generator(request.target_vendor)

        generation_started = perf_counter()
        try:
            artifacts = generator.generate(
                analysis.final_ir, format=request.target_format,
            )
        finally:
            if analysis.metrics is not None:
                generation_ms = (perf_counter() - generation_started) * 1000
                analysis.metrics.add("generation", generation_ms)
                analysis.metrics.total_duration_ms += generation_ms

        return MigrationResult(
            extraction=analysis.extraction,
            source_ir=analysis.source_ir,
            final_ir=analysis.final_ir,
            normalization=analysis.normalization,
            artifacts=artifacts,
            target_display_name=generator.display_name,
            unused_objects=analysis.unused_objects,
            generation_allowed=True,
            requires_manual_review=analysis.requires_manual_review,
            capability_analysis=analysis.capability_analysis,
            validation_result=analysis.validation_result,
            metrics=analysis.metrics,
        )
