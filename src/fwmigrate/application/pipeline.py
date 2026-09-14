from copy import deepcopy

from fwmigrate.application.models import MigrationRequest, MigrationResult
from fwmigrate.application.safety import evaluate_generation_safety
from fwmigrate.core.normalizer import RuleNormalizer
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.core.registry import PluginRegistry


class MigrationPipeline:
    """Run the source-to-target migration workflow."""

    def run(self, request: MigrationRequest) -> MigrationResult:
        parser = PluginRegistry.get_parser(request.source_vendor)
        extraction = parser.extract(
            request.source_content,
            zone_mapping=request.zone_mapping,
        )
        extracted_ir = extraction.canonical_ir
        if request.source_name and extracted_ir is not None:
            extracted_ir.metadata.input_type = "Configuration File"

        source_ir = deepcopy(extracted_ir) if extracted_ir is not None else None
        source_safety = evaluate_generation_safety(extraction, source_ir)
        if not source_safety.allowed:
            return MigrationResult(
                extraction=extraction,
                source_ir=source_ir,
                final_ir=None,
                generation_allowed=False,
                blocking_reasons=source_safety.blocking_reasons,
                requires_manual_review=source_safety.requires_manual_review,
            )

        ir = deepcopy(source_ir)
        RuleNormalizer(ir).normalize_outbound_threat_source_anomalies()

        unused_objects = {}
        if request.optimize or request.prune_unused:
            optimizer = RuleOptimizer(ir)
            unused_objects = optimizer.find_unused_objects()
            ir = optimizer.prune_unused_objects()

        final_safety = evaluate_generation_safety(extraction, ir)
        if not final_safety.allowed:
            return MigrationResult(
                extraction=extraction,
                source_ir=source_ir,
                final_ir=ir,
                unused_objects=unused_objects,
                generation_allowed=False,
                blocking_reasons=final_safety.blocking_reasons,
                requires_manual_review=(
                    source_safety.requires_manual_review
                    or final_safety.requires_manual_review
                ),
            )

        if request.target_options:
            generator = PluginRegistry.get_generator(
                request.target_vendor,
                **request.target_options,
            )
        else:
            generator = PluginRegistry.get_generator(request.target_vendor)
        artifacts = generator.generate(ir, format=request.target_format)
        return MigrationResult(
            extraction=extraction,
            source_ir=source_ir,
            final_ir=ir,
            artifacts=artifacts,
            target_display_name=generator.display_name,
            unused_objects=unused_objects,
            generation_allowed=True,
            requires_manual_review=(
                source_safety.requires_manual_review
                or final_safety.requires_manual_review
            ),
        )
