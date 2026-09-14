from __future__ import annotations

from copy import deepcopy
from typing import List

from fwmigrate.application.models import MigrationRequest, MigrationResult
from fwmigrate.application.safety import MigrationSafetyEvaluator
from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.core.normalizer import RuleNormalizer
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.validation.validators import (
    DependencyValidator,
    SafetyValidator,
    SchemaValidator,
    SemanticValidator,
)


def _validate(ir) -> list:
    issues: List[object] = []
    for validator in (
        SchemaValidator(),
        SafetyValidator(),
        DependencyValidator(),
        SemanticValidator(),
    ):
        issues.extend(validator.validate(ir) or [])
    return issues


class MigrationPipeline:
    """Run the source -> canonical IR -> validation -> generation workflow."""

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
        evaluator = MigrationSafetyEvaluator()
        extraction_safety = evaluator.evaluate_extraction(extraction)
        if not extraction_safety.allowed:
            return MigrationResult(
                extraction=extraction,
                source_ir=source_ir,
                final_ir=source_ir,
                generation_allowed=False,
                blocking_reasons=extraction_safety.blocking_reasons,
                requires_manual_review=extraction_safety.requires_manual_review,
                warnings=extraction_safety.warnings,
                safety_decisions=[extraction_safety],
                safety_issues=extraction_safety.issues,
            )

        validation_issues = _validate(source_ir) if source_ir is not None else []
        capability_issues = (
            CapabilityAnalyzer().analyze(source_ir, request.target_vendor)
            if source_ir is not None
            else []
        )
        # The central evaluator owns the application safety decision; user-facing
        # adapters only format its result.
        source_safety = evaluator.evaluate_pre_generation(
            extraction,
            source_ir,
            validation_result=validation_issues,
            capability_result=capability_issues,
        )
        if not source_safety.allowed:
            return MigrationResult(
                extraction=extraction,
                source_ir=source_ir,
                final_ir=source_ir,
                generation_allowed=False,
                blocking_reasons=source_safety.blocking_reasons,
                requires_manual_review=source_safety.requires_manual_review,
                warnings=source_safety.warnings,
                safety_decisions=[extraction_safety, source_safety],
                safety_issues=source_safety.issues,
                validation_issues=validation_issues,
                capability_issues=capability_issues,
            )

        ir = deepcopy(source_ir)
        RuleNormalizer(ir).normalize_outbound_threat_source_anomalies()

        unused_objects = {}
        if request.optimize or request.prune_unused:
            optimizer = RuleOptimizer(ir)
            unused_objects = optimizer.find_unused_objects()
            ir = optimizer.prune_unused_objects()

        validation_issues = _validate(ir)
        capability_issues = CapabilityAnalyzer().analyze(ir, request.target_vendor)
        final_safety = evaluator.evaluate_pre_generation(
            extraction,
            ir,
            validation_result=validation_issues,
            capability_result=capability_issues,
        )
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
                warnings=final_safety.warnings,
                safety_decisions=[extraction_safety, source_safety, final_safety],
                safety_issues=final_safety.issues,
                validation_issues=validation_issues,
                capability_issues=capability_issues,
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
            warnings=final_safety.warnings,
            safety_decisions=[extraction_safety, source_safety, final_safety],
            safety_issues=final_safety.issues,
            validation_issues=validation_issues,
            capability_issues=capability_issues,
        )
