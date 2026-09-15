"""FortiGate CLI target-scope rendering for mapped source VDOM contexts."""

from __future__ import annotations

from typing import Any, Mapping

from fwmigrate.core.base_generator import MigrationArtifact


def _same_context(value: str | None, expected: str) -> bool:
    return (value or "root") == expected


def _ir_for_context(ir: Any, source_context: str) -> Any:
    scoped = ir.model_copy(deep=True)
    for field_name in scoped.__class__.model_fields:
        value = getattr(scoped, field_name, None)
        if not isinstance(value, list) or not value:
            continue
        if not any(hasattr(item, "source_context") for item in value):
            continue
        filtered = [
            item
            for item in value
            if not hasattr(item, "source_context")
            or _same_context(getattr(item, "source_context", None), source_context)
        ]
        setattr(scoped, field_name, filtered)
    scoped.generation_safe = True
    scoped.generation_blocking_reasons = []
    return scoped


def generate_context_mapped_cli(
    ir: Any,
    context_mapping: Mapping[str, str],
    cli_generator_cls: type,
) -> list[MigrationArtifact]:
    """Render each source VDOM into its explicitly mapped FortiGate VDOM."""
    lines = [
        "# ====================================================",
        "# FortiOS multi-VDOM configuration generated from explicit context mapping",
        "# ====================================================",
        "",
        "config vdom",
    ]
    for source_context, target_scope in context_mapping.items():
        scoped_ir = _ir_for_context(ir, source_context)
        artifacts = cli_generator_cls().generate(scoped_ir)
        cli_artifact = next((artifact for artifact in artifacts if artifact.format == "cli"), None)
        if cli_artifact is None:
            raise ValueError(
                f"FortiGate CLI generator produced no CLI artifact for source context '{source_context}'"
            )
        escaped_scope = str(target_scope).replace('"', '\\"')
        lines.append(f'    edit "{escaped_scope}"')
        lines.append(f"        # Source VDOM: {source_context}")
        lines.extend(cli_artifact.content.rstrip().splitlines())
        lines.append("    next")
    lines.append("end")
    lines.append("")
    return [
        MigrationArtifact(
            filename="fortigate_config.conf",
            content="\n".join(lines),
            format="cli",
        )
    ]


__all__ = ["generate_context_mapped_cli"]
