from typing import List, Dict
from collections import defaultdict
from fg2pan.ir.core import IRConfig, IRAuditEntry, MigrationConfidence

class MigrationReporter:
    def __init__(self, ir: IRConfig):
        self.ir = ir
        
    def generate_report(self) -> str:
        report = []
        report.append("# Migration Report")
        report.append(f"**Hostname:** {self.ir.metadata.hostname}")
        report.append(f"**Date:** {self.ir.metadata.migration_timestamp}")
        
        # Calculate stats
        total_objects = (
            len(self.ir.interfaces) + len(self.ir.addresses) + len(self.ir.address_groups) +
            len(self.ir.services) + len(self.ir.service_groups) + len(self.ir.policies) +
            len(self.ir.nat_rules) + len(self.ir.vpn_tunnels) + len(self.ir.routes)
        )
        
        confidence_counts = defaultdict(int)
        for entry in self.ir.audit_entries:
            confidence_counts[entry.confidence] += 1
            
        # Assuming everything without an audit entry is FULL confidence
        confidence_counts[MigrationConfidence.FULL] += total_objects - len(self.ir.audit_entries)
        
        report.append("\n## Summary")
        report.append(f"- **Total objects processed:** {total_objects}")
        report.append(f"- **Full confidence:** {confidence_counts[MigrationConfidence.FULL]}")
        report.append(f"- **Partial confidence:** {confidence_counts[MigrationConfidence.PARTIAL]}")
        report.append(f"- **Manual review required:** {confidence_counts[MigrationConfidence.MANUAL]}")
        report.append(f"- **Unsupported:** {confidence_counts[MigrationConfidence.UNSUPPORTED]}")
        
        if self.ir.audit_entries:
            report.append("\n## Audit Trail")
            report.append("| Category | Object ID | Confidence | Message |")
            report.append("|----------|-----------|------------|---------|")
            for entry in self.ir.audit_entries:
                report.append(f"| {entry.category} | {entry.id} | {entry.confidence.value.upper()} | {entry.message} |")
                
        return "\n".join(report)
