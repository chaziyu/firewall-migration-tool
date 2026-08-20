from typing import List, Dict, Any
from fwmigrate.ir.v2.models import IRConfigV2
from fwmigrate.capabilities.schema import VendorCapabilityProfile, FeatureSupport
from fwmigrate.jobs.models import MigrationIssue

class CapabilityAnalyzer:
    """
    Analyzes an IR against a target capability profile to determine translation viability,
    flagging structural loss and creating MigrationIssues for the ledger.
    """
    
    def __init__(self, target_profile: VendorCapabilityProfile):
        self.target_profile = target_profile
        
    def analyze(self, ir_config: IRConfigV2) -> List[MigrationIssue]:
        issues = []
        
        # 1. Analyze global unknown fields
        for key, value in ir_config.global_unknown_fields.items():
            issues.append(
                MigrationIssue(
                    severity="MEDIUM",
                    category="DATA_LOSS",
                    source_object="GlobalConfig",
                    message=f"Global configuration field '{key}' could not be parsed.",
                    blocking=False
                )
            )
            
        # 2. Analyze objects against capability profile
        # E.g., policies
        policy_cap = self.target_profile.objects.get("SecurityRule")
        if policy_cap:
            for idx, policy in enumerate(ir_config.policies):
                if policy_cap.support == FeatureSupport.UNSUPPORTED:
                    issues.append(
                        MigrationIssue(
                            severity="CRITICAL",
                            category="CAPABILITY_MISMATCH",
                            source_object=f"SecurityRule:{policy.name}",
                            target_object="Target:SecurityRule",
                            message="Target platform does not support Security Rules.",
                            blocking=True
                        )
                    )
                    continue
                    
                # Check field level capabilities
                for field_name, field_cap in policy_cap.fields.items():
                    val = getattr(policy, field_name, None)
                    if val and field_cap.support == FeatureSupport.UNSUPPORTED:
                        issues.append(
                            MigrationIssue(
                                severity="HIGH",
                                category="DATA_LOSS",
                                source_object=f"SecurityRule:{policy.name}.{field_name}",
                                message=f"Target platform does not support '{field_name}'. Value will be dropped.",
                                blocking=False
                            )
                        )
                        
                # Check provenance for native structural loss
                if policy.provenance.unknown_fields:
                    issues.append(
                        MigrationIssue(
                            severity="LOW",
                            category="DATA_LOSS",
                            source_object=f"SecurityRule:{policy.name}",
                            message=f"Native structural data lost during parsing: {list(policy.provenance.unknown_fields.keys())}",
                            blocking=False
                        )
                    )
                    
        return issues
