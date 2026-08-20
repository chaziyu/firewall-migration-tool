import re
from typing import Optional, List

class RedactionPolicy:
    """
    Defines how sensitive strings should be scrubbed from output and audit logs.
    """
    
    def __init__(self, secrets: Optional[List[str]] = None):
        self.secrets = [s for s in (secrets or []) if s and len(s) >= 3]

    def redact(self, text: str) -> str:
        """Mask credentials and sensitive strings in text."""
        if not text:
            return ""

        redacted = text

        # Redact explicitly provided secret strings
        for sec in self.secrets:
            redacted = redacted.replace(sec, "******")

        # Generic patterns for API keys and passwords in HCL, JSON, YAML, or URL encoded
        redacted = re.sub(
            r'((?:api_key|password|psk|secret|key|token)[\s=:\'"]+)([^"\',\s&]+)',
            r'\1******',
            redacted,
            flags=re.IGNORECASE
        )

        return redacted

# Singleton helper for general redaction where specific secrets aren't known
default_redactor = RedactionPolicy()

def redact_sensitive(text: str, secrets: Optional[List[str]] = None) -> str:
    """Convenience wrapper for RedactionPolicy."""
    policy = RedactionPolicy(secrets)
    return policy.redact(text)
