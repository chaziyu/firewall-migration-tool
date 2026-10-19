"""Explicit public validation messages; arbitrary exception text stays private."""

# Only fixed literals with no customer values belong in this set.
_SAFE_VALIDATION_MESSAGES = frozenset({
    'A JSON object is required',
    'A signed design approval is required',
    'A signed deterministic draft is required',
    'A signed migration artifact is required',
    'A signed workspace envelope is required',
    'A vendor-native source file or snapshot is required',
    'An interface confirmation request is required',
    'Approved design is stale or modified; prepare and review it again',
    'Approved designs require REVIEW_ONLY planning',
    'Artifact command count or SHA-256 does not match',
    'Artifact commands must be an array of strings',
    'Bundle source does not match the signed artifact',
    'Draft is stale; prepare and review the current configuration',
    'Draft operations require a signed engineer approval',
    'Explicitly include or approve all prerequisite groups',
    'Invalid source evidence',
    'Mapping YAML must contain an object',
    'Migration decision document must be fortigate -> palo_alto',
    'Migration decisions belong to a different source configuration',
    'Migration requires a complete live collection; this source is PARTIAL or FAILED.',
    'Review and approve the deterministic draft before building an artifact',
    'Select unique current proposal groups',
    'Selected target device is not in the uploaded PAN-OS configuration',
    'Service name overrides must select current supported services',
    'Snapshot vendor does not match the requested vendor',
    'Source configuration exceeds the size limit.',
    'Source evidence must be an object',
    'Target-backed approval requires a selected PAN-OS device',
    'Unsupported migration decision document',
    'Unsupported migration rule',
    'Vendor-native source evidence is required',
    'Workspace envelope signature is invalid',
    'apply_to contains a decision outside the current server-validated rule scope',
    'apply_to must be a non-empty array of decision keys',
    'decision_keys must be a non-empty array',
    'decision_keys must contain unique strings',
    'draft overrides must be non-empty strings',
    'draft_overrides must select current decision keys',
    'enabled_policies must be an array of policy names',
    'enabled_policies must contain unique policy names',
    'reference_role must be DESTINATION, TEMPLATE, or null',
})


def safe_validation_message(error, fallback):
    args = error.args
    message = args[0] if len(args) == 1 and type(args[0]) is str else None
    return message if type(error) is ValueError and message in _SAFE_VALIDATION_MESSAGES else fallback
