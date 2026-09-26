"""Safe, provider-independent AI errors."""


class AIError(RuntimeError):
    pass


class AIDisabledError(AIError):
    pass


class AIConfigurationError(AIError):
    pass


class AIRateLimitError(AIError):
    pass


class AITimeoutError(AIError):
    pass


class AIProviderError(AIError):
    pass


class AIInvalidResponseError(AIError):
    pass


class AIStaleProposalError(AIError):
    pass
