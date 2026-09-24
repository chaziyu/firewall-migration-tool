from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PANDeploymentCommandResult:
    index: int
    command: str
    accepted: bool
    response: str = ""


@dataclass(frozen=True, slots=True)
class PANValidationResult:
    job_id: str | None = None
    status: str = "NOT_RUN"
    response: str = ""


@dataclass(frozen=True, slots=True)
class PANCommitResult:
    job_id: str | None = None
    status: str = "NOT_RUN"
    response: str = ""


@dataclass(frozen=True, slots=True)
class PANDeploymentResult:
    connected: bool
    commands_attempted: int = 0
    commands_succeeded: int = 0
    failed_command_index: int | None = None
    failure_message: str | None = None
    command_results: tuple[PANDeploymentCommandResult, ...] = ()
    validation: PANValidationResult = field(default_factory=PANValidationResult)
    commit: PANCommitResult = field(default_factory=PANCommitResult)


@dataclass(frozen=True, slots=True)
class PANDeploymentOptions:
    host: str
    username: str
    password: str = field(repr=False)
    validate: bool = True
    commit: bool = False
    port: int = 22
