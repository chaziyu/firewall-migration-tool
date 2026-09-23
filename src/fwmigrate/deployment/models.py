from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PANDeploymentOptions:
    host: str
    username: str
    password: str
    validate: bool = True
    commit: bool = False
