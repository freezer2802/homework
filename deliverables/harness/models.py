"""Data shapes passed between the stages. Plain dataclasses, no logic."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class State(str, Enum):
    ACCEPT = "ACCEPT"
    ROUTE_FOR_REVIEW = "ROUTE_FOR_REVIEW"
    REJECT = "REJECT"


@dataclass(frozen=True)
class Finding:
    id: str
    cve: str
    severity: str
    service: str
    package: str
    installed_version: str
    path: str
    fixed_version: str | None
    sla_days_remaining: int
    notes: str = ""


@dataclass(frozen=True)
class FileChange:
    path: str
    op: str                      # "add" | "modify" | "delete"
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyChange:
    package: str
    from_version: str
    to_version: str
    direct: bool                 # False = overriding a transitive / parent-managed version
    produced_by: str             # command that regenerates the manifest/lockfile


@dataclass(frozen=True)
class Proposal:
    """What the agent hands back. Everything here is an untrusted claim."""
    id: str
    finding_id: str
    summary: str
    changes: tuple[FileChange, ...]
    dependency: DependencyChange | None
    agent_claims: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    """Facts the harness gathered itself. None means 'not established'."""
    build_passes: bool | None
    existing_tests_pass: bool | None
    lockfile_reproducible: bool | None
    regression_test_red_to_green: bool | None
    changed_code_covered_by_tests: bool | None      # by any test, incl. the agent's new ones
    covered_by_existing_tests: bool | None          # by tests that existed before the proposal
    agent_test_fingerprint: str | None              # sha256 of the agent's added test lines
    agent_test_approved: bool                       # fingerprint is on the human-approved list
    advisory_fixed_versions: tuple[str, ...]


@dataclass
class Decision:
    proposal_id: str
    finding_id: str
    state: State
    reasons: list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d
