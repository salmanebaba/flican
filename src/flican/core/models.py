from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from math import isfinite
from pathlib import PurePosixPath

RUN_MODES = ("scan", "test", "build", "image", "pipeline")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    CANCELLED = "cancelled"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GateDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    INCOMPLETE = "incomplete"


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Execution timestamps must be UTC strings.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("Invalid execution timestamp.") from error
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("Execution timestamps must include UTC timezone information.")
    return parsed


def _artifacts(paths: tuple[str, ...]) -> None:
    if not isinstance(paths, tuple) or not all(isinstance(path, str) for path in paths):
        raise ValueError("Artifacts must be a tuple of relative paths.")
    if len(paths) != len(set(paths)):
        raise ValueError("Duplicate artifact paths.")
    for path in paths:
        parsed = PurePosixPath(path)
        if (not path or parsed.is_absolute() or ".." in parsed.parts
                or parsed.as_posix() != path or path == "." or "\\" in path
                or any(ord(character) < 32 for character in path)):
            raise ValueError("Artifact paths must be normalized and stay inside the run.")


@dataclass(frozen=True)
class StageResult:
    """Execution outcome; completed stages may contain blocking findings."""

    stage_id: str
    tool: str
    status: StageStatus = StageStatus.PENDING
    required: bool = True
    started_at: str | None = None
    finished_at: str | None = None
    duration_seconds: float | None = None
    exit_code: int | None = None
    findings_count: int | None = None
    artifacts: tuple[str, ...] = ()
    coverage: dict | None = None
    profile_hash: str | None = None
    image: str | None = None
    error: str | None = None


    def __post_init__(self):
        if not all(isinstance(value, str) and value.strip() for value in (self.stage_id, self.tool)):
            raise ValueError("A stage must have an ID and tool name.")
        if not isinstance(self.status, StageStatus) or type(self.required) is not bool:
            raise ValueError("Invalid stage status or required flag.")
        _artifacts(self.artifacts)
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError("Stage exit codes must be integers.")
        if self.coverage is not None and not isinstance(self.coverage, dict):
            raise ValueError("Stage coverage must be an object.")
        if self.error is not None and (not isinstance(self.error, str) or not self.error.strip()):
            raise ValueError("Stage errors/reasons must be non-empty strings.")
        for value in (self.profile_hash, self.image):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError("Stage profile and image must be non-empty strings.")
        start = _timestamp(self.started_at) if self.started_at is not None else None
        finish = _timestamp(self.finished_at) if self.finished_at is not None else None
        if start and finish and finish < start:
            raise ValueError("A stage cannot finish before it starts.")
        if self.status in (StageStatus.PENDING, StageStatus.RUNNING):
            if (finish is not None or self.duration_seconds is not None or self.exit_code is not None
                    or self.findings_count is not None or self.artifacts or self.coverage is not None or self.error):
                raise ValueError("An unfinished stage cannot contain a final result.")
            if (self.status == StageStatus.RUNNING) != (start is not None):
                raise ValueError("Only running stages have a start time before completion.")
            return
        if finish is None or (type(self.duration_seconds) not in (int, float)
                              or not isfinite(self.duration_seconds) or self.duration_seconds < 0):
            raise ValueError("Terminal stages need a finish time and finite non-negative duration.")
        if self.status in (StageStatus.COMPLETED, StageStatus.FAILED, StageStatus.TIMED_OUT) and start is None:
            raise ValueError("Executed stages need a start time.")
        if self.status == StageStatus.COMPLETED:
            if (self.exit_code is None or type(self.findings_count) is not int
                    or self.findings_count < 0 or self.error is not None):
                raise ValueError("Completed stages need an exit code and finding count, without an error.")
        elif self.findings_count is not None or self.artifacts or self.coverage is not None or self.error is None:
            raise ValueError("Unsuccessful stages need a reason and cannot claim usable findings/artifacts.")

    def to_dict(self) -> dict:
        result = asdict(self)
        result.update(status=self.status.value, artifacts=list(self.artifacts))
        return result

    @classmethod
    def from_dict(cls, raw: dict) -> "StageResult":
        try:
            values = dict(raw) if isinstance(raw, dict) else {}
            values["status"] = StageStatus(values["status"])
            if not isinstance(values.get("artifacts"), list):
                raise ValueError("Stage artifacts must be a JSON array.")
            values["artifacts"] = tuple(values["artifacts"])
            return cls(**values)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Invalid serialized stage result.") from error


@dataclass(frozen=True)
class Run:
    """Versioned scan execution journal, separate from its policy decision."""

    run_id: str
    project_name: str
    project_path: str
    started_at: str
    policy_threshold: Severity
    stages: tuple[StageResult, ...]
    schema_version: int = 1
    mode: str = "scan"
    status: RunStatus = RunStatus.RUNNING
    finished_at: str | None = None
    decision: GateDecision | None = None
    exit_code: int | None = None
    artifacts: tuple[str, ...] = ()
    error: str | None = None
    source_sha256: str | None = None

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != 1 or self.mode not in RUN_MODES:
            raise ValueError("Unsupported run schema or mode.")
        if self.source_sha256 is not None and (not isinstance(self.source_sha256, str)
                or len(self.source_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.source_sha256)):
            raise ValueError("The source identity must be a SHA-256 hex digest.")
        if not all(isinstance(value, str) and value.strip()
                   for value in (self.run_id, self.project_name, self.project_path)):
            raise ValueError("Run identity and project must be non-empty strings.")
        if not isinstance(self.status, RunStatus) or not isinstance(self.policy_threshold, Severity):
            raise ValueError("Invalid run status or policy threshold.")
        if (not isinstance(self.stages, tuple) or not self.stages
                or not all(isinstance(stage, StageResult) for stage in self.stages)
                or len({stage.stage_id for stage in self.stages}) != len(self.stages)):
            raise ValueError("Runs require stages with unique IDs.")
        _artifacts(self.artifacts)
        start = _timestamp(self.started_at)
        if any(stage.started_at is not None and _timestamp(stage.started_at) < start for stage in self.stages):
            raise ValueError("A stage cannot start before its run.")
        if self.error is not None and (not isinstance(self.error, str) or not self.error.strip()):
            raise ValueError("Run errors must be non-empty strings.")
        if self.status == RunStatus.RUNNING:
            if self.finished_at is not None or self.decision is not None or self.exit_code is not None or self.error:
                raise ValueError("Running executions cannot claim a final decision.")
            return
        if self.finished_at is None or _timestamp(self.finished_at) < start:
            raise ValueError("Finished runs need an ordered UTC finish time.")
        if any(stage.finished_at is not None and _timestamp(stage.finished_at) > _timestamp(self.finished_at)
               for stage in self.stages):
            raise ValueError("A stage cannot finish after its run.")
        if any(stage.status in (StageStatus.PENDING, StageStatus.RUNNING) for stage in self.stages):
            raise ValueError("A finished run cannot contain unfinished stages.")
        if not isinstance(self.decision, GateDecision) or type(self.exit_code) is not int:
            raise ValueError("Finished runs need a decision and exit code.")
        if self.status == RunStatus.COMPLETED:
            expected = {GateDecision.ALLOW: 0, GateDecision.BLOCK: 1}.get(self.decision)
            if (expected is None or self.exit_code != expected or self.error
                    or any(stage.required and stage.status != StageStatus.COMPLETED for stage in self.stages)):
                raise ValueError("Completed runs require usable stages and an allow/block decision.")
            if self.mode == "pipeline" and (
                any(stage.status == StageStatus.COMPLETED and stage.exit_code == 1 for stage in self.stages)
                != (self.decision == GateDecision.BLOCK)
            ):
                raise ValueError("A workflow decision must preserve every child gate result.")
        elif self.decision != GateDecision.INCOMPLETE or self.exit_code != 2:
            raise ValueError("Failed/cancelled runs must have an incomplete decision and exit code 2.")
        elif self.error is None and all(stage.status == StageStatus.COMPLETED for stage in self.stages):
            raise ValueError("Unsuccessful runs need a failure or cancellation reason.")

    def to_dict(self) -> dict:
        result = asdict(self)
        result.update(status=self.status.value, policy_threshold=self.policy_threshold.value,
                      decision=self.decision.value if self.decision is not None else None,
                      stages=[stage.to_dict() for stage in self.stages], artifacts=list(self.artifacts))
        return result

    @classmethod
    def from_dict(cls, raw: dict) -> "Run":
        try:
            values = dict(raw) if isinstance(raw, dict) else {}
            values["status"] = RunStatus(values["status"])
            values["policy_threshold"] = Severity(values["policy_threshold"])
            if values.get("decision") is not None:
                values["decision"] = GateDecision(values["decision"])
            if not isinstance(values.get("stages"), list) or not isinstance(values.get("artifacts"), list):
                raise ValueError("Run stages/artifacts must be JSON arrays.")
            values["stages"] = tuple(StageResult.from_dict(stage) for stage in values["stages"])
            values["artifacts"] = tuple(values["artifacts"])
            return cls(**values)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Invalid serialized run.") from error

@dataclass(frozen=True)
class Finding:
    """A security finding in Flican's common format."""

    scanner: str
    rule_id: str
    description: str
    severity: Severity
    file_path: str | None
    line: int | None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    resource_id: str | None = None
    severity_source: str | None = None
    framework: str | None = None
    column: int | None = None
