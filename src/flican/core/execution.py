"""Progressive, atomic execution checkpoints for a single scan."""

import subprocess
from dataclasses import replace
from pathlib import Path
from time import monotonic

from flican.core.models import GateDecision, Run, RunStatus, StageResult, StageStatus
from flican.core.provenance import utc_now
from flican.core.state import write_private_json


def execution_error(error: BaseException) -> str:
    """Bound diagnostics; never serialize subprocess output or its command."""
    if isinstance(error, subprocess.TimeoutExpired):
        return f"Scanner exceeded its timeout ({error.timeout} seconds)."
    if isinstance(error, subprocess.CalledProcessError):
        return f"Scanner subprocess failed with exit code {error.returncode}."
    return " ".join(str(error).split())[:2000] or type(error).__name__


class RunJournal:
    def __init__(self, root: Path, run: Run):
        if (root.name != run.run_id or run.status != RunStatus.RUNNING
                or any(stage.status != StageStatus.PENDING for stage in run.stages)):
            raise ValueError("A new run journal must match its directory and start with pending stages.")
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root = root
        self.run = run
        self._timers: dict[str, float] = {}
        self._save(run)

    def _save(self, run: Run) -> None:
        write_private_json(self.root / "run.json", run.to_dict())
        self.run = run

    def stage(self, stage_id: str) -> StageResult:
        for stage in self.run.stages:
            if stage.stage_id == stage_id:
                return stage
        raise ValueError("Unknown execution stage.")

    def _update(self, stage: StageResult) -> None:
        if self.run.status != RunStatus.RUNNING:
            raise ValueError("This run already has a final decision.")
        self._save(replace(self.run, stages=tuple(
            stage if previous.stage_id == stage.stage_id else previous for previous in self.run.stages
        )))

    def start(self, stage_id: str) -> None:
        stage = self.stage(stage_id)
        if stage.status != StageStatus.PENDING:
            raise ValueError("Only a pending stage can start.")
        self._timers[stage_id] = monotonic()
        self._update(replace(stage, status=StageStatus.RUNNING, started_at=utc_now()))

    def complete(self, stage_id: str, *, exit_code: int, findings_count: int,
                 artifacts: tuple[str, ...], coverage: dict | None = None) -> None:
        self._finish(stage_id, StageStatus.COMPLETED, exit_code=exit_code,
                     findings_count=findings_count, artifacts=artifacts, coverage=coverage)

    def fail(self, stage_id: str, error: Exception, *, exit_code: int | None = None) -> None:
        status = StageStatus.TIMED_OUT if isinstance(error, subprocess.TimeoutExpired) else StageStatus.FAILED
        self._finish(stage_id, status, exit_code=exit_code, error=execution_error(error))

    def skip(self, stage_id: str, reason: str) -> None:
        """Skip a conditionally inactive stage; the parent must retain its blocking/error decision."""
        stage = self.stage(stage_id)
        if stage.status != StageStatus.PENDING:
            raise ValueError("Only a pending stage can be skipped.")
        if stage.required and (self.run.mode != "pipeline" or not any(
            previous.status == StageStatus.COMPLETED and previous.exit_code == 1 for previous in self.run.stages
        )):
            raise ValueError("A required stage can be skipped only after a completed workflow gate blocks.")
        self._update(replace(stage, status=StageStatus.SKIPPED, required=False,
                             finished_at=utc_now(), duration_seconds=0, error=reason))

    def _finish(self, stage_id: str, status: StageStatus, **values) -> None:
        stage = self.stage(stage_id)
        if stage.status != StageStatus.RUNNING:
            raise ValueError("Only a running stage can finish.")
        self._update(replace(stage, status=status, finished_at=utc_now(),
                             duration_seconds=round(monotonic() - self._timers[stage_id], 6), **values))

    def artifacts(self, paths: tuple[str, ...]) -> None:
        if self.run.status != RunStatus.RUNNING:
            raise ValueError("This run already has a final decision.")
        self._save(replace(self.run, artifacts=paths))

    def finish(self, *, gate_failed: bool) -> Run:
        if self.run.status != RunStatus.RUNNING:
            raise ValueError("This run already has a final decision.")
        incomplete = any(stage.required and stage.status != StageStatus.COMPLETED for stage in self.run.stages)
        self._save(replace(
            self.run, status=RunStatus.FAILED if incomplete else RunStatus.COMPLETED,
            finished_at=utc_now(),
            decision=GateDecision.INCOMPLETE if incomplete else (GateDecision.BLOCK if gate_failed else GateDecision.ALLOW),
            exit_code=2 if incomplete else int(gate_failed),
        ))
        return self.run

    def abort(self, error: BaseException, *, cancelled: bool = False) -> None:
        reason = execution_error(error)
        now = utc_now()
        stages = []
        for stage in self.run.stages:
            if stage.status in (StageStatus.PENDING, StageStatus.RUNNING):
                status = StageStatus.CANCELLED if cancelled else (
                    StageStatus.FAILED if stage.status == StageStatus.RUNNING else StageStatus.SKIPPED
                )
                elapsed = monotonic() - self._timers[stage.stage_id] if stage.started_at is not None else 0
                stage = replace(stage, status=status, finished_at=now,
                                duration_seconds=round(elapsed, 6), error=reason)
            stages.append(stage)
        self._save(replace(self.run, stages=tuple(stages), finished_at=now,
                           status=RunStatus.CANCELLED if cancelled else RunStatus.FAILED,
                           decision=GateDecision.INCOMPLETE, exit_code=2, error=reason))
