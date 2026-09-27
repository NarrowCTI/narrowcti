"""Canonical Community Worker lifecycle."""

from __future__ import annotations

import sys
import time
from typing import Callable

from narrowcti.adapters.persistence.local.sqlite_runtime_store import SQLiteRuntimeStore
from narrowcti.adapters.persistence.local.job_repository import SQLiteJobRepository
from narrowcti.adapters.persistence.local.worker_lease import (
    WORKER_LEASE_HELD_EXIT_CODE,
    SQLiteWorkerLeaseRepository,
    new_owner_token,
    start_heartbeat,
)
from narrowcti.adapters.persistence.local.lease_heartbeat import LeaseHeartbeat
from narrowcti.adapters.persistence.local.process_coordination import SQLiteProcessCoordinationRepository
from narrowcti.infrastructure.config.settings import load_settings
from narrowcti.infrastructure.runtime.gateway_composition import default_source_registry
from narrowcti.ports.jobs import QUARANTINE_EXPORT_JOB

from .gateway import run_gateway_loop, run_gateway_once


EXPORT_QUARANTINE_JOB = QUARANTINE_EXPORT_JOB


class WorkerLeaseUnavailable(RuntimeError):
    exit_code = WORKER_LEASE_HELD_EXIT_CODE


def run_worker(
    settings,
    registry,
    logger: Callable[[str], None],
    *,
    run_once=run_gateway_once,
    run_loop=run_gateway_loop,
):
    """Run the historical gateway lifecycle under the Worker lease."""

    runtime_db = getattr(settings, "runtime_db_file", "")
    if not runtime_db:
        # Lightweight settings objects used by legacy callers/tests predate
        # the role contract and intentionally retain their old behavior.
        if getattr(settings, "run_once", False):
            return run_once(settings, registry, logger)
        return run_loop(settings, registry, logger)

    owner = new_owner_token()
    lease_seconds = max(int(getattr(settings, "worker_lease_seconds", 120)), 3)
    leases = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(runtime_db))
    if not leases.acquire("worker", owner, lease_seconds=lease_seconds):
        logger("worker lease already held")
        raise WorkerLeaseUnavailable("worker lease already held")
    try:
        heartbeat = start_heartbeat(leases, "worker", owner, lease_seconds)
        if getattr(settings, "run_once", False):
            result = run_once(settings, registry, logger)
        elif run_loop is run_worker_loop or getattr(run_loop, "__module__", "").startswith("gateway"):
            result = run_worker_loop(
                settings,
                registry,
                logger,
                owner_token=owner,
                lease_repository=leases,
                lease_seconds=lease_seconds,
                heartbeat=heartbeat,
            )
        else:
            result = run_loop(settings, registry, logger)
        if heartbeat.lost:
            raise WorkerLeaseUnavailable("worker lease heartbeat was lost")
        return result
    finally:
        heartbeat.stop()
        leases.release("worker", owner)


def _execute_export_job(job, settings, logger):
    from narrowcti.adapters.opencti.exporter import send_bundle
    from narrowcti.adapters.persistence.local.artifact_index import ArtifactDeduplicationIndex
    from narrowcti.adapters.opencti.deduplication import CompositeArtifactDeduplication, OpenCTIArtifactLookup
    from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository
    from narrowcti.application.review.service import AnalystReviewService
    from narrowcti.api.review.app import default_opencti_client_factory
    from narrowcti.domain.review.quarantine import released_indicators

    payload = dict(job.get("payload") or {})
    coordination = SQLiteProcessCoordinationRepository(SQLiteRuntimeStore(settings.runtime_db_file))
    repository = QuarantineRepository(
        settings.quarantine_repository_file,
        settings.release_audit_file,
        coordination=coordination,
        runtime_db_file=getattr(settings, "runtime_db_file", ""),
    )
    api_client = default_opencti_client_factory()
    local_index = ArtifactDeduplicationIndex(settings.dedup_state_file) if settings.dedup_state_file else None
    recovery = int(job.get("attempt") or 1) > 1
    if recovery:
        if local_index is None:
            raise RuntimeError("OpenCTI recovery requires a local artifact index")
        # Recovery already checked the released set strictly. A second
        # best-effort remote lookup could turn an outage into a blind export.
        remote_lookup = None
    else:
        remote_lookup = OpenCTIArtifactLookup(api_client) if settings.opencti_dedup_lookup else None

    def export_under_current_coordination(*, coordinated):
        dedup = CompositeArtifactDeduplication(local_index=local_index, opencti_lookup=remote_lookup)
        service = AnalystReviewService(
            repository,
            coordination=None if coordinated else coordination,
        )
        results = service.export_released(
            payload.get("quarantine_id", ""),
            api_client=api_client,
            artifact_dedup=dedup,
            identity_name=payload.get("identity_name", "NarrowCTI Gateway"),
            logger=logger,
            dry_run=False,
            exported_by=payload.get("exported_by", "review-api"),
            exporter=send_bundle,
            strict_artifact_mark=recovery,
        )
        items = [item.to_dict() for item in results]
        if any(item.get("action") == "error" for item in items):
            raise RuntimeError("quarantine export failed")
        return {"items": items}

    if not recovery:
        return export_under_current_coordination(coordinated=False)

    scope = f"artifact-export:{repository.repository_file}"
    with coordination.exclusive(scope):
        record = repository.get(payload.get("quarantine_id", ""))
        lookup = OpenCTIArtifactLookup(api_client)
        known = [
            indicator
            for indicator in released_indicators(record)
            if lookup.has_indicator_for_recovery(indicator)
        ]
        if known:
            local_index.mark_indicators(
                known,
                source_key=record.get("source_key", ""),
                external_id=record.get("external_id", ""),
                title=record.get("title", ""),
            )
        return export_under_current_coordination(coordinated=True)


def process_pending_jobs(settings, owner_token, logger, *, lease_seconds=None):
    runtime_db = getattr(settings, "runtime_db_file", "")
    if not runtime_db:
        return 0
    jobs = SQLiteJobRepository(SQLiteRuntimeStore(runtime_db))
    processed = 0
    while True:
        job_lease_seconds = max(int(lease_seconds or getattr(settings, "worker_lease_seconds", 120)), 3)
        job = jobs.claim_next(owner_token, lease_seconds=job_lease_seconds)
        if not job:
            return processed
        processed += 1
        heartbeat = LeaseHeartbeat(
            lambda job_id=job["job_id"], attempt=job["attempt"], lease=job_lease_seconds:
            jobs.renew(job_id, owner_token, attempt, lease),
            job_lease_seconds,
        ).start()
        try:
            if job["job_type"] != EXPORT_QUARANTINE_JOB:
                raise ValueError(f"unsupported job type: {job['job_type']}")
            result = _execute_export_job(job, settings, logger)
            jobs.complete(job["job_id"], owner_token, job["attempt"], result)
        except Exception as exc:
            logger(f"runtime job failed: type={job['job_type']} error={exc}")
            try:
                jobs.fail(job["job_id"], owner_token, job["attempt"], str(exc))
            except PermissionError:
                logger(f"runtime job claim lost: id={job['job_id']}")
        finally:
            heartbeat.stop()


def run_worker_loop(
    settings,
    registry,
    logger,
    sleeper=time.sleep,
    owner_token=None,
    lease_repository=None,
    lease_seconds=300,
    heartbeat=None,
    clock=time.monotonic,
):
    """Canonical continuous Worker loop with bounded job polling."""

    owner_token = owner_token or new_owner_token()
    next_source_deadline = clock()
    next_job_deadline = clock()
    while True:
        if heartbeat and heartbeat.lost:
            raise WorkerLeaseUnavailable("worker lease heartbeat was lost")
        now = clock()
        if now >= next_job_deadline:
            process_pending_jobs(settings, owner_token, logger, lease_seconds=lease_seconds)
            next_job_deadline = clock() + max(float(getattr(settings, "job_poll_seconds", 2.0)), 0.05)
        if clock() >= next_source_deadline:
            run_gateway_once(settings, registry, logger)
            next_source_deadline = clock() + max(int(getattr(settings, "source_interval_seconds", 60)), 1)
            process_pending_jobs(settings, owner_token, logger, lease_seconds=lease_seconds)
        wait_seconds = max(
            min(next_source_deadline, next_job_deadline) - clock(),
            0.0,
        )
        if wait_seconds:
            logger(f"Gateway sleeping {wait_seconds:.3f}s until next runtime deadline")
            sleeper(wait_seconds)


def main():
    settings = load_settings()
    registry = default_source_registry(print, settings)
    try:
        run_worker(settings, registry, lambda message: print(f"[INFO] {message}", flush=True), run_loop=run_worker_loop)
    except WorkerLeaseUnavailable as exc:
        print(str(exc), file=sys.stderr, flush=True)
        return WORKER_LEASE_HELD_EXIT_CODE
    return 0


__all__ = [
    "EXPORT_QUARANTINE_JOB",
    "WORKER_LEASE_HELD_EXIT_CODE",
    "WorkerLeaseUnavailable",
    "main",
    "process_pending_jobs",
    "run_worker",
    "run_worker_loop",
]


if __name__ == "__main__":
    raise SystemExit(main())
