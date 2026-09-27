import multiprocessing
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.quarantine import QuarantineRecord
from narrowcti.adapters.persistence.local.artifact_index import (
    ArtifactDeduplicationIndex,
    indicator_fingerprint,
)
from narrowcti.adapters.stix.patterns import indicator_pattern
from narrowcti.adapters.persistence.local.job_repository import SQLiteJobRepository
from narrowcti.adapters.persistence.local.process_coordination import (
    SQLiteProcessCoordinationRepository,
)
from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository
from narrowcti.adapters.persistence.local.sqlite_runtime_store import SQLiteRuntimeStore
from narrowcti.adapters.persistence.local.worker_lease import SQLiteWorkerLeaseRepository
from narrowcti.adapters.persistence.local.lease_heartbeat import LeaseHeartbeat
from narrowcti.application.review.export import QuarantineExporter
from narrowcti.application.runtime_roles import WORKER_LEASE_HELD_EXIT_CODE, RuntimeRole
from narrowcti.cli.quarantine import command_export_released
from narrowcti.cli.worker import (
    WorkerLeaseUnavailable,
    process_pending_jobs,
    run_worker,
    run_worker_loop,
)
from narrowcti.domain.review.quarantine import released_indicators
from narrowcti.ports.jobs import QUARANTINE_EXPORT_JOB, quarantine_export_idempotency_key


def _submit_job(path, key, queue):
    repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
    queue.put(repository.submit("bounded", "test", {"key": key}, key))


def _claim_job(path, barrier, owner, queue):
    repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
    barrier.wait()
    queue.put(repository.claim_next(owner, lease_seconds=30))


def _retry_failed_job(path, job_id, barrier, queue):
    repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
    barrier.wait()
    queue.put(repository.retry_failed(job_id))


class FakeRecoveryOpenCTI:
    def __init__(self, known_patterns=(), fail=False):
        self.known_patterns = set(known_patterns)
        self.fail = fail
        self.patterns_queried = []

    def query(self, _query, variables):
        if self.fail:
            raise RuntimeError("synthetic OpenCTI outage")
        pattern = variables["filters"]["filters"][0]["values"][0]
        self.patterns_queried.append(pattern)
        edges = [{"node": {"id": "indicator--remote"}}] if pattern in self.known_patterns else []
        return {"data": {"indicators": {"edges": edges}}}


def _acquire_lease(path, owner, queue):
    repository = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(path))
    queue.put(repository.acquire("worker", owner, lease_seconds=30))


def _hold_worker_lease(path, ready, stop):
    repository = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(path))
    owner = "healthy-owner"
    repository.acquire("worker", owner, lease_seconds=1)
    heartbeat = LeaseHeartbeat(
        lambda: repository.renew("worker", owner, lease_seconds=1), 1
    ).start()
    ready.set()
    stop.wait(10)
    heartbeat.stop()


def _hold_job_lease(path, ready, stop):
    repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
    job = repository.claim_next("job-owner", lease_seconds=1)
    heartbeat = LeaseHeartbeat(
        lambda: repository.renew(job["job_id"], "job-owner", job["attempt"], 1), 1
    ).start()
    ready.set()
    stop.wait(10)
    heartbeat.stop()


def _hold_coordination(path, ready, stop):
    repository = SQLiteProcessCoordinationRepository(SQLiteRuntimeStore(path))
    with repository.exclusive("scope", owner_token="healthy-owner", lease_seconds=1):
        ready.set()
        stop.wait(10)


def _quarantine_add(path, runtime_db, external_id, queue):
    repository = QuarantineRepository(path, runtime_db_file=runtime_db)
    record = QuarantineRecord(
        source_key="process-test",
        external_id=external_id,
        title=external_id,
        reason="test",
        indicators=[{"type": "domain", "indicator": f"{external_id}.example"}],
    )
    repository.add(record)
    queue.put(True)


def _export_record(repository_path, audit_path, artifact_path, runtime_db, counter, queue):
    repository = QuarantineRepository(repository_path, audit_path, runtime_db_file=runtime_db)
    record = repository.records()[0]
    dedup = ArtifactDeduplicationIndex(artifact_path)

    def export_operation(*_args, **_kwargs):
        with counter.get_lock():
            counter.value += 1
        return 1

    result = QuarantineExporter(
        repository,
        artifact_dedup=dedup,
        exporter=export_operation,
        dry_run=False,
        coordination=SQLiteProcessCoordinationRepository(SQLiteRuntimeStore(runtime_db)),
    ).export_record(record)
    queue.put(result.to_dict())


class PR23RuntimeFoundationTests(unittest.TestCase):
    def setUp(self):
        self.context = multiprocessing.get_context("spawn")

    def _run_processes(self, target, args_list):
        queue = self.context.SimpleQueue()
        processes = [self.context.Process(target=target, args=(*args, queue)) for args in args_list]
        for process in processes:
            process.start()
        for process in processes:
            process.join(30)
            self.assertEqual(0, process.exitcode)
            process.close()
        return [queue.get() for _ in processes]

    def _seed_export_job(self, directory, indicators):
        quarantine_path = str(Path(directory) / "quarantine.jsonl")
        audit_path = str(Path(directory) / "audit.jsonl")
        runtime_db = str(Path(directory) / "runtime.db")
        artifact_path = str(Path(directory) / "artifacts.json")
        repository = QuarantineRepository(quarantine_path, audit_path, runtime_db_file=runtime_db)
        record = repository.add(
            QuarantineRecord(
                source_key="misp:misp",
                external_id="event-recovery",
                title="Recovery test",
                reason="review",
                indicators=indicators,
            )
        )
        repository.release(record["quarantine_id"], "approved")
        store = SQLiteRuntimeStore(runtime_db)
        jobs = SQLiteJobRepository(store)
        job = jobs.submit(
            QUARANTINE_EXPORT_JOB,
            "review-api",
            {"quarantine_id": record["quarantine_id"], "identity_name": "NarrowCTI", "exported_by": "review-api:test"},
            "recovery-key",
        )
        settings = SimpleNamespace(
            quarantine_repository_file=quarantine_path,
            release_audit_file=audit_path,
            runtime_db_file=runtime_db,
            dedup_state_file=artifact_path,
            opencti_dedup_lookup=False,
        )
        return repository, jobs, store, settings, job, artifact_path

    @staticmethod
    def _expire_claim(store, job_id):
        connection = store.connect()
        try:
            connection.execute("UPDATE jobs SET lease_until=0 WHERE job_id=?", (job_id,))
            connection.commit()
        finally:
            connection.close()

    def test_job_submission_is_idempotent_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            results = self._run_processes(_submit_job, [(path, "same-key"), (path, "same-key")])
            self.assertEqual(results[0]["job_id"], results[1]["job_id"])
            self.assertEqual("pending", results[0]["status"])

    def test_submit_reuses_pending_running_and_succeeded_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = SQLiteJobRepository(SQLiteRuntimeStore(str(Path(directory) / "runtime.db")))
            pending = repository.submit("bounded", "test", {"v": 1}, "same")
            self.assertEqual(pending["job_id"], repository.submit("bounded", "other", {"v": 2}, "same")["job_id"])
            running = repository.claim_next("worker")
            self.assertEqual("running", running["status"])
            self.assertEqual(running["job_id"], repository.submit("bounded", "test", {}, "same")["job_id"])
            succeeded = repository.complete(running["job_id"], "worker", running["attempt"], {"ok": True})
            reused = repository.submit("bounded", "test", {}, "same")
            self.assertEqual("succeeded", reused["status"])
            self.assertEqual(succeeded["job_id"], reused["job_id"])

    def test_failed_job_retry_preserves_identity_clears_execution_and_increments_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRuntimeStore(str(Path(directory) / "runtime.db"))
            repository = SQLiteJobRepository(store)
            original = repository.submit("bounded", "test", {"payload": "same"}, "retry-key")
            first_claim = repository.claim_next("old-owner")
            failed = repository.fail(first_claim["job_id"], "old-owner", first_claim["attempt"], "temporary")
            connection = store.connect()
            try:
                connection.execute(
                    "UPDATE jobs SET result_json=? WHERE job_id=?",
                    ('{"stale":true}', original["job_id"]),
                )
                connection.commit()
            finally:
                connection.close()

            pending = repository.retry_failed(original["job_id"])
            self.assertEqual("pending", pending["status"])
            self.assertEqual(original["job_id"], pending["job_id"])
            self.assertEqual(original["job_type"], pending["job_type"])
            self.assertEqual(original["payload"], pending["payload"])
            self.assertEqual(original["idempotency_key"], pending["idempotency_key"])
            self.assertEqual(original["created_at"], pending["created_at"])
            self.assertEqual(failed["attempt"], pending["attempt"])
            for field in ("claim_owner", "claimed_at", "lease_until", "started_at", "finished_at", "result", "error"):
                self.assertIsNone(pending[field], field)

            self.assertEqual(pending["job_id"], repository.submit("bounded", "test", {}, "retry-key")["job_id"])
            second_claim = repository.claim_next("new-owner")
            self.assertEqual(first_claim["attempt"] + 1, second_claim["attempt"])
            with self.assertRaises(PermissionError):
                repository.complete(second_claim["job_id"], "old-owner", first_claim["attempt"], {})
            self.assertEqual("succeeded", repository.complete(second_claim["job_id"], "new-owner", second_claim["attempt"], {})["status"])
            self.assertEqual("succeeded", repository.retry_failed(second_claim["job_id"])["status"])

    def test_only_one_concurrent_retry_requeues_a_failed_job(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
            job = repository.submit("bounded", "test", {}, "retry-race")
            claim = repository.claim_next("first-owner")
            repository.fail(claim["job_id"], "first-owner", claim["attempt"], "temporary")
            barrier = self.context.Barrier(2)
            results = self._run_processes(
                _retry_failed_job,
                [(path, job["job_id"], barrier), (path, job["job_id"], barrier)],
            )
            self.assertEqual({"pending"}, {result["status"] for result in results})
            self.assertEqual(1, len({result["job_id"] for result in results}))
            claimed = repository.claim_next("retry-owner")
            self.assertEqual(2, claimed["attempt"])

    def test_atomic_claim_has_one_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
            repository.submit("bounded", "test", {}, "claim-once")
            barrier = self.context.Barrier(2)
            results = self._run_processes(
                _claim_job,
                [(path, barrier, "owner-a"), (path, barrier, "owner-b")],
            )
            self.assertEqual(1, sum(result is not None for result in results))

    def test_job_attempt_and_owner_fencing_reject_stale_transitions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
            submitted = repository.submit("bounded", "test", {}, "fenced")
            first = repository.claim_next("owner-a", lease_seconds=1)
            self.assertEqual(submitted["job_id"], first["job_id"])
            with self.assertRaises(PermissionError):
                repository.complete(first["job_id"], "owner-b", first["attempt"], {})
            import time

            time.sleep(1.1)
            second = repository.claim_next("owner-b", lease_seconds=30)
            self.assertEqual(2, second["attempt"])
            with self.assertRaises(PermissionError):
                repository.complete(first["job_id"], "owner-a", first["attempt"], {})
            completed = repository.complete(second["job_id"], "owner-b", second["attempt"], {"ok": True})
            self.assertEqual("succeeded", completed["status"])
            with self.assertRaises(RuntimeError):
                repository.fail(second["job_id"], "owner-b", second["attempt"], "conflict")

    def test_job_heartbeat_keeps_long_running_claim_and_crash_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
            submitted = repository.submit("bounded", "test", {}, "heartbeat")
            ready = self.context.Event()
            stop = self.context.Event()
            holder = self.context.Process(target=_hold_job_lease, args=(path, ready, stop))
            holder.start()
            self.assertTrue(ready.wait(10))
            time.sleep(1.4)
            self.assertIsNone(repository.claim_next("other-owner", lease_seconds=1))
            holder.terminate()
            holder.join(10)
            time.sleep(1.2)
            reclaimed = repository.claim_next("other-owner", lease_seconds=10)
            self.assertEqual(submitted["job_id"], reclaimed["job_id"])

    def test_reclaimed_export_reconciles_remote_crash_and_repairs_local_state(self):
        with tempfile.TemporaryDirectory() as directory:
            indicator = {"type": "domain", "indicator": "already-exported.example"}
            repository, jobs, store, settings, submitted, artifact_path = self._seed_export_job(directory, [indicator])
            remote = FakeRecoveryOpenCTI()
            logs = []

            def export_then_crash(_api, _title, _description, _score, indicators, **_kwargs):
                remote.known_patterns.update(indicator_pattern(item) for item in indicators)
                raise SystemExit("simulated process death after remote success")

            with patch("narrowcti.api.review.app.default_opencti_client_factory", return_value=remote), patch(
                "narrowcti.adapters.opencti.exporter.send_bundle", side_effect=export_then_crash
            ):
                with self.assertRaises(SystemExit):
                    process_pending_jobs(settings, "worker-first", logs.append, lease_seconds=3)

            first = jobs.get(submitted["job_id"])
            self.assertEqual("running", first["status"])
            self.assertEqual(1, first["attempt"])
            local = ArtifactDeduplicationIndex(artifact_path)
            fingerprint = indicator_fingerprint(indicator)
            self.assertFalse(local.has_fingerprint(fingerprint))
            self.assertFalse(repository.get(first["payload"]["quarantine_id"])["review"].get("exported", False))

            self._expire_claim(store, submitted["job_id"])
            with patch("narrowcti.api.review.app.default_opencti_client_factory", return_value=remote), patch(
                "narrowcti.adapters.opencti.exporter.send_bundle", side_effect=AssertionError("blind duplicate export")
            ) as exporter:
                process_pending_jobs(settings, "worker-recovery", logs.append, lease_seconds=3)

            recovered = jobs.get(submitted["job_id"])
            self.assertEqual("succeeded", recovered["status"])
            self.assertEqual(2, recovered["attempt"])
            self.assertEqual("dedup-skip", recovered["result"]["items"][0]["action"])
            exporter.assert_not_called()
            self.assertEqual([indicator_pattern(indicator)], remote.patterns_queried)
            self.assertTrue(local.has_fingerprint(fingerprint))
            artifact = local.artifact_record(fingerprint)
            self.assertEqual(["misp:misp"], artifact["sources"])
            self.assertEqual("event-recovery", artifact["sightings"][0]["external_id"])
            final_record = repository.get(first["payload"]["quarantine_id"])
            self.assertTrue(final_record["review"]["exported"])

    def test_reclaimed_export_lookup_error_fails_without_blind_export(self):
        with tempfile.TemporaryDirectory() as directory:
            indicator = {"type": "domain", "indicator": "lookup-error.example"}
            repository, jobs, store, settings, submitted, artifact_path = self._seed_export_job(directory, [indicator])
            initial = jobs.claim_next("crashed-worker", lease_seconds=1)
            self._expire_claim(store, submitted["job_id"])
            remote = FakeRecoveryOpenCTI(fail=True)
            logs = []
            with patch("narrowcti.api.review.app.default_opencti_client_factory", return_value=remote), patch(
                "narrowcti.adapters.opencti.exporter.send_bundle", side_effect=AssertionError("must not export")
            ) as exporter:
                process_pending_jobs(settings, "recovery-worker", logs.append, lease_seconds=3)
            failed = jobs.get(submitted["job_id"])
            self.assertEqual(2, failed["attempt"])
            self.assertEqual("failed", failed["status"])
            exporter.assert_not_called()
            self.assertIn("runtime job failed", logs[0])
            current = repository.get(initial["payload"]["quarantine_id"])
            self.assertFalse(current["review"].get("exported", False))
            local = ArtifactDeduplicationIndex(artifact_path)
            self.assertFalse(local.has_fingerprint(indicator_fingerprint(indicator)))

    def test_reclaimed_export_reconciles_known_and_exports_only_missing_indicators(self):
        with tempfile.TemporaryDirectory() as directory:
            known = {"type": "domain", "indicator": "known.example"}
            missing = {"type": "domain", "indicator": "missing.example"}
            repository, jobs, store, settings, submitted, artifact_path = self._seed_export_job(directory, [known, missing])
            jobs.claim_next("crashed-worker", lease_seconds=1)
            self._expire_claim(store, submitted["job_id"])
            remote = FakeRecoveryOpenCTI({indicator_pattern(known)})
            exported = []

            def export_missing(_api, _title, _description, _score, indicators, **_kwargs):
                exported.extend(indicators)
                return len(indicators)

            with patch("narrowcti.api.review.app.default_opencti_client_factory", return_value=remote), patch(
                "narrowcti.adapters.opencti.exporter.send_bundle", side_effect=export_missing
            ):
                process_pending_jobs(settings, "recovery-worker", lambda _message: None, lease_seconds=3)

            self.assertEqual([missing], exported)
            final_record = repository.get(submitted["payload"]["quarantine_id"])
            self.assertTrue(final_record["review"]["exported"])
            self.assertEqual(1, final_record["review"]["exported_indicator_count"])
            self.assertEqual(1, final_record["review"]["dedup_duplicate_count"])
            local = ArtifactDeduplicationIndex(artifact_path)
            for indicator in (known, missing):
                self.assertTrue(local.has_fingerprint(indicator_fingerprint(indicator)))
                self.assertEqual("event-recovery", local.artifact_record(indicator_fingerprint(indicator))["sightings"][0]["external_id"])

    def test_worker_heartbeat_prevents_second_owner_until_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            ready = self.context.Event()
            stop = self.context.Event()
            holder = self.context.Process(target=_hold_worker_lease, args=(path, ready, stop))
            holder.start()
            self.assertTrue(ready.wait(10))
            time.sleep(1.4)
            repository = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(path))
            self.assertFalse(repository.acquire("worker", "other-owner", lease_seconds=1))
            stop.set()
            holder.join(10)
            self.assertEqual(0, holder.exitcode)
            crashed_ready = self.context.Event()
            crashed_stop = self.context.Event()
            crashed = self.context.Process(target=_hold_worker_lease, args=(path, crashed_ready, crashed_stop))
            crashed.start()
            self.assertTrue(crashed_ready.wait(10))
            crashed.terminate()
            crashed.join(10)
            time.sleep(1.2)
            self.assertTrue(repository.acquire("worker", "recovery-owner", lease_seconds=1))
            repository.release("worker", "recovery-owner")

    def test_process_coordination_heartbeat_prevents_overlap_until_release_or_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            ready = self.context.Event()
            stop = self.context.Event()
            holder = self.context.Process(target=_hold_coordination, args=(path, ready, stop))
            holder.start()
            self.assertTrue(ready.wait(10))
            time.sleep(1.4)
            repository = SQLiteProcessCoordinationRepository(SQLiteRuntimeStore(path))
            self.assertFalse(repository.acquire("scope", "other-owner", timeout_seconds=0, lease_seconds=1))
            stop.set()
            holder.join(10)
            crashed_ready = self.context.Event()
            crashed_stop = self.context.Event()
            crashed = self.context.Process(target=_hold_coordination, args=(path, crashed_ready, crashed_stop))
            crashed.start()
            self.assertTrue(crashed_ready.wait(10))
            crashed.terminate()
            crashed.join(10)
            time.sleep(1.2)
            self.assertTrue(repository.acquire("scope", "recovery-owner", timeout_seconds=0, lease_seconds=1))
            repository.release("scope", "recovery-owner")

    def test_worker_lease_has_one_owner_and_supports_release(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = str(Path(directory) / "runtime.db")
            results = self._run_processes(
                _acquire_lease,
                [(path, "owner-a"), (path, "owner-b")],
            )
            self.assertEqual(1, sum(results))
            repository = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(path))
            current = repository.inspect("worker")
            self.assertIsNotNone(current)
            self.assertTrue(repository.release("worker", current["owner_token"]))
            self.assertTrue(repository.acquire("worker", "owner-c", lease_seconds=30))
            self.assertTrue(repository.release("worker", "owner-c"))
            del repository

    def test_worker_run_once_cannot_bypass_an_existing_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            store = SQLiteRuntimeStore(path)
            leases = SQLiteWorkerLeaseRepository(store)
            self.assertTrue(leases.acquire("worker", "continuous", lease_seconds=30))
            settings = SimpleNamespace(runtime_db_file=path, source_interval_seconds=1, run_once=True)
            with self.assertRaises(WorkerLeaseUnavailable) as raised:
                run_worker(settings, None, lambda _message: None, run_once=lambda *_args: None)
            self.assertEqual(WORKER_LEASE_HELD_EXIT_CODE, raised.exception.exit_code)
            self.assertTrue(leases.release("worker", "continuous"))

    def test_worker_run_once_releases_lease_on_graceful_exit(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path = str(Path(directory) / "runtime.db")
            settings = SimpleNamespace(runtime_db_file=path, source_interval_seconds=1, run_once=True)
            run_worker(settings, None, lambda _message: None, run_once=lambda *_args: "done")
            repository = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(path))
            self.assertIsNone(repository.inspect("worker"))
            del repository

    def test_worker_polls_jobs_between_slow_source_cycles(self):
        clock_value = [0.0]
        pending_calls = []
        source_calls = []

        def clock():
            return clock_value[0]

        def sleeper(seconds):
            self.assertLessEqual(seconds, 2.0)
            clock_value[0] += seconds

        def pending(*_args, **_kwargs):
            pending_calls.append(clock_value[0])
            if len(pending_calls) >= 3:
                raise StopIteration

        settings = SimpleNamespace(source_interval_seconds=300, job_poll_seconds=2)
        from unittest.mock import patch

        with patch("narrowcti.cli.worker.process_pending_jobs", side_effect=pending), patch(
            "narrowcti.cli.worker.run_gateway_once", side_effect=lambda *_args: source_calls.append(True)
        ):
            with self.assertRaises(StopIteration):
                run_worker_loop(settings, None, lambda _message: None, sleeper=sleeper, clock=clock)

        self.assertGreaterEqual(len(pending_calls), 3)
        self.assertEqual([True], source_calls)

    def test_quarantine_writers_are_serialized_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            repository_path = str(Path(directory) / "quarantine.jsonl")
            runtime_db = str(Path(directory) / "runtime.db")
            results = self._run_processes(
                _quarantine_add,
                [(repository_path, runtime_db, "event-a"), (repository_path, runtime_db, "event-b")],
            )
            self.assertEqual([True, True], results)
            records = QuarantineRepository(repository_path, runtime_db_file=runtime_db).records()
            self.assertEqual({"event-a", "event-b"}, {record["external_id"] for record in records})
            self.assertTrue(all(record["status"] == "pending" for record in records))

    def test_export_check_external_mark_is_serialized(self):
        with tempfile.TemporaryDirectory() as directory:
            repository_path = str(Path(directory) / "quarantine.jsonl")
            audit_path = str(Path(directory) / "release.jsonl")
            artifact_path = str(Path(directory) / "artifacts.json")
            runtime_db = str(Path(directory) / "runtime.db")
            repository = QuarantineRepository(repository_path, audit_path, runtime_db_file=runtime_db)
            record = repository.add(
                QuarantineRecord(
                    source_key="process-test",
                    external_id="event-export",
                    title="Export",
                    reason="test",
                    indicators=[{"type": "domain", "indicator": "shared.example"}],
                )
            )
            repository.release(record["quarantine_id"], "approved")
            counter = self.context.Value("i", 0)
            results = self._run_processes(
                _export_record,
                [(repository_path, audit_path, artifact_path, runtime_db, counter),
                 (repository_path, audit_path, artifact_path, runtime_db, counter)],
            )
            self.assertEqual(1, counter.value)
            self.assertEqual({"export", "skip"}, {result["action"] for result in results})
            current = QuarantineRepository(repository_path, audit_path, runtime_db_file=runtime_db).get(record["quarantine_id"])
            self.assertTrue(current["review"]["exported"])

    def test_role_contract_and_exit_code_are_stable(self):
        self.assertTrue(RuntimeRole("web").is_web)
        self.assertTrue(RuntimeRole("worker").is_worker)
        self.assertTrue(RuntimeRole("ops").is_ops)
        self.assertEqual(75, WORKER_LEASE_HELD_EXIT_CODE)

    def test_runtime_schema_rejects_unsupported_newer_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            SQLiteRuntimeStore(path)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE schema_metadata SET value='99' WHERE key='schema_version'"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(RuntimeError, "unsupported runtime database schema version"):
                SQLiteRuntimeStore(path)

    def test_export_job_key_is_stable_and_changes_with_released_set(self):
        first = [{"type": "domain", "indicator": "a.example"}]
        reordered = [{"indicator": "a.example", "type": "domain"}]
        changed = [{"type": "domain", "indicator": "b.example"}]
        self.assertEqual(
            quarantine_export_idempotency_key("q-1", first),
            quarantine_export_idempotency_key("q-1", reordered),
        )
        self.assertNotEqual(
            quarantine_export_idempotency_key("q-1", first),
            quarantine_export_idempotency_key("q-1", changed),
        )
        self.assertNotIn("a.example", quarantine_export_idempotency_key("q-1", first))

    def test_ops_execute_submits_job_and_never_exports_locally(self):
        with tempfile.TemporaryDirectory() as directory:
            repository_path = str(Path(directory) / "quarantine.jsonl")
            audit_path = str(Path(directory) / "audit.jsonl")
            runtime_db = str(Path(directory) / "runtime.db")
            repository = QuarantineRepository(repository_path, audit_path)
            record = repository.add(
                QuarantineRecord(
                    source_key="ops-test",
                    external_id="ops-event",
                    title="Ops",
                    reason="review",
                    indicators=[{"type": "domain", "indicator": "ops.example"}],
                )
            )
            repository.release(record["quarantine_id"], "approved")
            args = SimpleNamespace(
                execute=True,
                repository=repository_path,
                release_audit_file=audit_path,
                id=record["quarantine_id"],
                limit=0,
                identity_name="NarrowCTI Gateway",
                json=True,
                reviewer="operator",
            )
            with patch.dict(
                "os.environ",
                {
                    "NARROWCTI_RUNTIME_DB": runtime_db,
                    "NARROWCTI_QUARANTINE_REPOSITORY": repository_path,
                    "NARROWCTI_RELEASE_AUDIT_FILE": audit_path,
                    "NARROWCTI_REVIEW_EXPORT_TIMEOUT_SECONDS": "0.01",
                },
                clear=False,
            ), patch("narrowcti.cli.quarantine.send_bundle", side_effect=AssertionError("local export")):
                self.assertEqual(75, command_export_released(args))
            connection = SQLiteRuntimeStore(runtime_db).connect()
            try:
                row = connection.execute(
                    "SELECT status FROM jobs WHERE job_type=?", (QUARANTINE_EXPORT_JOB,)
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual("pending", row["status"])

    def test_ops_new_export_request_requeues_same_failed_job(self):
        with tempfile.TemporaryDirectory() as directory:
            repository_path = str(Path(directory) / "quarantine.jsonl")
            audit_path = str(Path(directory) / "audit.jsonl")
            runtime_db = str(Path(directory) / "runtime.db")
            repository = QuarantineRepository(repository_path, audit_path)
            record = repository.add(
                QuarantineRecord(
                    source_key="ops-test",
                    external_id="ops-event-retry",
                    title="Ops retry",
                    reason="review",
                    indicators=[{"type": "domain", "indicator": "ops-retry.example"}],
                )
            )
            repository.release(record["quarantine_id"], "approved")
            jobs = SQLiteJobRepository(SQLiteRuntimeStore(runtime_db))
            identity = quarantine_export_idempotency_key(
                record["quarantine_id"], released_indicators(repository.get(record["quarantine_id"]))
            )
            submitted = jobs.submit(
                QUARANTINE_EXPORT_JOB,
                "ops",
                {"quarantine_id": record["quarantine_id"]},
                identity,
            )
            claim = jobs.claim_next("previous-worker")
            jobs.fail(claim["job_id"], "previous-worker", claim["attempt"], "transient provider error")
            args = SimpleNamespace(
                execute=True,
                repository=repository_path,
                release_audit_file=audit_path,
                id=record["quarantine_id"],
                limit=0,
                identity_name="NarrowCTI Gateway",
                json=True,
                reviewer="operator",
            )
            with patch.dict(
                "os.environ",
                {
                    "NARROWCTI_RUNTIME_DB": runtime_db,
                    "NARROWCTI_QUARANTINE_REPOSITORY": repository_path,
                    "NARROWCTI_RELEASE_AUDIT_FILE": audit_path,
                    "NARROWCTI_REVIEW_EXPORT_TIMEOUT_SECONDS": "0.01",
                },
                clear=False,
            ), patch("narrowcti.cli.quarantine.send_bundle", side_effect=AssertionError("local export")):
                self.assertEqual(75, command_export_released(args))
            current = jobs.get(submitted["job_id"])
            self.assertEqual(submitted["job_id"], current["job_id"])
            self.assertEqual(identity, current["idempotency_key"])
            self.assertEqual("pending", current["status"])
            self.assertEqual(1, current["attempt"])


if __name__ == "__main__":
    unittest.main()
