import multiprocessing
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from core.quarantine import QuarantineRecord
from narrowcti.adapters.persistence.local.artifact_index import ArtifactDeduplicationIndex
from narrowcti.adapters.persistence.local.job_repository import SQLiteJobRepository
from narrowcti.adapters.persistence.local.process_coordination import (
    SQLiteProcessCoordinationRepository,
)
from narrowcti.adapters.persistence.local.quarantine_repository import QuarantineRepository
from narrowcti.adapters.persistence.local.sqlite_runtime_store import SQLiteRuntimeStore
from narrowcti.adapters.persistence.local.worker_lease import SQLiteWorkerLeaseRepository
from narrowcti.application.review.export import QuarantineExporter
from narrowcti.application.runtime_roles import WORKER_LEASE_HELD_EXIT_CODE, RuntimeRole
from narrowcti.cli.worker import WorkerLeaseUnavailable, run_worker


def _submit_job(path, key, queue):
    repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
    queue.put(repository.submit("bounded", "test", {"key": key}, key))


def _claim_job(path, barrier, owner, queue):
    repository = SQLiteJobRepository(SQLiteRuntimeStore(path))
    barrier.wait()
    queue.put(repository.claim_next(owner, lease_seconds=30))


def _acquire_lease(path, owner, queue):
    repository = SQLiteWorkerLeaseRepository(SQLiteRuntimeStore(path))
    queue.put(repository.acquire("worker", owner, lease_seconds=30))


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

    def test_job_submission_is_idempotent_across_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "runtime.db")
            results = self._run_processes(_submit_job, [(path, "same-key"), (path, "same-key")])
            self.assertEqual(results[0]["job_id"], results[1]["job_id"])
            self.assertEqual("pending", results[0]["status"])

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


if __name__ == "__main__":
    unittest.main()
