from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from narrowcti.application.runtime import GatewayRunSummary, SourceRunResult
from narrowcti.cli.exit_codes import RUN_ONCE_SOURCE_FAILURE_EXIT_CODE
from narrowcti.cli.worker import WORKER_LEASE_HELD_EXIT_CODE, main as worker_main, run_worker_loop


def _summary(*successes):
    return GatewayRunSummary(
        tuple(SourceRunResult(str(index), str(index), success) for index, success in enumerate(successes))
    )


class RunOnceExitContractTests(unittest.TestCase):
    def _worker_main(self, summary, *, run_once=True):
        settings = SimpleNamespace(run_once=run_once, runtime_db_file="")
        with patch("narrowcti.cli.worker.load_settings", return_value=settings), patch(
            "narrowcti.cli.worker.default_source_registry", return_value=object()
        ), patch("narrowcti.cli.worker.run_worker", return_value=summary):
            return worker_main()

    def test_all_enabled_sources_succeed_exits_zero(self):
        self.assertEqual(0, self._worker_main(_summary(True, True)))

    def test_one_source_failure_exits_two(self):
        self.assertEqual(RUN_ONCE_SOURCE_FAILURE_EXIT_CODE, self._worker_main(_summary(False)))

    def test_mixed_sources_exit_two_and_successful_run_once_remains_zero(self):
        self.assertEqual(RUN_ONCE_SOURCE_FAILURE_EXIT_CODE, self._worker_main(_summary(True, False, True)))
        self.assertEqual(0, self._worker_main(_summary(True, True)))

    def test_lease_conflict_remains_exit_75(self):
        settings = SimpleNamespace(run_once=True)
        with patch("narrowcti.cli.worker.load_settings", return_value=settings), patch(
            "narrowcti.cli.worker.default_source_registry", return_value=object()
        ), patch("narrowcti.cli.worker.run_worker", side_effect=RuntimeError("not used")) as run_worker:
            from narrowcti.cli.worker import WorkerLeaseUnavailable

            run_worker.side_effect = WorkerLeaseUnavailable("lease busy")
            self.assertEqual(WORKER_LEASE_HELD_EXIT_CODE, worker_main())

    def test_continuous_worker_survives_a_transient_failed_cycle(self):
        settings = SimpleNamespace(source_interval_seconds=1, job_poll_seconds=0.05)
        calls = []

        def run_once(*_args):
            calls.append(True)
            if len(calls) == 1:
                return _summary(False)
            raise StopIteration

        with patch("narrowcti.cli.worker.process_pending_jobs", return_value=0), patch(
            "narrowcti.cli.worker.run_gateway_once", side_effect=run_once
        ):
            with self.assertRaises(StopIteration):
                run_worker_loop(settings, object(), lambda _message: None, sleeper=lambda _seconds: None)
        self.assertEqual(2, len(calls))

    def test_legacy_gateway_entrypoint_returns_numeric_source_failure_status(self):
        from gateway.connector import main as legacy_main

        settings = SimpleNamespace(run_once=True)
        with patch("gateway.connector.load_settings", return_value=settings), patch(
            "gateway.connector.default_source_registry", return_value=object()
        ), patch("gateway.connector.run_worker", return_value=_summary(False)):
            self.assertEqual(2, legacy_main())


if __name__ == "__main__":
    unittest.main()
