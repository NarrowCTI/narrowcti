import ast
import unittest
from pathlib import Path

from narrowcti.application.ingestion import IngestionOutcome, run_candidate
from narrowcti.application.ingestion.contracts import IngestionOperations


class IngestionPipelineTests(unittest.TestCase):
    def operations(self, calls, *, tlp=None, policy=None, dry_run=False, export=None):
        decisions = []

        def record(candidate_ref, candidate, outcome):
            calls.append("decision")
            decisions.append((candidate_ref, candidate, outcome))

        return IngestionOperations(
            precheck=lambda candidate_ref: None,
            enrich=lambda candidate_ref: calls.append("enrich") or {"id": candidate_ref},
            tlp=tlp or (lambda candidate: calls.append("tlp") or IngestionOutcome("ingest", "tlp-allowed")),
            score=lambda candidate: calls.append("score") or candidate,
            policy=policy or (lambda candidate: calls.append("policy") or IngestionOutcome("ingest", "policy-approved")),
            indicator_filter=lambda candidate: (
                calls.append("indicator_filter") or (candidate, "")
            ),
            artifact_dedup=lambda candidate: calls.append("artifact_dedup") or (candidate, ""),
            export=export or (lambda ref, candidate, reason: calls.append("export") or True),
            mark_artifacts=lambda candidate: calls.append("artifact_mark"),
            checkpoint=lambda candidate: calls.append("checkpoint"),
            record_decision=record,
            mark_graph=lambda ref, candidate, metadata: calls.append("graph_mark"),
            dry_run=dry_run,
        ), decisions

    def test_tlp_deny_short_circuits_before_scoring(self):
        calls = []
        operations, decisions = self.operations(
            calls,
            tlp=lambda candidate: calls.append("tlp")
            or IngestionOutcome("drop", "tlp not allowed"),
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual("drop", result.action)
        self.assertEqual(["enrich", "tlp", "decision"], calls)
        self.assertEqual("tlp not allowed", decisions[0][2].reason)

    def test_scoring_runs_before_policy(self):
        calls = []
        operations, _ = self.operations(calls)

        result = run_candidate("candidate-1", operations)

        self.assertEqual("ingest", result.action)
        self.assertLess(calls.index("score"), calls.index("policy"))

    def test_terminal_policy_result_short_circuits_later_steps(self):
        calls = []
        operations, _ = self.operations(
            calls,
            policy=lambda candidate: calls.append("policy")
            or IngestionOutcome("quarantine", "low score"),
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual("quarantine", result.action)
        self.assertEqual(
            ["enrich", "tlp", "score", "policy", "decision"],
            calls,
        )

    def test_success_preserves_side_effect_order_and_graph_mark(self):
        calls = []
        operations, decisions = self.operations(
            calls,
            export=lambda ref, candidate, reason: calls.append("export") or {"graph_export_plan": {"actions": []}},
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual("ingest", result.action)
        self.assertEqual(
            [
                "enrich",
                "tlp",
                "score",
                "policy",
                "indicator_filter",
                "artifact_dedup",
                "export",
                "artifact_mark",
                "checkpoint",
                "decision",
                "graph_mark",
            ],
            calls,
        )
        self.assertEqual("ingest", decisions[0][2].action)
        self.assertEqual("policy-approved", result.reason)

    def test_precheck_terminal_short_circuits_pipeline(self):
        calls = []
        operations, decisions = self.operations(calls)
        operations = IngestionOperations(
            **{**operations.__dict__, "precheck": lambda ref: IngestionOutcome("skip", "already processed")}
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual(IngestionOutcome("skip", "already processed"), result)
        self.assertEqual(1, len(decisions))
        self.assertEqual(["decision"], calls)
        self.assertEqual("already processed", decisions[0][2].reason)

    def test_indicator_filter_skip_is_terminal(self):
        calls = []
        candidate = {"id": "candidate-before-filter"}
        operations, decisions = self.operations(
            calls,
        )
        operations = IngestionOperations(
            **{
                **operations.__dict__,
                "enrich": lambda ref: candidate,
                "indicator_filter": lambda candidate: (None, "indicator filtered"),
            }
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual(IngestionOutcome("skip", "indicator filtered"), result)
        self.assertEqual(1, len(decisions))
        self.assertIs(candidate, decisions[0][1])
        self.assertNotIn("artifact_dedup", calls)
        self.assertNotIn("export", calls)

    def test_artifact_dedup_skip_is_terminal(self):
        calls = []
        candidate = {"id": "candidate-before-dedup"}
        operations, decisions = self.operations(calls)
        operations = IngestionOperations(
            **{
                **operations.__dict__,
                "enrich": lambda ref: candidate,
                "artifact_dedup": lambda candidate: (None, "all indicators already known"),
            }
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual(IngestionOutcome("skip", "all indicators already known"), result)
        self.assertEqual(1, len(decisions))
        self.assertIs(candidate, decisions[0][1])
        self.assertNotIn("export", calls)
        self.assertNotIn("artifact_mark", calls)
        self.assertNotIn("checkpoint", calls)

    def test_export_error_does_not_mark_or_checkpoint(self):
        calls = []
        operations, _ = self.operations(
            calls,
            export=lambda ref, candidate, reason: calls.append("export") or False,
        )

        result = run_candidate("candidate-1", operations)

        self.assertEqual(IngestionOutcome("error", "export failed"), result)
        self.assertNotIn("artifact_mark", calls)
        self.assertNotIn("checkpoint", calls)

    def test_graph_replay_preserves_reason_and_skips_artifact_side_effect(self):
        calls = []
        exported = []
        graph_marks = []

        def export(ref, candidate, reason):
            calls.append("export")
            exported.append((ref, reason))
            return {"graph_export_plan": {"actions": []}}

        operations, _ = self.operations(calls, export=export)
        operations = IngestionOperations(
            **{
                **operations.__dict__,
                "enrich": lambda ref: {"id": ref, "indicators": []},
                "artifact_dedup": lambda candidate: (candidate, "graph replay reason"),
                "mark_artifacts": lambda candidate: calls.append("artifact_mark")
                if candidate.get("indicators")
                else None,
                "mark_graph": lambda ref, candidate, metadata: graph_marks.append(metadata),
            }
        )

        result = run_candidate("candidate-graph", operations)

        self.assertEqual(IngestionOutcome("ingest", "graph replay reason"), result)
        self.assertEqual([("candidate-graph", "graph replay reason")], exported)
        self.assertNotIn("artifact_mark", calls)
        self.assertIn("checkpoint", calls)
        self.assertEqual(1, len(graph_marks))

    def test_dry_run_has_no_export_or_persistence_side_effects(self):
        calls = []
        operations, _ = self.operations(calls, dry_run=True)

        result = run_candidate("candidate-1", operations)

        self.assertEqual("dry_run", result.action)
        self.assertEqual("policy-approved", result.reason)
        self.assertNotIn("export", calls)
        self.assertNotIn("artifact_mark", calls)
        self.assertNotIn("checkpoint", calls)
        self.assertNotIn("graph_mark", calls)

    def test_outcome_vocabulary_is_exact(self):
        from narrowcti.application.ingestion.outcomes import INGESTION_OUTCOMES

        self.assertEqual(
            (
                "ingest",
                "drop",
                "quarantine",
                "skip",
                "error",
                "dry_run",
            ),
            INGESTION_OUTCOMES,
        )

    def test_ingestion_boundary_has_no_runtime_boundary_imports(self):
        root = Path(__file__).resolve().parents[1] / "src" / "narrowcti" / "application" / "ingestion"
        forbidden = (
            "core",
            "connectors",
            "gateway",
            "exporters",
            "narrowcti.adapters",
            "narrowcti.infrastructure",
            "narrowcti.api",
        )

        for source_file in root.glob("*.py"):
            tree = ast.parse(source_file.read_text(encoding="utf-8"))
            imports = [
                node.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            ]
            imports.extend(
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            )
            for imported in imports:
                self.assertFalse(
                    imported == "core"
                    or imported.startswith(("core.", "connectors.", "gateway.", "exporters."))
                    or imported.startswith(forbidden[4:]),
                    f"{source_file.name} imports forbidden runtime boundary {imported}",
                )


if __name__ == "__main__":
    unittest.main()
