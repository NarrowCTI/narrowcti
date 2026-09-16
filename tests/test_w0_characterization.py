import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.decision_audit import DecisionRecord
from core.graph_candidates import apply_graph_candidate_policy, build_graph_candidates
from core.graph_evidence import build_graph_evidence
from core.graph_export_plan import build_graph_export_plan
from exporters.stix_builder import build_graph_report_bundle


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "w0"
INVENTORY_SCRIPT = ROOT / "scripts" / "generate_w0_baseline_inventory.py"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def detection_metadata():
    return {
        "misp_event_id": "822",
        "misp_event_date": "2017-02-18",
        "misp_detection_rules": [
            {
                "value": "sigma-w0",
                "rule_type": "sigma",
                "pattern_type": "sigma",
                "pattern": "selection: Image|endswith: powershell.exe",
                "opencti_indicator_compatible": True,
                "opencti_indicator_compatibility_reason": "valid sigma pattern",
                "attack_pattern_ids": ["T1059.001"],
                "attack_id_source": "Galaxy",
                "source_field": "Attribute",
            }
        ],
    }


class W0CharacterizationTests(unittest.TestCase):
    def test_inventory_uses_a_git_tree_and_preserves_tracked_empty_files(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "state").mkdir()
            (repo / "state" / ".gitkeep").write_bytes(b"")
            (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            (repo / "working-only.txt").write_text("not tracked\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(
                ["git", "config", "user.email", "w0@example.invalid"],
                cwd=repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "W0 Test"],
                cwd=repo,
                check=True,
            )
            subprocess.run(["git", "add", "state/.gitkeep", "tracked.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            subprocess.run(["git", "tag", "v1.1.1"], cwd=repo, check=True)

            result = subprocess.run(
                [
                    sys.executable,
                    str(INVENTORY_SCRIPT),
                    "--repo",
                    str(repo),
                    "--ref",
                    "v1.1.1",
                    "--expected-commit",
                    commit,
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            inventory = json.loads(result.stdout)

            self.assertEqual(commit, inventory["commit"])
            self.assertEqual(2, inventory["entry_count"])
            paths = {item["path"] for item in inventory["entries"]}
            self.assertEqual({"state/.gitkeep", "tracked.txt"}, paths)
            self.assertNotIn("working-only.txt", paths)
            empty = next(item for item in inventory["entries"] if item["path"] == "state/.gitkeep")
            self.assertEqual(0, empty["size"])
            self.assertEqual(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                empty["sha256"],
            )

    def test_release_inventory_has_canonical_shape_when_tag_is_available(self):
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "--verify", "v1.1.1^{commit}"],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except subprocess.CalledProcessError:
            self.skipTest("release tag is not available in this checkout")

        result = subprocess.run(
            [sys.executable, str(INVENTORY_SCRIPT), "--ref", "v1.1.1"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        inventory = json.loads(result.stdout)
        self.assertEqual(
            "4e3509b8f18c330361994975ab3c5b11e8f5b05f",
            commit,
        )
        self.assertEqual(commit, inventory["commit"])
        self.assertEqual(205, inventory["entry_count"])
        self.assertIn("state/.gitkeep", {item["path"] for item in inventory["entries"]})

    def test_misp_evidence_and_sigma_relationship_golden(self):
        expected = fixture("misp-normalized-evidence.json")
        evidence = build_graph_evidence(
            detection_metadata(),
            source_key="misp",
            external_id="822",
            title="W0 fixture",
        )
        record = evidence["records"][0]

        self.assertEqual(expected["version"], evidence["version"])
        self.assertEqual(expected["record_count"], evidence["record_count"])
        self.assertEqual(expected["counts"], evidence["counts"])
        self.assertEqual(expected["record"]["entity_type"], record["entity_type"])
        self.assertEqual(expected["record"]["relationship_type"], record["relationship_type"])
        self.assertEqual(expected["record"]["attack_pattern_id"], record["attributes"]["attack_pattern_ids"][0])
        self.assertEqual(expected["record"]["relationship_inference"], record["attributes"]["relationship_inference"])
        self.assertEqual(expected["record"]["source_date"], record["attributes"]["source_date"])

        sigma = fixture("sigma-compatibility.json")
        self.assertEqual(sigma["rule_type"], record["attributes"]["rule_type"])
        self.assertEqual(sigma["pattern_type"], record["attributes"]["pattern_type"])
        self.assertEqual(sigma["opencti_indicator_compatible"], record["attributes"]["opencti_indicator_compatible"])

    def test_graph_candidate_and_export_plan_golden(self):
        evidence = build_graph_evidence(
            detection_metadata(), source_key="misp", external_id="822", title="W0 fixture"
        )
        candidates = build_graph_candidates(evidence)
        policy = apply_graph_candidate_policy(
            candidates, require_relationship_provenance=True
        )
        plan = build_graph_export_plan(policy.to_dict(), mode="dry-run")
        expected = fixture("graph-export-plan.json")
        for key in (
            "version",
            "mode",
            "status",
            "export_enabled",
            "candidate_count",
            "accepted_count",
            "held_count",
            "accepted_object_counts",
            "accepted_relationship_counts",
            "would_create_object_count",
            "would_create_relationship_count",
        ):
            self.assertEqual(expected[key], plan[key], key)

        candidate = candidates.to_dict()["candidates"][0]
        self.assertEqual("detection_rule", candidate["entity_type"])
        self.assertEqual("detects", candidate["relationship_type"])
        self.assertEqual("misp", candidate["source_key"])

    def test_stix_publication_and_decision_golden_contracts(self):
        expected_stix = fixture("stix-bundle.json")
        evidence = build_graph_evidence(
            detection_metadata(), source_key="misp", external_id="822", title="W0 fixture"
        )
        policy = apply_graph_candidate_policy(
            build_graph_candidates(evidence), require_relationship_provenance=True
        )
        bundle, summary = build_graph_report_bundle(
            "Historical MISP event",
            "Imported source event",
            85,
            graph_candidate_policy=policy.to_dict(),
            published_at="2017-02-18",
        )
        data = json.loads(bundle.serialize())
        object_types = {item["type"] for item in data["objects"]}
        self.assertEqual(1, summary["accepted_candidate_count"])
        self.assertTrue(set(expected_stix["required_object_types"]).issubset(object_types))
        self.assertEqual(1, summary["graph_relationship_count"])
        report = next(item for item in data["objects"] if item["type"] == "report")
        self.assertEqual("2017-02-18", report["x_narrowcti_source_date"])

        expected_decision = fixture("decision-record.json")
        decision = DecisionRecord(
            action=expected_decision["action"],
            reason=expected_decision["reason"],
            source_key=expected_decision["source_key"],
            external_id=expected_decision["external_id"],
            title=expected_decision["title"],
            query=expected_decision["query"],
            score=expected_decision["score"],
            age_days=expected_decision["age_days"],
            indicator_count=expected_decision["indicator_count"],
            recorded_at=expected_decision["recorded_at"],
            metadata=expected_decision["metadata"],
        )
        self.assertEqual(expected_decision, decision.to_dict())

if __name__ == "__main__":
    unittest.main()
