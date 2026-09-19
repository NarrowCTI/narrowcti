import os
import tempfile
import unittest

from core import atomic_io as legacy_atomic
from core import deduplication as legacy_artifacts
from core import state_repository as legacy_state
from core.graph_deduplication import GraphDeduplicationIndex
from narrowcti.adapters.persistence.local import (
    ArtifactDeduplicationIndex,
    MISPEventStateRepository,
    ProcessedItemStateRepository,
    PulseStateRepository,
)
from narrowcti.adapters.persistence.local import artifact_index as local_artifacts
from narrowcti.adapters.persistence.local import atomic_io as local_atomic
from narrowcti.adapters.persistence.local import state_repository as local_state
from narrowcti.ports.graph import GraphIndex
from narrowcti.ports.storage import ArtifactIndex, StateRepository


class PR06PortCompatibilityTests(unittest.TestCase):
    def test_legacy_core_symbols_are_exact_canonical_objects(self):
        self.assertIs(legacy_atomic.write_json_atomic, local_atomic.write_json_atomic)
        self.assertIs(
            legacy_state.ProcessedItemStateRepository,
            local_state.ProcessedItemStateRepository,
        )
        self.assertIs(legacy_state.PulseStateRepository, local_state.PulseStateRepository)
        self.assertIs(
            legacy_state.MISPEventStateRepository,
            local_state.MISPEventStateRepository,
        )
        self.assertIs(
            legacy_artifacts.ArtifactDeduplicationIndex,
            local_artifacts.ArtifactDeduplicationIndex,
        )
        self.assertFalse(hasattr(local_artifacts, "LocalArtifactIndex"))

    def test_concrete_names_remain_historical(self):
        self.assertEqual("ProcessedItemStateRepository", ProcessedItemStateRepository.__name__)
        self.assertEqual("PulseStateRepository", PulseStateRepository.__name__)
        self.assertEqual("MISPEventStateRepository", MISPEventStateRepository.__name__)
        self.assertEqual("ArtifactDeduplicationIndex", ArtifactDeduplicationIndex.__name__)

    def test_concrete_implementations_satisfy_minimal_protocols(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            artifact_file = os.path.join(tmpdir, "artifacts.json")
            graph_file = os.path.join(tmpdir, "graph.json")

            state = ProcessedItemStateRepository(state_file, "pulses")
            artifacts = ArtifactDeduplicationIndex(artifact_file)
            graph = GraphDeduplicationIndex(graph_file)

            self.assertIsInstance(state, StateRepository)
            self.assertIsInstance(artifacts, ArtifactIndex)
            self.assertIsInstance(graph, GraphIndex)

    def test_state_adapter_preserves_source_collections_and_refresh(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "state.json")
            pulse = PulseStateRepository(state_file)
            misp = MISPEventStateRepository(state_file)

            pulse.mark_pulse("pulse-1")
            misp.mark_event("event-1")

            self.assertTrue(PulseStateRepository(state_file).has_pulse("pulse-1"))
            self.assertTrue(MISPEventStateRepository(state_file).has_event("event-1"))
            self.assertFalse(MISPEventStateRepository(state_file).has_event("pulse-1"))

    def test_artifact_adapter_preserves_fingerprint_and_sighting_contract(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "artifacts.json")
            index = ArtifactDeduplicationIndex(state_file)
            indicator = {"type": "Domain", "indicator": " Example.COM "}

            self.assertEqual(1, index.mark_indicators(
                [indicator],
                source_key="misp:misp",
                external_id="event-1",
                title="MISP event",
            ))
            self.assertEqual(
                ([], 1),
                index.filter_new_indicators(
                    [{"type": "domain", "indicator": "example.com"}]
                ),
            )
            record = index.artifact_record("domain:example.com")
            self.assertEqual("domain:example.com", record["fingerprint"])
            self.assertEqual(["misp:misp"], record["sources"])
            self.assertEqual("event-1", record["sightings"][0]["external_id"])


if __name__ == "__main__":
    unittest.main()
