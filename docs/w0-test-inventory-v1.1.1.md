# W0 test inventory and characterization gaps

The 544 existing tests are the primary characterization layer. This matrix
prevents a second suite from merely repeating them.

| Invariant | Existing protection | Protection level | Characterization gap | New artifact |
| --- | --- | --- | --- | --- |
| MISP normalization and provenance | `test_misp_processor.py`, `test_misp_feed_adapter.py`, `test_misp_settings.py` | High | no complete normalized/evidence golden | golden fixture |
| GraphEvidence relation classification | `test_graph_evidence.py`, `test_opencti_relationship_audit.py` | High | no serialized representative output | golden fixture |
| GraphCandidate/GraphExportPlan and idempotency | `test_graph_candidates.py`, `test_graph_export_plan.py`, `test_graph_deduplication.py`, `test_opencti_graph_lookup.py` | High | no candidate-to-plan golden | golden fixture |
| STIX bundle and source publication time | `test_graph_stix_builder.py`, `test_core_pipeline.py` | High | no bundle golden preserving source date | golden fixture |
| DecisionRecord and audit | `test_core_pipeline.py`, `test_gateway_decisions.py`, `test_gateway_operational_validation.py` | High | no stable JSONL record contract | golden fixture |
| Sigma/detection-rule compatibility | `test_misp_processor.py`, `test_misp_connector.py` | Medium/high | no complete compatibility/rejection golden | targeted fixture |
| Canonical OpenCTI lookup | `test_opencti_graph_lookup.py`, `test_opencti_client*.py` | High | no lookup snapshot contract | golden fixture |
| Configuration/default precedence | `test_misp_settings.py`, `test_gateway_preflight.py`, `test_feature_gates.py` | High | matrix not documented | documentation only |
| Quarantine and state transitions | `test_quarantine_*.py`, `test_gateway_quarantine.py` | High | no gap identified | none in W0 |
| Event/publication/observation dates | MISP and STIX builder tests | Medium | no explicit event-date-vs-ingestion golden | targeted fixture |

New tests in `test_w0_characterization.py` are restricted to the gaps and the
Git-tree inventory contract. They do not repeat the existing behavior suite.
