"""PR-17 contracts for canonical reporting, assurance and validation boundaries."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "narrowcti"


def imported_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


class PR17BoundaryTests(unittest.TestCase):
    def test_canonical_application_modules_do_not_import_runtime_boundaries(self):
        files = [
            *sorted((SRC / "application" / "reporting").glob("*.py")),
            *sorted((SRC / "application" / "assurance").glob("*.py")),
            *sorted((SRC / "application" / "validation").glob("*.py")),
            SRC / "application" / "preflight.py",
        ]
        forbidden_prefixes = (
            "core",
            "connectors",
            "gateway",
            "exporters",
            "pycti",
            "stix2",
            "requests",
            "argparse",
        )
        for path in files:
            for imported in imported_names(path):
                self.assertFalse(
                    imported == forbidden_prefixes
                    or imported.startswith(forbidden_prefixes),
                    f"{path.relative_to(ROOT)} imports forbidden boundary {imported}",
                )

    def test_support_diagnostics_is_semantic_and_not_a_filesystem_writer(self):
        path = SRC / "application" / "support" / "diagnostics.py"
        forbidden_prefixes = ("gateway", "core", "zipfile", "os", "pathlib")
        for imported in imported_names(path):
            self.assertFalse(
                imported == forbidden_prefixes
                or imported.startswith(forbidden_prefixes),
                f"support diagnostics imports forbidden boundary {imported}",
            )

    def test_relationship_transport_is_adapter_owned(self):
        application_path = SRC / "application" / "assurance" / "opencti_relationship_audit.py"
        adapter_path = SRC / "adapters" / "opencti" / "relationship_audit.py"
        self.assertNotIn("requests", imported_names(application_path))
        self.assertIn("requests", imported_names(adapter_path))
        self.assertIn("urllib.parse", imported_names(adapter_path))

    def test_preflight_keeps_legacy_composition_outside_canonical_module(self):
        path = SRC / "application" / "preflight.py"
        imports = imported_names(path)
        self.assertNotIn("core.runtime_config", imports)
        self.assertNotIn("core.mitre_attack", imports)
        self.assertNotIn("gateway.feature_gates", imports)

    def test_legacy_wrappers_reexport_canonical_semantics(self):
        pairs = (
            ("gateway.report", "narrowcti.application.reporting.operational", "build_operational_report"),
            ("gateway.correlation", "narrowcti.application.reporting.correlation", "build_correlation_report"),
            ("gateway.decisions", "narrowcti.application.reporting.decisions", "build_decision_audit_report"),
            ("gateway.curation_report", "narrowcti.application.reporting.curation", "build_curation_report"),
            ("gateway.operational_validation", "narrowcti.application.assurance.operational_validation", "build_operational_validation_report"),
            ("gateway.opencti_relationship_audit", "narrowcti.application.assurance.opencti_relationship_audit", "summarize_relationships"),
            ("gateway.opencti_client_validation", "narrowcti.application.validation.opencti_client", "validate_authentication"),
        )
        for legacy_name, canonical_name, symbol in pairs:
            legacy = importlib.import_module(legacy_name)
            canonical = importlib.import_module(canonical_name)
            self.assertIs(getattr(legacy, symbol), getattr(canonical, symbol), f"{legacy_name}.{symbol}")

    def test_operational_validation_uses_composed_legacy_preflight(self):
        import gateway.operational_validation as legacy_validation
        import gateway.preflight as legacy_preflight

        self.assertIs(
            legacy_validation.build_preflight_report,
            legacy_preflight.build_preflight_report,
        )

    def test_operational_validation_preflight_preserves_misp_tls_evidence(self):
        from gateway.operational_validation import build_preflight_report
        from tests.test_gateway_preflight import make_settings

        report = build_preflight_report(
            make_settings(enabled_sources=["misp"]),
            env={"MISP_VERIFY_TLS": "definitely-invalid"},
        )
        issue_codes = {issue.code for issue in report.issues}
        self.assertIn("misp-tls-invalid", issue_codes)
        self.assertEqual("error", next(issue.severity for issue in report.issues if issue.code == "misp-tls-invalid"))

    def test_gateway_report_write_report_preserves_legacy_return_contract(self):
        import tempfile

        from gateway.report import build_operational_report, render_report, write_report

        report = build_operational_report([])
        self.assertIsNone(write_report(report, ""))
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "report.txt"
            self.assertIsNone(write_report(report, output_file))
            self.assertEqual(
                render_report(report) + "\n",
                output_file.read_text(encoding="utf-8"),
            )

    def test_legacy_reader_and_semantic_constants_are_preserved(self):
        import gateway.decisions as legacy_decisions
        import gateway.operational_validation as legacy_validation
        import gateway.report as legacy_report
        from narrowcti.adapters.persistence.local.decision_audit_reader import expand_paths
        from narrowcti.application.assurance import operational_validation as canonical_validation
        from narrowcti.application.reporting import decisions as canonical_decisions
        from narrowcti.application.runtime import SUMMARY_FIELDS

        self.assertIs(legacy_decisions.expand_paths, expand_paths)
        self.assertIs(legacy_decisions.ACTION_ORDER, canonical_decisions.ACTION_ORDER)
        self.assertIs(
            legacy_decisions.GRAPH_ENTITY_CATEGORIES,
            canonical_decisions.GRAPH_ENTITY_CATEGORIES,
        )
        self.assertIs(
            legacy_decisions.GRAPH_ENTITY_TOP_FIELDS,
            canonical_decisions.GRAPH_ENTITY_TOP_FIELDS,
        )
        self.assertIs(legacy_validation.STATUS_ORDER, canonical_validation.STATUS_ORDER)
        self.assertIs(
            legacy_validation.DECISION_SOURCE_ALIASES,
            canonical_validation.DECISION_SOURCE_ALIASES,
        )
        self.assertIs(legacy_report.SUMMARY_FIELDS, SUMMARY_FIELDS)

    def test_opencti_validation_lookup_surface_is_preserved(self):
        import gateway.opencti_client_validation as legacy_validation
        from narrowcti.application.validation import opencti_client as canonical_validation

        self.assertEqual(
            legacy_validation.REPORT_LOOKUP_QUERY,
            canonical_validation.REPORT_LOOKUP_QUERY,
        )
        self.assertIs(
            legacy_validation.exact_report_matches,
            canonical_validation.exact_report_matches,
        )

    def test_canonical_modules_are_importable_without_gateway_composition(self):
        modules = (
            "narrowcti.application.preflight",
            "narrowcti.application.reporting.operational",
            "narrowcti.application.reporting.correlation",
            "narrowcti.application.reporting.decisions",
            "narrowcti.application.reporting.curation",
            "narrowcti.application.assurance.opencti_relationship_audit",
            "narrowcti.application.assurance.operational_validation",
            "narrowcti.application.validation.opencti_client",
            "narrowcti.application.support.diagnostics",
        )
        for module_name in modules:
            self.assertIsNotNone(importlib.import_module(module_name))


if __name__ == "__main__":
    unittest.main()
