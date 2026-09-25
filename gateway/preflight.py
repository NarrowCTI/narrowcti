"""Compatibility/composition surface for runtime preflight."""

from __future__ import annotations
# ruff: noqa: F403, F405

import argparse
import json
import os

from core.mitre_attack import load_attack_cache
from core.runtime_config import parse_misp_verify_tls
from gateway.feature_gates import build_capability_inventory
from gateway.settings import load_settings
from narrowcti.application.preflight import *  # noqa: F403
from narrowcti.application.preflight import (
    AVAILABLE_SOURCES,
    PreflightIssue,
    PreflightReport,
    build_preflight_report as _build_preflight_report,
)

def build_preflight_report(settings, available_sources=AVAILABLE_SOURCES, env=None):
    env = env if env is not None else os.environ
    enabled = tuple(str(value).strip().lower() for value in settings.enabled_sources)
    misp_verify_tls = True
    misp_tls_error = ""
    if "misp" in enabled:
        try:
            misp_verify_tls = parse_misp_verify_tls(env.get("MISP_VERIFY_TLS"))
        except ValueError as exc:
            misp_verify_tls = None
            misp_tls_error = str(exc)
    return _build_preflight_report(
        settings,
        available_sources=available_sources,
        env=env,
        feature_gate_state=build_capability_inventory(
            requested_capabilities=getattr(settings, "declared_capabilities", []),
        ),
        misp_verify_tls=misp_verify_tls,
        misp_tls_error=misp_tls_error,
        mitre_issues=mitre_cache_issues(settings),
    )

def mitre_cache_issues(settings):
    if not getattr(settings, "enable_mitre_attack_resolution", True):
        return [
            PreflightIssue(
                "info",
                "mitre-resolution-disabled",
                "NARROWCTI_ENABLE_MITRE_ATTACK_RESOLUTION is disabled; "
                "ATT&CK ids will remain unresolved metadata.",
            )
        ]

    issues = []
    cache_file = getattr(settings, "mitre_cache_file", "")
    if not cache_file:
        issues.append(
            PreflightIssue(
                "warning",
                "mitre-cache-disabled",
                "NARROWCTI_MITRE_CACHE_FILE is empty; ATT&CK enrichment will "
                "record missing-cache evidence.",
            )
        )
    elif not os.path.exists(cache_file):
        issues.append(
            PreflightIssue(
                "warning",
                "mitre-cache-missing",
                f"MITRE ATT&CK cache does not exist: {cache_file}",
            )
        )
    else:
        try:
            cache = load_attack_cache(cache_file)
            if int(cache.get("technique_count", 0) or 0) <= 0:
                issues.append(
                    PreflightIssue(
                        "warning",
                        "mitre-cache-empty",
                        f"MITRE ATT&CK cache has no techniques: {cache_file}",
                    )
                )
        except Exception as exc:
            issues.append(
                PreflightIssue(
                    "warning",
                    "mitre-cache-invalid",
                    f"MITRE ATT&CK cache could not be loaded: {cache_file} error={exc}",
                )
            )

    if not getattr(settings, "mitre_stix_url", ""):
        issues.append(
            PreflightIssue(
                "warning",
                "mitre-stix-url-empty",
                "NARROWCTI_MITRE_STIX_URL is empty; refresh-cache has no "
                "configured ATT&CK source URL.",
            )
        )
    return issues


def main():
    parser = argparse.ArgumentParser(
        description="Validate NarrowCTI gateway runtime configuration."
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    try:
        report = build_preflight_report(load_settings())
    except Exception as exc:
        issue = PreflightIssue("error", "settings-invalid", str(exc))
        report = PreflightReport(
            ok=False,
            enabled_sources=(),
            ingestion_mode="direct",
            available_sources=AVAILABLE_SOURCES,
            settings={},
            evidence_paths={},
            source_controls={},
            issues=(issue,),
        )

    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print(format_text_report(report))
    raise SystemExit(0 if report.ok else 1)




if __name__ == "__main__":
    main()
