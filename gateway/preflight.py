import argparse
import json
import os
from dataclasses import dataclass

from gateway.settings import load_settings


AVAILABLE_SOURCES = ("otx", "misp")


@dataclass(frozen=True)
class PreflightIssue:
    severity: str
    code: str
    message: str

    def to_dict(self):
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class PreflightReport:
    ok: bool
    enabled_sources: tuple[str, ...]
    available_sources: tuple[str, ...]
    settings: dict
    source_controls: dict
    issues: tuple[PreflightIssue, ...]

    def to_dict(self):
        return {
            "ok": self.ok,
            "enabled_sources": list(self.enabled_sources),
            "available_sources": list(self.available_sources),
            "settings": self.settings,
            "source_controls": self.source_controls,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def build_preflight_report(settings, available_sources=AVAILABLE_SOURCES, env=None):
    env = env if env is not None else os.environ
    available = tuple(normalize_source(value) for value in available_sources)
    enabled = tuple(normalize_source(value) for value in settings.enabled_sources)
    issues = []

    unknown_sources = tuple(source for source in enabled if source not in available)
    for source in unknown_sources:
        issues.append(
            PreflightIssue(
                "error",
                "unknown-source",
                f"Enabled source is not registered: {source}",
            )
        )

    if settings.mode != "gateway":
        issues.append(
            PreflightIssue(
                "warning",
                "non-gateway-mode",
                f"NARROWCTI_MODE is {settings.mode}; expected gateway for v0.5 runtime.",
            )
        )

    if settings.dedup_mode == "off":
        issues.append(
            PreflightIssue(
                "warning",
                "dedup-disabled",
                "NARROWCTI_DEDUP_MODE=off disables source and artifact graph hygiene controls.",
            )
        )
    elif settings.dedup_mode == "source":
        issues.append(
            PreflightIssue(
                "warning",
                "artifact-dedup-disabled",
                "NARROWCTI_DEDUP_MODE=source keeps per-source state "
                "but does not keep a shared artifact index.",
            )
        )

    if settings.opencti_dedup_lookup and settings.dedup_mode not in ("artifact", "hybrid"):
        issues.append(
            PreflightIssue(
                "warning",
                "opencti-lookup-without-local-artifacts",
                "OpenCTI lookup is enabled without the local artifact index "
                "used for source sightings.",
            )
        )

    if not settings.run_summary_file:
        issues.append(
            PreflightIssue(
                "info",
                "run-summary-disabled",
                "NARROWCTI_RUN_SUMMARY_FILE is empty; aggregate gateway "
                "JSONL summaries will not be written.",
            )
        )

    source_controls = build_source_controls(enabled, env)
    unsafe_sources = [
        source
        for source, controls in source_controls.items()
        if not controls.get("dry_run", False)
    ]
    for source in unsafe_sources:
        issues.append(
            PreflightIssue(
                "warning",
                "source-dry-run-disabled",
                f"{source} dry-run is disabled; validate limits and "
                "OpenCTI capacity before running.",
            )
        )

    ok = not any(issue.severity == "error" for issue in issues)
    return PreflightReport(
        ok=ok,
        enabled_sources=enabled,
        available_sources=available,
        settings={
            "mode": settings.mode,
            "dry_run": settings.dry_run,
            "run_once": settings.run_once,
            "source_interval_seconds": settings.source_interval_seconds,
            "state_dir": settings.state_dir,
            "decision_audit_dir": settings.decision_audit_dir,
            "run_summary_file": settings.run_summary_file,
            "min_score_to_ingest": settings.min_score_to_ingest,
            "enable_quarantine": settings.enable_quarantine,
            "quarantine_score_threshold": settings.quarantine_score_threshold,
            "max_days_old": settings.max_days_old,
            "dedup_mode": settings.dedup_mode,
            "opencti_dedup_lookup": settings.opencti_dedup_lookup,
            "dedup_state_file": settings.dedup_state_file,
        },
        source_controls=source_controls,
        issues=tuple(issues),
    )


def build_source_controls(enabled_sources, env):
    controls = {}
    for source in enabled_sources:
        if source == "otx":
            controls[source] = {
                "dry_run": env_bool(env, "OTX_DRY_RUN", env_bool(env, "NARROWCTI_DRY_RUN", False)),
                "dry_run_variable": "OTX_DRY_RUN",
            }
        elif source == "misp":
            controls[source] = {
                "dry_run": env_bool(env, "MISP_DRY_RUN", True),
                "dry_run_variable": "MISP_DRY_RUN",
                "run_once": env_bool(env, "MISP_RUN_ONCE", False),
            }
        else:
            controls[source] = {}
    return controls


def normalize_source(value):
    return str(value).strip().lower()


def env_bool(env, name, default=False):
    value = env.get(name)
    if value is None:
        return default
    return str(value).lower() in ("true", "1", "yes")


def format_text_report(report):
    lines = [
        "NarrowCTI gateway preflight",
        f"ok={str(report.ok).lower()}",
        f"enabled_sources={','.join(report.enabled_sources)}",
        f"available_sources={','.join(report.available_sources)}",
        f"dedup_mode={report.settings['dedup_mode']}",
        f"opencti_dedup_lookup={str(report.settings['opencti_dedup_lookup']).lower()}",
        f"run_summary_file={report.settings['run_summary_file'] or '(disabled)'}",
        f"min_score_to_ingest={report.settings['min_score_to_ingest']}",
        f"enable_quarantine={str(report.settings['enable_quarantine']).lower()}",
        f"quarantine_score_threshold={report.settings['quarantine_score_threshold']}",
        f"max_days_old={report.settings['max_days_old']}",
    ]
    for source, controls in report.source_controls.items():
        if "dry_run" in controls:
            lines.append(f"{source}.dry_run={str(controls['dry_run']).lower()}")
    if report.issues:
        lines.append("issues:")
        for issue in report.issues:
            lines.append(f"- {issue.severity} {issue.code}: {issue.message}")
    return "\n".join(lines)


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
            available_sources=AVAILABLE_SOURCES,
            settings={},
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
