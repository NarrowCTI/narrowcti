import argparse
import html
import json
import os
from dataclasses import dataclass

from core.decision_audit import utc_now
from gateway.decisions import build_decision_audit_report, read_decision_records
from gateway.report import (
    build_operational_report,
    read_gateway_summary_file,
    read_quarantine_records,
)
from gateway.review import AnalystReviewService, ReviewSummary
from gateway.settings import load_settings


@dataclass(frozen=True)
class CurationReport:
    generated_at: str
    executive_summary: dict
    operational: dict
    decisions: dict
    analyst_review: dict
    recommendations: list

    def to_dict(self):
        return {
            "generated_at": self.generated_at,
            "executive_summary": self.executive_summary,
            "operational": self.operational,
            "decisions": self.decisions,
            "analyst_review": self.analyst_review,
            "recommendations": list(self.recommendations),
        }


def build_curation_report(
    operational_report,
    decision_report,
    analyst_review_summary,
    generated_at="",
):
    operational = operational_report.to_dict()
    decisions = decision_report.to_dict()
    analyst_review = analyst_review_summary.to_dict()
    executive = build_executive_summary(operational, decisions, analyst_review)
    return CurationReport(
        generated_at=generated_at or utc_now(),
        executive_summary=executive,
        operational=operational,
        decisions=decisions,
        analyst_review=analyst_review,
        recommendations=build_recommendations(executive),
    )


def build_executive_summary(operational, decisions, analyst_review):
    totals = operational.get("totals") or {}
    metrics = operational.get("metrics") or {}
    graph_export = decisions.get("graph_export") or {}
    graph_preview = decisions.get("graph_stix_preview") or {}
    actions = decisions.get("actions") or {}
    return {
        "run_count": operational.get("run_count", 0),
        "source_count": len(operational.get("sources") or {}),
        "decision_record_count": decisions.get("record_count", 0),
        "reviewed_count": int(totals.get("reviewed", 0) or 0),
        "accepted_count": int(metrics.get("accepted", 0) or 0),
        "filtered_count": int(metrics.get("filtered", 0) or 0),
        "error_count": int(metrics.get("errors", 0) or 0),
        "quarantine_decision_count": int(actions.get("quarantine", 0) or 0),
        "pending_review_count": analyst_review.get("pending_count", 0),
        "exportable_review_count": analyst_review.get("exportable_count", 0),
        "acceptance_rate_pct": metrics.get("acceptance_rate_pct", 0.0),
        "filter_rate_pct": metrics.get("filter_rate_pct", 0.0),
        "error_rate_pct": metrics.get("error_rate_pct", 0.0),
        "graph_candidate_count": graph_export.get("candidate_count", 0),
        "graph_accepted_count": graph_export.get("accepted_count", 0),
        "graph_held_count": graph_export.get("held_count", 0),
        "graph_lookup_match_count": graph_export.get("lookup_match_count", 0),
        "graph_would_create_object_count": graph_export.get(
            "would_create_object_count",
            0,
        ),
        "graph_would_create_relationship_count": graph_export.get(
            "would_create_relationship_count",
            0,
        ),
        "graph_stix_bundle_count": graph_preview.get("bundle_count", 0),
        "graph_stix_object_count": graph_preview.get("object_count", 0),
        "graph_stix_relationship_count": graph_preview.get("relationship_count", 0),
    }


def build_recommendations(summary):
    recommendations = []
    if summary.get("decision_record_count", 0) == 0 and summary.get("run_count", 0) == 0:
        recommendations.append(
            recommendation(
                "collect-evidence",
                "Run the gateway in dry-run mode and collect summary and decision audit evidence.",
            )
        )
    if summary.get("error_count", 0) > 0:
        recommendations.append(
            recommendation(
                "review-source-errors",
                "Investigate source errors before enabling continuous operation.",
            )
        )
    if summary.get("pending_review_count", 0) > 0:
        recommendations.append(
            recommendation(
                "review-quarantine",
                "Review pending quarantine records before promoting broader ingestion.",
            )
        )
    if summary.get("graph_would_create_object_count", 0) > 0:
        recommendations.append(
            recommendation(
                "validate-graph-promotion",
                "Validate graph dry-run objects and relationships in OpenCTI before export mode.",
            )
        )
    if summary.get("graph_lookup_match_count", 0) > 0:
        recommendations.append(
            recommendation(
                "preserve-graph-hygiene",
                "Keep OpenCTI graph lookup enabled for canonical object matching.",
            )
        )
    return recommendations


def recommendation(code, message):
    return {
        "code": code,
        "message": message,
    }


def build_curation_report_from_files(
    summary_file="",
    decision_paths=None,
    quarantine_file="",
    release_audit_file="",
    limit=0,
):
    summary_records = safe_read_gateway_summary_file(summary_file, limit=limit)
    quarantine_records = read_quarantine_records(quarantine_file) if quarantine_file else []
    operational = build_operational_report(
        summary_records,
        quarantine_records=quarantine_records,
    )
    decision_records = read_decision_records(decision_paths or (), limit=limit or None)
    decisions = build_decision_audit_report(decision_records)
    review_summary = build_review_summary(quarantine_file, release_audit_file)
    return build_curation_report(operational, decisions, review_summary)


def safe_read_gateway_summary_file(summary_file, limit=0):
    if not summary_file or not os.path.exists(summary_file):
        return []
    return read_gateway_summary_file(summary_file, limit=limit or None)


def build_review_summary(quarantine_file="", release_audit_file=""):
    if not quarantine_file or not os.path.exists(quarantine_file):
        return ReviewSummary(
            record_count=0,
            status_counts={},
            source_counts={},
            pending_count=0,
            exportable_count=0,
        )
    return AnalystReviewService.from_paths(
        quarantine_file,
        release_audit_file=release_audit_file,
    ).summary()


def format_text_report(report):
    data = report.to_dict()
    summary = data["executive_summary"]
    lines = [
        "NarrowCTI curation report",
        f"generated_at={data['generated_at']}",
        "executive_summary:",
        "- "
        f"runs={summary['run_count']} "
        f"sources={summary['source_count']} "
        f"decision_records={summary['decision_record_count']} "
        f"reviewed={summary['reviewed_count']} "
        f"accepted={summary['accepted_count']} "
        f"filtered={summary['filtered_count']} "
        f"errors={summary['error_count']}",
        "- "
        f"acceptance_rate_pct={summary['acceptance_rate_pct']} "
        f"filter_rate_pct={summary['filter_rate_pct']} "
        f"error_rate_pct={summary['error_rate_pct']}",
        "analyst_review:",
        "- "
        f"pending={summary['pending_review_count']} "
        f"exportable={summary['exportable_review_count']} "
        f"quarantine_decisions={summary['quarantine_decision_count']}",
        "graph_readiness:",
        "- "
        f"candidates={summary['graph_candidate_count']} "
        f"accepted={summary['graph_accepted_count']} "
        f"held={summary['graph_held_count']} "
        f"lookup_matches={summary['graph_lookup_match_count']} "
        f"would_create_objects={summary['graph_would_create_object_count']} "
        f"would_create_relationships="
        f"{summary['graph_would_create_relationship_count']}",
        "- "
        f"stix_bundles={summary['graph_stix_bundle_count']} "
        f"stix_objects={summary['graph_stix_object_count']} "
        f"stix_relationships={summary['graph_stix_relationship_count']}",
    ]
    if data["recommendations"]:
        lines.append("recommendations:")
        for item in data["recommendations"]:
            lines.append(f"- {item['code']}: {item['message']}")
    return "\n".join(lines)


def format_html_report(report):
    data = report.to_dict()
    summary = data["executive_summary"]
    recommendations = "\n".join(
        "<li><strong>{}</strong>: {}</li>".format(
            escape(item.get("code")),
            escape(item.get("message")),
        )
        for item in data.get("recommendations") or []
    )
    if not recommendations:
        recommendations = "<li>none</li>"

    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NarrowCTI curation report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #202124; }}
    h1, h2 {{ margin: 0 0 12px; }}
    section {{ margin-top: 24px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
    th, td {{ border: 1px solid #d8dee4; padding: 6px 8px; text-align: left; }}
    th {{ background: #f6f8fa; }}
    code {{ background: #f6f8fa; padding: 1px 4px; }}
  </style>
</head>
<body>
  <h1>NarrowCTI curation report</h1>
  <section>
    <h2>Snapshot</h2>
    <p><strong>generated_at:</strong> <code>{generated_at}</code></p>
  </section>
  <section>
    <h2>Executive Summary</h2>
    <table>
      <tr><th>runs</th><th>sources</th><th>decision records</th><th>reviewed</th><th>accepted</th><th>filtered</th><th>errors</th></tr>
      <tr><td>{runs}</td><td>{sources}</td><td>{decision_records}</td><td>{reviewed}</td><td>{accepted}</td><td>{filtered}</td><td>{errors}</td></tr>
    </table>
    <table>
      <tr><th>acceptance rate</th><th>filter rate</th><th>error rate</th><th>pending review</th><th>exportable review</th><th>quarantine decisions</th></tr>
      <tr><td>{acceptance_rate_pct}</td><td>{filter_rate_pct}</td><td>{error_rate_pct}</td><td>{pending_review}</td><td>{exportable_review}</td><td>{quarantine_decisions}</td></tr>
    </table>
  </section>
  <section>
    <h2>Graph Readiness</h2>
    <table>
      <tr><th>candidates</th><th>accepted</th><th>held</th><th>lookup matches</th><th>would-create objects</th><th>would-create relationships</th></tr>
      <tr><td>{graph_candidates}</td><td>{graph_accepted}</td><td>{graph_held}</td><td>{lookup_matches}</td><td>{would_create_objects}</td><td>{would_create_relationships}</td></tr>
    </table>
    <table>
      <tr><th>STIX bundles</th><th>STIX objects</th><th>STIX relationships</th></tr>
      <tr><td>{stix_bundles}</td><td>{stix_objects}</td><td>{stix_relationships}</td></tr>
    </table>
  </section>
  <section>
    <h2>Recommendations</h2>
    <ul>
      {recommendations}
    </ul>
  </section>
</body>
</html>""".format(
        generated_at=escape(data["generated_at"]),
        runs=escape(summary["run_count"]),
        sources=escape(summary["source_count"]),
        decision_records=escape(summary["decision_record_count"]),
        reviewed=escape(summary["reviewed_count"]),
        accepted=escape(summary["accepted_count"]),
        filtered=escape(summary["filtered_count"]),
        errors=escape(summary["error_count"]),
        acceptance_rate_pct=escape(summary["acceptance_rate_pct"]),
        filter_rate_pct=escape(summary["filter_rate_pct"]),
        error_rate_pct=escape(summary["error_rate_pct"]),
        pending_review=escape(summary["pending_review_count"]),
        exportable_review=escape(summary["exportable_review_count"]),
        quarantine_decisions=escape(summary["quarantine_decision_count"]),
        graph_candidates=escape(summary["graph_candidate_count"]),
        graph_accepted=escape(summary["graph_accepted_count"]),
        graph_held=escape(summary["graph_held_count"]),
        lookup_matches=escape(summary["graph_lookup_match_count"]),
        would_create_objects=escape(summary["graph_would_create_object_count"]),
        would_create_relationships=escape(
            summary["graph_would_create_relationship_count"]
        ),
        stix_bundles=escape(summary["graph_stix_bundle_count"]),
        stix_objects=escape(summary["graph_stix_object_count"]),
        stix_relationships=escape(summary["graph_stix_relationship_count"]),
        recommendations=recommendations,
    )


def write_html_report(report, html_file):
    html_file = str(html_file or "").strip()
    if not html_file:
        raise ValueError("html_file is required")
    directory = os.path.dirname(html_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(html_file, "w", encoding="utf-8") as handle:
        handle.write(format_html_report(report) + "\n")
    return html_file


def escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def main():
    parser = argparse.ArgumentParser(
        description="Build an analyst-facing NarrowCTI curation report."
    )
    parser.add_argument(
        "--summary-file",
        default="",
        help="Gateway run summary JSONL. Defaults to NARROWCTI_RUN_SUMMARY_FILE.",
    )
    parser.add_argument(
        "--decision-path",
        action="append",
        default=[],
        help="Decision audit JSONL file or directory. Can be passed more than once.",
    )
    parser.add_argument(
        "--quarantine-file",
        default="",
        help="Quarantine repository JSONL. Defaults to NARROWCTI_QUARANTINE_REPOSITORY.",
    )
    parser.add_argument(
        "--release-audit-file",
        default="",
        help="Release audit JSONL. Defaults to NARROWCTI_RELEASE_AUDIT_FILE.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Read only the most recent N records where supported.",
    )
    parser.add_argument(
        "--html-file",
        default="",
        help="Optional HTML report output file.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    settings = load_settings()
    report = build_curation_report_from_files(
        summary_file=args.summary_file or settings.run_summary_file,
        decision_paths=args.decision_path or [settings.decision_audit_dir],
        quarantine_file=args.quarantine_file or settings.quarantine_repository_file,
        release_audit_file=args.release_audit_file or settings.release_audit_file,
        limit=args.limit,
    )
    if args.html_file:
        write_html_report(report, args.html_file)
    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print(format_text_report(report))


if __name__ == "__main__":
    main()
