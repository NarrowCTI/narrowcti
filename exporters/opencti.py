import json

from core.graph_export_plan import normalize_graph_export_mode
from core.opencti_graph_lookup import filter_eq, first_node
from exporters.stix_builder import (
    build_curated_report_bundle,
    build_report_bundle,
    graph_accepted_candidates,
    graph_description_hydration_requests,
)


DESCRIPTION_READ_QUERY = """
query ReadObjectDescription($id: String!) {
  stixDomainObject(id: $id) {
    id
    standard_id
    entity_type
    createdBy { ... on Identity { name } }
    ... on Sector { name description }
    ... on ThreatActorGroup { name description }
    ... on ThreatActorIndividual { name description }
    ... on IntrusionSet { name description }
    ... on Campaign { name description }
    ... on Malware { name description }
    ... on Tool { name description }
    ... on Vulnerability { name description }
    ... on AttackPattern { name description }
    ... on CourseOfAction { name description }
    ... on Indicator { name description }
    ... on Infrastructure { name description }
    ... on Organization { name description }
    ... on Individual { name description }
    ... on System { name description }
    ... on SecurityPlatform { name description }
    ... on Region { name description }
    ... on Country { name description }
    ... on AdministrativeArea { name description }
    ... on City { name description }
    ... on Position { name description }
  }
}
"""


DESCRIPTION_PATCH_MUTATION = """
mutation HydrateObjectDescription($id: ID!, $input: [EditInput]!) {
  stixDomainObjectEdit(id: $id) {
    fieldPatch(input: $input) {
      id
      standard_id
      entity_type
      ... on Sector { name description }
      ... on ThreatActorGroup { name description }
      ... on ThreatActorIndividual { name description }
      ... on IntrusionSet { name description }
      ... on Campaign { name description }
      ... on Malware { name description }
      ... on Tool { name description }
      ... on Vulnerability { name description }
      ... on AttackPattern { name description }
      ... on CourseOfAction { name description }
      ... on Indicator { name description }
      ... on Infrastructure { name description }
      ... on Organization { name description }
      ... on Individual { name description }
      ... on System { name description }
      ... on SecurityPlatform { name description }
      ... on Region { name description }
      ... on Country { name description }
      ... on AdministrativeArea { name description }
      ... on City { name description }
      ... on Position { name description }
    }
  }
}
"""

SECURITY_PLATFORM_LOOKUP_QUERY = """
query NarrowCTISecurityPlatformExportLookup($filters: FilterGroup) {
  securityPlatforms(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        security_platform_type
      }
    }
  }
}
"""

SECURITY_PLATFORM_ADD_MUTATION = """
mutation NarrowCTISecurityPlatformAdd($input: SecurityPlatformAddInput!) {
  securityPlatformAdd(input: $input) {
    id
    standard_id
    entity_type
    name
    security_platform_type
  }
}
"""

THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY = """
query NarrowCTIThreatActorIndividualExportLookup($filters: FilterGroup) {
  threatActorsIndividuals(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
        aliases
        threat_actor_types
      }
    }
  }
}
"""

THREAT_ACTOR_INDIVIDUAL_ADD_MUTATION = """
mutation NarrowCTIThreatActorIndividualAdd(
  $input: ThreatActorIndividualAddInput!
) {
  threatActorIndividualAdd(input: $input) {
    id
    standard_id
    entity_type
    name
    aliases
    threat_actor_types
  }
}
"""

REPORT_LOOKUP_QUERY = """
query NarrowCTIReportExportLookup($filters: FilterGroup) {
  reports(first: 1, filters: $filters) {
    edges {
      node {
        id
        standard_id
        entity_type
        name
      }
    }
  }
}
"""

REPORT_OBJECT_REF_ADD_MUTATION = """
mutation NarrowCTIReportObjectRefAdd(
  $id: ID!
  $input: StixRefRelationshipAddInput!
) {
  reportEdit(id: $id) {
    relationAdd(input: $input) {
      id
      entity_type
      relationship_type
    }
  }
}
"""


def send_bundle(
    api_client,
    name,
    description,
    score,
    indicators=None,
    identity_name="NarrowCTI Gateway",
    graph_candidate_policy=None,
    graph_export_mode="audit",
):
    export_enabled = normalize_graph_export_mode(graph_export_mode) == "export"
    if export_enabled:
        bundle, indicator_count, _ = build_curated_report_bundle(
            name,
            description,
            score,
            indicators,
            graph_candidate_policy=graph_candidate_policy,
            identity_name=identity_name,
        )
    else:
        bundle, indicator_count = build_report_bundle(
            name,
            description,
            score,
            indicators,
            identity_name=identity_name,
        )
    bundle_json = bundle.serialize()
    api_client.stix2.import_bundle_from_json(bundle_json, update=True)
    if export_enabled:
        native_security_platforms = export_native_security_platforms(
            api_client,
            graph_candidate_policy,
        )
        native_threat_actor_individuals = export_native_threat_actor_individuals(
            api_client,
            graph_candidate_policy,
        )
        link_native_security_platforms_to_reports(
            api_client,
            bundle_json,
            [*native_security_platforms, *native_threat_actor_individuals],
        )
        hydrate_existing_graph_descriptions(
            api_client,
            graph_description_hydration_requests(
                graph_candidate_policy,
                identity_name=identity_name,
            ),
        )
    return indicator_count


def export_native_security_platforms(api_client, graph_candidate_policy):
    exported = []
    for candidate in native_security_platform_candidates(graph_candidate_policy):
        existing_id = candidate_existing_id(candidate)
        if existing_id:
            exported.append(
                {
                    "id": existing_id,
                    "standard_id": clean_string(
                        candidate_attributes(candidate).get("opencti_existing_ref")
                    ),
                    "entity_type": "SecurityPlatform",
                    "name": graph_candidate_name(candidate),
                }
            )
            continue
        name = graph_candidate_name(candidate)
        if not name:
            continue
        existing = find_security_platform(api_client, name)
        if existing:
            exported.append(existing)
            continue
        attributes = candidate_attributes(candidate)
        input_payload = {
            "name": name,
            "update": True,
        }
        description = clean_string(attributes.get("description"))
        platform_type = clean_string(
            attributes.get("security_platform_type")
            or attributes.get("platform_type")
            or attributes.get("type")
        )
        confidence = graph_candidate_confidence(candidate)
        if description:
            input_payload["description"] = description
        if platform_type:
            input_payload["security_platform_type"] = platform_type
        if confidence is not None:
            input_payload["confidence"] = confidence
        try:
            result = api_client.query(
                SECURITY_PLATFORM_ADD_MUTATION,
                {"input": input_payload},
            )
        except Exception:
            continue
        node = ((result.get("data") or {}).get("securityPlatformAdd")) or {}
        if node:
            exported.append(node)
    return exported


def export_native_threat_actor_individuals(api_client, graph_candidate_policy):
    exported = []
    for candidate in native_threat_actor_individual_candidates(graph_candidate_policy):
        existing_id = candidate_existing_id(candidate)
        if existing_id:
            exported.append(
                {
                    "id": existing_id,
                    "standard_id": clean_string(
                        candidate_attributes(candidate).get("opencti_existing_ref")
                    ),
                    "entity_type": "Threat-Actor-Individual",
                    "name": graph_candidate_name(candidate),
                }
            )
            continue
        name = graph_candidate_name(candidate)
        if not name:
            continue
        existing = find_threat_actor_individual(api_client, name)
        if existing:
            exported.append(existing)
            continue
        attributes = candidate_attributes(candidate)
        input_payload = {
            "name": name,
            "update": True,
        }
        description = clean_string(attributes.get("description"))
        confidence = graph_candidate_confidence(candidate)
        aliases = clean_list_values(
            attributes.get("aliases"),
            attributes.get("alias"),
            attributes.get("x_opencti_aliases"),
        )
        threat_actor_types = clean_list_values(
            attributes.get("threat_actor_types"),
            attributes.get("threat_actor_type"),
            attributes.get("type"),
        )
        if description:
            input_payload["description"] = description
        if confidence is not None:
            input_payload["confidence"] = confidence
        if aliases:
            input_payload["aliases"] = aliases
        if threat_actor_types:
            input_payload["threat_actor_types"] = threat_actor_types
        for field in (
            "first_seen",
            "last_seen",
            "primary_motivation",
            "resource_level",
            "sophistication",
        ):
            value = clean_string(attributes.get(field))
            if value:
                input_payload[field] = value
        for field in ("goals", "personal_motivations", "secondary_motivations"):
            values = clean_list_values(attributes.get(field))
            if values:
                input_payload[field] = values
        try:
            result = api_client.query(
                THREAT_ACTOR_INDIVIDUAL_ADD_MUTATION,
                {"input": input_payload},
            )
        except Exception:
            continue
        node = ((result.get("data") or {}).get("threatActorIndividualAdd")) or {}
        if node:
            exported.append(node)
    return exported


def link_native_security_platforms_to_reports(
    api_client,
    bundle_json,
    security_platforms,
):
    if not security_platforms:
        return []
    reports = report_nodes_for_bundle(api_client, bundle_json)
    linked = []
    for report in reports:
        report_id = clean_string(report.get("id"))
        if not report_id:
            continue
        for platform in security_platforms:
            platform_id = clean_string(platform.get("id"))
            if not platform_id:
                continue
            try:
                result = api_client.query(
                    REPORT_OBJECT_REF_ADD_MUTATION,
                    {
                        "id": report_id,
                        "input": {
                            "toId": platform_id,
                            "relationship_type": "object",
                            "update": True,
                        },
                    },
                )
            except Exception:
                continue
            node = (((result.get("data") or {}).get("reportEdit") or {}).get(
                "relationAdd"
            )) or {}
            if node:
                linked.append(node)
    return linked


def report_nodes_for_bundle(api_client, bundle_json):
    reports = []
    for report_ref in report_refs_from_bundle_json(bundle_json):
        standard_id = clean_string(report_ref.get("standard_id"))
        name = clean_string(report_ref.get("name"))
        node = {}
        if standard_id:
            node = find_report(api_client, "standard_id", standard_id)
        if not node and name:
            node = find_report(api_client, "name", name)
        if node:
            reports.append(node)
    return reports


def report_refs_from_bundle_json(bundle_json):
    try:
        data = json.loads(bundle_json)
    except (TypeError, ValueError):
        return []
    reports = []
    for item in data.get("objects") or []:
        if item.get("type") != "report":
            continue
        reports.append(
            {
                "standard_id": clean_string(item.get("id")),
                "name": clean_string(item.get("name")),
            }
        )
    return reports


def find_report(api_client, key, value):
    try:
        result = api_client.query(
            REPORT_LOOKUP_QUERY,
            {"filters": filter_eq(key, value)},
        )
    except Exception:
        return {}
    return first_node(result, "reports")


def native_security_platform_candidates(graph_candidate_policy):
    candidates = []
    for candidate in graph_accepted_candidates(graph_candidate_policy):
        if clean_string(candidate.get("stix_object_type")).lower() != "security-platform":
            continue
        if clean_string(candidate.get("entity_type")).lower() != "security_platform":
            continue
        candidates.append(candidate)
    return candidates


def native_threat_actor_individual_candidates(graph_candidate_policy):
    candidates = []
    for candidate in graph_accepted_candidates(graph_candidate_policy):
        if clean_string(candidate.get("stix_object_type")).lower() != "threat-actor":
            continue
        if clean_string(candidate.get("entity_type")).lower() != "threat_actor_individual":
            continue
        candidates.append(candidate)
    return candidates


def find_security_platform(api_client, name):
    try:
        result = api_client.query(
            SECURITY_PLATFORM_LOOKUP_QUERY,
            {"filters": filter_eq("name", name)},
        )
    except Exception:
        return {}
    return first_node(result, "securityPlatforms")


def find_threat_actor_individual(api_client, name):
    try:
        result = api_client.query(
            THREAT_ACTOR_INDIVIDUAL_LOOKUP_QUERY,
            {"filters": filter_eq("name", name)},
        )
    except Exception:
        return {}
    return first_node(result, "threatActorsIndividuals")


def candidate_existing_id(candidate):
    return clean_string(candidate_attributes(candidate).get("opencti_existing_id"))


def hydrate_existing_graph_descriptions(api_client, requests):
    for request in requests or []:
        opencti_id = request.get("opencti_id")
        description = request.get("description")
        if not opencti_id or not description:
            continue
        try:
            current = api_client.query(
                DESCRIPTION_READ_QUERY,
                {"id": opencti_id},
            )
        except Exception:
            continue
        current_object = (current.get("data") or {}).get("stixDomainObject") or {}
        if current_object.get("description"):
            continue
        if not request.get("narrow_owned") and not has_narrowcti_author(current_object):
            continue
        try:
            api_client.query(
                DESCRIPTION_PATCH_MUTATION,
                {
                    "id": opencti_id,
                    "input": [{"key": "description", "value": [description]}],
                },
            )
        except Exception:
            continue


def has_narrowcti_author(opencti_object):
    author = opencti_object.get("createdBy") or {}
    return "narrowcti" in str(author.get("name") or "").lower()


def graph_candidate_name(candidate):
    return clean_string(candidate.get("name") or candidate.get("value"))


def graph_candidate_confidence(candidate):
    try:
        confidence = int(candidate.get("confidence"))
    except (TypeError, ValueError):
        return None
    return max(0, min(100, confidence))


def candidate_attributes(candidate):
    attributes = candidate.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def clean_string(value):
    return " ".join(str(value or "").strip().split())


def clean_list_values(*values):
    cleaned = []
    seen = set()
    for value in values:
        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = [value]
        for item in items:
            text = clean_string(item)
            key = text.casefold()
            if not text or key in seen:
                continue
            seen.add(key)
            cleaned.append(text)
    return cleaned
