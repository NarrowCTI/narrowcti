# ruff: noqa: F401,F403,F405
from collections.abc import Mapping
from .common import *  # noqa: F403,F401

def misp_detection_rule_evidence(detection_rules, source_key=""):
    records = []
    for detection_rule in detection_rules or []:
        detection_rule = compact_mapping(detection_rule)
        if not detection_rule:
            continue
        base_attributes = {
            "rule_type": detection_rule.get("rule_type"),
            "pattern_type": detection_rule.get("pattern_type"),
            "pattern": detection_rule.get("pattern"),
            "opencti_indicator_compatible": detection_rule.get(
                "opencti_indicator_compatible"
            ),
            "opencti_indicator_compatibility_reason": detection_rule.get(
                "opencti_indicator_compatibility_reason"
            ),
            "attribute_category": detection_rule.get("attribute_category"),
            "attribute_uuid": detection_rule.get("attribute_uuid"),
            "object_name": detection_rule.get("object_name"),
            "object_uuid": detection_rule.get("object_uuid"),
            "first_seen": detection_rule.get("first_seen"),
            "last_seen": detection_rule.get("last_seen"),
            "tags": detection_rule.get("tags"),
            "attack_pattern_ids": detection_rule.get("attack_pattern_ids"),
            "attack_id_source": detection_rule.get("attack_id_source"),
        }
        rule_type = clean_string(detection_rule.get("rule_type")).casefold()
        compatible = detection_rule.get("opencti_indicator_compatible")
        incompatible = compatible is False or clean_string(compatible).casefold() in {
            "false",
            "0",
            "no",
        }
        attack_pattern_ids = (
            clean_values(detection_rule.get("attack_pattern_ids"))
            if rule_type in {"sigma", "yara"} and not incompatible
            else []
        )
        records_to_build = attack_pattern_ids or [""]
        for attack_id in records_to_build:
            attributes = dict(base_attributes)
            confidence = 70
            relationship_type = ""
            if attack_id:
                relation_source_field = (
                    detection_rule.get("source_field") or "Attribute"
                )
                attack_id_source = clean_string(
                    detection_rule.get("attack_id_source")
                )
                if attack_id_source:
                    relation_source_field = (
                        f"{relation_source_field}.{attack_id_source}"
                    )
                attributes.update(
                    {
                        "relationship_source_stix_object_type": "attack-pattern",
                        "relationship_source_value": attack_id,
                        "relationship_source_field": relation_source_field,
                        "relationship_inference": "explicit-detection-rule-attack-reference",
                    }
                )
                confidence = 85
                relationship_type = "detects"
            record = evidence_record(
                entity_type="detection_rule",
                value=detection_rule.get("value"),
                source_key=source_key,
                source_name="misp",
                source_field=detection_rule.get("source_field") or "Attribute",
                confidence=confidence,
                relationship_type=relationship_type,
                attributes=attributes,
            )
            if record:
                records.append(record)
    return records
