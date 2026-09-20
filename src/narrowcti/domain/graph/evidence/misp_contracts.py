"""Shared MISP-specific contracts used by graph evidence families."""

import re

from .common import ATTACK_ID_PATTERN, CVE_ID_PATTERN, clean_string


MISP_GALAXY_TAG_PATTERN = re.compile(
    r'^misp-galaxy:([^=]+)=(?:"([^"]+)"|(.+))$',
    re.IGNORECASE,
)

MISP_INFRA_CONTEXT_MAX_INFRASTRUCTURES = 50
MISP_INFRA_CONTEXT_MAX_PAIRINGS = 100
MISP_INFRA_CONTEXT_MAX_RECORDS = 200
MISP_INFRA_CAPABILITY_ENTITY_TYPES = {
    "malware",
    "tool",
    "channel",
}
MISP_INFRA_VICTIMOLOGY_ENTITY_TYPES = {
    "target_administrative_area",
    "target_city",
    "target_country",
    "target_individual",
    "target_organization",
    "target_position",
    "target_region",
    "target_sector",
    "target_system",
}

MISP_CAMPAIGN_CONTEXT_MAX_CAMPAIGNS = 50
MISP_CAMPAIGN_CONTEXT_MAX_PAIRINGS = 100
MISP_CAMPAIGN_CONTEXT_MAX_RECORDS = 200
MISP_CAMPAIGN_ADVERSARY_ENTITY_TYPES = {
    "intrusion_set",
    "threat_actor",
    "threat_actor_individual",
}
MISP_CAMPAIGN_CAPABILITY_ENTITY_TYPES = {
    "attack_pattern",
    "channel",
    "malware",
    "tool",
}

TARGET_ORGANIZATION_VALUE_DENYLIST = {
    "alienvault",
    "alienvault otx",
    "misp",
    "narrowcti",
    "narrowcti gateway",
    "opencti",
    "otx",
    "the mitre corporation",
}

TARGET_INDIVIDUAL_VALUE_DENYLIST = TARGET_ORGANIZATION_VALUE_DENYLIST | {
    "admin",
    "administrator",
    "analyst",
    "author",
    "root",
    "user",
}


def is_target_organization_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not value:
        return False
    if lowered in TARGET_ORGANIZATION_VALUE_DENYLIST:
        return False
    if lowered.startswith(("http://", "https://", "ftp://", "tlp:")):
        return False
    if "@" in value and not any(char.isspace() for char in value):
        return False
    if ATTACK_ID_PATTERN.fullmatch(value) or CVE_ID_PATTERN.fullmatch(value):
        return False
    if is_dotted_identifier_value(value):
        return False
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", lowered):
        return False
    return True


def is_dotted_identifier_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not value or any(char.isspace() for char in value):
        return False
    if lowered.count(".") < 2:
        return False
    labels = lowered.split(".")
    return all(re.fullmatch(r"[a-z0-9_-]+", label or "") for label in labels)


def is_target_individual_value(value):
    value = clean_string(value)
    lowered = value.casefold()
    if not is_target_organization_value(value):
        return False
    if lowered in TARGET_INDIVIDUAL_VALUE_DENYLIST:
        return False
    if re.fullmatch(r"\d+", value):
        return False
    return True


def is_safe_misp_meta_graph_value(entity_type, value):
    if entity_type == "target_individual":
        return is_target_individual_value(value)
    if entity_type in {
        "channel",
        "event",
        "narrative",
        "security_platform",
        "target_organization",
        "target_system",
    }:
        value = clean_string(value)
        if not is_target_organization_value(value):
            return False
        if re.fullmatch(r"\d+", value):
            return False
        return True
    return bool(clean_string(value))
