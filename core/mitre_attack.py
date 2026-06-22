import json
import os
import re
import urllib.request
from dataclasses import asdict, dataclass

from core.decision_audit import utc_now


DEFAULT_MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


@dataclass(frozen=True)
class MITRETechnique:
    attack_id: str
    name: str
    tactics: tuple[str, ...] = ()
    stix_id: str = ""
    source_name: str = "mitre-attack"
    url: str = ""
    revoked: bool = False
    deprecated: bool = False

    def to_dict(self):
        data = asdict(self)
        data["tactics"] = list(self.tactics)
        return data


def normalize_attack_id(value):
    candidate = str(value or "").strip().upper()
    if ATTACK_ID_PATTERN.match(candidate):
        return candidate
    return ""


def attack_id_from_external_references(external_references):
    for reference in external_references or []:
        if not isinstance(reference, dict):
            continue
        if reference.get("source_name") != "mitre-attack":
            continue
        attack_id = normalize_attack_id(reference.get("external_id"))
        if attack_id:
            return attack_id
    return ""


def reference_url(external_references):
    for reference in external_references or []:
        if not isinstance(reference, dict):
            continue
        if reference.get("source_name") == "mitre-attack":
            return str(reference.get("url") or "").strip()
    return ""


def tactics_from_kill_chain_phases(kill_chain_phases):
    tactics = []
    for phase in kill_chain_phases or []:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        tactic = normalize_tactic(phase.get("phase_name"))
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    return tactics


def normalize_tactic(value):
    normalized = str(value or "").strip().lower().replace("_", "-")
    normalized = "-".join(part for part in re.split(r"[\s-]+", normalized) if part)
    return normalized


def build_attack_cache(stix_bundle):
    techniques = {}
    for item in (stix_bundle or {}).get("objects") or []:
        if not isinstance(item, dict) or item.get("type") != "attack-pattern":
            continue
        attack_id = attack_id_from_external_references(
            item.get("external_references")
        )
        if not attack_id:
            continue
        technique = MITRETechnique(
            attack_id=attack_id,
            name=str(item.get("name") or "").strip(),
            tactics=tuple(tactics_from_kill_chain_phases(item.get("kill_chain_phases"))),
            stix_id=str(item.get("id") or "").strip(),
            url=reference_url(item.get("external_references")),
            revoked=bool(item.get("revoked", False)),
            deprecated=bool(item.get("x_mitre_deprecated", False)),
        )
        techniques[attack_id] = technique.to_dict()

    return {
        "source": "mitre-attack",
        "generated_at": utc_now(),
        "technique_count": len(techniques),
        "techniques": dict(sorted(techniques.items())),
    }


def normalize_attack_cache(data):
    if not isinstance(data, dict):
        return empty_attack_cache()
    if "objects" in data:
        return build_attack_cache(data)
    techniques = {}
    for attack_id, technique in (data.get("techniques") or {}).items():
        normalized_id = normalize_attack_id(
            technique.get("attack_id") if isinstance(technique, dict) else attack_id
        )
        if not normalized_id or not isinstance(technique, dict):
            continue
        techniques[normalized_id] = MITRETechnique(
            attack_id=normalized_id,
            name=str(technique.get("name") or "").strip(),
            tactics=tuple(
                tactic
                for tactic in (
                    normalize_tactic(value) for value in technique.get("tactics") or []
                )
                if tactic
            ),
            stix_id=str(technique.get("stix_id") or "").strip(),
            source_name=str(technique.get("source_name") or "mitre-attack").strip(),
            url=str(technique.get("url") or "").strip(),
            revoked=bool(technique.get("revoked", False)),
            deprecated=bool(technique.get("deprecated", False)),
        ).to_dict()
    return {
        "source": str(data.get("source") or "mitre-attack"),
        "generated_at": str(data.get("generated_at") or ""),
        "technique_count": len(techniques),
        "techniques": dict(sorted(techniques.items())),
    }


def empty_attack_cache():
    return {
        "source": "mitre-attack",
        "generated_at": "",
        "technique_count": 0,
        "techniques": {},
    }


def load_attack_cache(cache_file):
    with open(cache_file, "r", encoding="utf-8") as handle:
        return normalize_attack_cache(json.load(handle))


def save_attack_cache(cache, cache_file):
    directory = os.path.dirname(cache_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as handle:
        json.dump(normalize_attack_cache(cache), handle, sort_keys=True, indent=2)


def refresh_attack_cache(
    cache_file,
    stix_url=DEFAULT_MITRE_STIX_URL,
    timeout=60,
    opener=urllib.request.urlopen,
):
    with opener(stix_url, timeout=timeout) as response:
        bundle = json.loads(response.read().decode("utf-8"))
    cache = build_attack_cache(bundle)
    save_attack_cache(cache, cache_file)
    return cache


class MITREAttackResolver:
    def __init__(self, cache=None, cache_file=""):
        if cache is None and cache_file:
            cache = load_attack_cache(cache_file)
        self.cache = normalize_attack_cache(cache or empty_attack_cache())
        self.techniques = self.cache.get("techniques") or {}

    def resolve_one(self, attack_id):
        normalized_id = normalize_attack_id(attack_id)
        if not normalized_id:
            return self.missing_result(str(attack_id or ""))
        technique = self.techniques.get(normalized_id)
        if not technique:
            return self.missing_result(normalized_id)
        return {
            "attack_id": normalized_id,
            "found": True,
            "name": technique.get("name", ""),
            "tactics": list(technique.get("tactics") or []),
            "stix_id": technique.get("stix_id", ""),
            "source_name": technique.get("source_name", "mitre-attack"),
            "url": technique.get("url", ""),
            "revoked": bool(technique.get("revoked", False)),
            "deprecated": bool(technique.get("deprecated", False)),
        }

    def resolve(self, attack_ids):
        return [self.resolve_one(attack_id) for attack_id in attack_ids or []]

    def missing_result(self, attack_id):
        return {
            "attack_id": attack_id,
            "found": False,
            "name": "",
            "tactics": [],
            "stix_id": "",
            "source_name": "mitre-attack",
            "url": "",
            "revoked": False,
            "deprecated": False,
        }
