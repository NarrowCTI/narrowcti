import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Mapping


def utc_now():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class DecisionRecord:
    action: str
    reason: str
    source_key: str
    external_id: str
    title: str
    query: str = ""
    score: int | None = None
    age_days: int | None = None
    indicator_count: int = 0
    recorded_at: str = field(default_factory=utc_now)
    metadata: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self):
        data = asdict(self)
        data["metadata"] = dict(self.metadata or {})
        return data


class DecisionAuditLog:
    def __init__(self, audit_file=""):
        self.audit_file = audit_file

    def record(self, decision):
        if not self.audit_file:
            return decision

        directory = os.path.dirname(self.audit_file)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision.to_dict(), sort_keys=True) + "\n")

        return decision
