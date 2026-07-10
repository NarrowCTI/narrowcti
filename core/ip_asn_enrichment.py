import csv
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IPASNRecord:
    network: object
    asn: int
    as_name: str = ""
    rir: str = ""
    source: str = ""

    @property
    def value(self):
        name = clean_string(self.as_name)
        if name:
            return f"AS{self.asn} {name}"
        return f"AS{self.asn}"


class OfflineIPASNEnricher:
    def __init__(self, records=None):
        self.records = tuple(
            sorted(
                (record for record in records or [] if isinstance(record, IPASNRecord)),
                key=lambda item: item.network.prefixlen,
                reverse=True,
            )
        )

    def lookup(self, value):
        target = parse_ip_or_network(value)
        if target is None:
            return None
        for record in self.records:
            if network_contains(record.network, target):
                return record
        return None


def load_ip_asn_enricher(path):
    path = clean_string(path)
    if not path:
        return None
    records = load_ip_asn_records(path)
    if not records:
        return None
    return OfflineIPASNEnricher(records)


def load_ip_asn_records(path):
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return []
    if file_path.suffix.lower() == ".csv":
        return load_csv_records(file_path)
    return load_json_records(file_path)


def load_csv_records(path):
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return records_from_rows(csv.DictReader(handle))


def load_json_records(path):
    text = path.read_text(encoding="utf-8-sig")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records_from_rows(rows)
    if isinstance(payload, dict):
        payload = payload.get("records") or payload.get("prefixes") or [payload]
    return records_from_rows(payload if isinstance(payload, list) else [])


def records_from_rows(rows):
    records = []
    for row in rows or []:
        record = record_from_mapping(row if isinstance(row, dict) else {})
        if record:
            records.append(record)
    return records


def record_from_mapping(row):
    network = parse_network(
        first_clean_value(
            row.get("cidr"),
            row.get("prefix"),
            row.get("netblock"),
            row.get("network"),
        )
    )
    asn = parse_asn(
        first_clean_value(
            row.get("asn"),
            row.get("as_number"),
            row.get("number"),
            row.get("autonomous_system"),
        )
    )
    if network is None or asn is None:
        return None
    return IPASNRecord(
        network=network,
        asn=asn,
        as_name=first_clean_value(row.get("as_name"), row.get("asn_name"), row.get("name")),
        rir=clean_string(row.get("rir")),
        source=clean_string(row.get("source")),
    )


def parse_network(value):
    text = clean_string(value)
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def parse_ip_or_network(value):
    text = clean_string(value)
    if not text:
        return None
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def network_contains(network, target):
    if getattr(network, "version", None) != getattr(target, "version", None):
        return False
    if hasattr(target, "network_address"):
        return target.subnet_of(network)
    return target in network


def parse_asn(value):
    text = clean_string(value).upper()
    if text.startswith("AS"):
        text = text[2:].strip()
    if not text.isdigit():
        return None
    number = int(text)
    if number < 0 or number > 4294967295:
        return None
    return number


def first_clean_value(*values):
    for value in values:
        cleaned = clean_string(value)
        if cleaned:
            return cleaned
    return ""


def clean_string(value):
    return " ".join(str(value or "").strip().split())
