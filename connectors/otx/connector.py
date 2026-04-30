import os
import json
import time
import requests
from datetime import datetime, timezone
from dateutil.parser import parse
from pycti import OpenCTIApiClient
from stix2 import Bundle, Report, Identity

def env_required(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required variable: {name}")
    return value

def env_int(name, default):
    return int(os.getenv(name, str(default)))

def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ["true", "1", "yes"]

def env_list(name):
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]

OPENCTI_URL = env_required("OPENCTI_URL")
OPENCTI_TOKEN = env_required("OPENCTI_TOKEN")
OTX_API_KEY = env_required("OTX_API_KEY")

OTX_QUERIES = env_list("OTX_QUERIES")

CONNECTOR_RUN_INTERVAL = env_int("CONNECTOR_RUN_INTERVAL", 3600)

MAX_DAYS_OLD = env_int("MAX_DAYS_OLD", 1095)
MAX_DAYS_HARD_FILTER = env_int("MAX_DAYS_HARD_FILTER", 365)

MAX_PULSES_PER_QUERY = env_int("MAX_PULSES_PER_QUERY", 5)
MAX_IOCS_PER_PULSE = env_int("MAX_IOCS_PER_PULSE", 2000)

MIN_SCORE_FOR_OLD_PULSE = env_int("MIN_SCORE_FOR_OLD_PULSE", 80)
MIN_SCORE_TO_INGEST = env_int("MIN_SCORE_TO_INGEST", 60)

ENABLE_QUARANTINE = env_bool("ENABLE_QUARANTINE", True)
QUARANTINE_SCORE_THRESHOLD = env_int("QUARANTINE_SCORE_THRESHOLD", 50)

STATE_FILE = os.getenv("STATE_FILE", "/app/state/state.json")

api = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

def log(msg):
    print(f"[INFO] {msg}", flush=True)

def safe_request(url, headers=None, params=None, retries=3):
    for attempt in range(retries):
        try:
            log(f"HTTP request attempt {attempt+1}: {url}")

            r = requests.get(
                url,
                headers={
                    **(headers or {}),
                    "Connection": "close",
                    "User-Agent": "curl/7.88.1"
                },
                params=params,
                timeout=(5, 30),
                verify=True
            )

            log(f"HTTP status: {r.status_code}")

            if r.status_code == 200:
                return r.json()

            if r.status_code == 403:
                log("Auth error or invalid API key")

        except requests.exceptions.ReadTimeout:
            log("Read timeout")

        except requests.exceptions.ConnectTimeout:
            log("Connect timeout")

        except Exception as e:
            log(f"HTTP error: {str(e)}")

        time.sleep((attempt + 1) * 3)

    log("Request failed completely")
    return None

def load_state():
    if not os.path.exists(STATE_FILE):
        return {"pulses": []}

    with open(STATE_FILE, "r") as f:
        try:
            data = json.load(f)
            if "pulses" not in data:
                data["pulses"] = []
            return data
        except:
            return {"pulses": []}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def age_days(date_str):
    try:
        dt = parse(date_str)
        return (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
    except:
        return None

def calculate_score(pulse, query):
    score = 40

    name = pulse.get("name", "").lower()
    tags = [t.lower() for t in pulse.get("tags", [])]
    iocs = pulse.get("indicators", [])
    created = pulse.get("created")

    age = age_days(created)
    ioc_count = len(iocs)

    if query.lower() in name:
        score += 15

    if any(query.lower() in t for t in tags):
        score += 10

    if 10 <= ioc_count <= 500:
        score += 20
    elif 500 < ioc_count <= 2000:
        score += 10
    elif ioc_count > 2000:
        score -= 10

    if age:
        if age < 30:
            score += 20
        elif age < 90:
            score += 10
        elif age > 365:
            score -= 10

    return max(0, min(score, 100))

def should_ingest(pulse, score):
    created = pulse.get("created")
    days = age_days(created)

    if score < QUARANTINE_SCORE_THRESHOLD:
        if ENABLE_QUARANTINE:
            return "quarantine", "low score"
        return False, "very low score"

    if score < MIN_SCORE_TO_INGEST:
        return False, "below minimum score"

    if days and days > MAX_DAYS_OLD and score < MIN_SCORE_FOR_OLD_PULSE:
        return False, "old pulse with low score"

    return True, "ok"

def search(query):
    log(f"Searching OTX: {query}")

    data = safe_request(
        "https://otx.alienvault.com/api/v1/search/pulses",
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        params={"q": query}
    )

    if not data:
        return []

    return data.get("results", [])

def enrich(pulse_id):
    data = safe_request(
        f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}",
        headers={"X-OTX-API-KEY": OTX_API_KEY}
    )

    return data

def send_bundle(name, description, score):
    identity = Identity(name="OTX Gateway", identity_class="organization")

    report = Report(
        name=name,
        description=description,
        report_types=["threat-report"],
        confidence=score,
        created=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
    )

    bundle = Bundle(objects=[identity, report], allow_custom=True)

    api.stix2.import_bundle_from_json(bundle.serialize(), update=True)

def run():
    state = load_state()

    for query in OTX_QUERIES:
        log(f"Query: {query}")

        pulses = search(query)

        for p in pulses[:MAX_PULSES_PER_QUERY]:
            pid = p.get("id")

            if pid in state["pulses"]:
                log(f"Skip state: {p.get('name')}")
                continue

            full = enrich(pid)

            if not full:
                log(f"Skip enrich failed: {p.get('name')}")
                continue

            name = full.get("name")
            indicators = full.get("indicators", [])
            ioc_count = len(indicators)

            age = age_days(full.get("created"))

            if age and age > MAX_DAYS_HARD_FILTER:
                log(f"Drop old: {name}")
                continue

            if ioc_count > MAX_IOCS_PER_PULSE:
                indicators = indicators[:MAX_IOCS_PER_PULSE]

            score = calculate_score(full, query)

            decision, reason = should_ingest(full, score)

            if decision == "quarantine":
                log(f"Quarantine: {name} score={score}")
                continue

            if decision is False:
                log(f"Drop: {name} reason={reason}")
                continue

            log(f"Ingest: {name} score={score}")

            send_bundle(name, full.get("description", ""), score)

            state["pulses"].append(pid)
            save_state(state)

            time.sleep(2)

while True:
    run()
    log(f"Sleeping {CONNECTOR_RUN_INTERVAL}s")
    time.sleep(CONNECTOR_RUN_INTERVAL)