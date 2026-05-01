from datetime import datetime, timezone
import re

from dateutil.parser import parse


def age_days(date_str):
    if not date_str:
        return None

    try:
        dt = parse(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


def query_terms(query):
    terms = re.findall(r"[a-z0-9]+", query.lower())
    return [term for term in terms if len(term) >= 3 or any(char.isdigit() for char in term)]


def has_query_term(value, terms):
    normalized = value.lower()
    return any(term in normalized for term in terms)


def calculate_score(pulse, query):
    score = 40

    name = pulse.get("name", "").lower()
    tags = [t.lower() for t in pulse.get("tags", [])]
    iocs = pulse.get("indicators", [])
    created = pulse.get("created")

    age = age_days(created)
    ioc_count = len(iocs)
    terms = query_terms(query)

    if query.lower() in name:
        score += 15
    elif has_query_term(name, terms):
        score += 10

    if any(query.lower() in t for t in tags):
        score += 10
    elif any(has_query_term(tag, terms) for tag in tags):
        score += 5

    if 10 <= ioc_count <= 500:
        score += 20
    elif 500 < ioc_count <= 2000:
        score += 10
    elif ioc_count > 2000:
        score -= 10

    if age is not None:
        if age < 30:
            score += 20
        elif age < 90:
            score += 10
        elif age > 365:
            score -= 10

    return max(0, min(score, 100))
