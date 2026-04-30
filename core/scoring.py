from datetime import datetime, timezone
from dateutil.parser import parse


def age_days(date_str):
    try:
        dt = parse(date_str)
        return (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
    except Exception:
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
