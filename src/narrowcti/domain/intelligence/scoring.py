from datetime import datetime, timezone
import re

from dateutil.parser import parse


BASE_SCORE = 40
NEUTRAL_SOURCE_CONFIDENCE = 50


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


def clamp_score(score):
    return max(0, min(score, 100))


def source_confidence_adjustment(source_confidence):
    try:
        confidence = int(source_confidence)
    except (TypeError, ValueError):
        confidence = NEUTRAL_SOURCE_CONFIDENCE
    confidence = clamp_score(confidence)
    return round((confidence - NEUTRAL_SOURCE_CONFIDENCE) / 5), confidence


def score_adjustment(signal, points, reason):
    return {
        "signal": signal,
        "points": points,
        "reason": reason,
    }


def calculate_score_details(pulse, query, source_confidence=NEUTRAL_SOURCE_CONFIDENCE):
    score = BASE_SCORE
    adjustments = []

    name = pulse.get("name", "").lower()
    tags = [t.lower() for t in pulse.get("tags", [])]
    iocs = pulse.get("indicators", [])
    created = pulse.get("created")

    age = age_days(created)
    ioc_count = len(iocs)
    terms = query_terms(query)

    source_points, normalized_confidence = source_confidence_adjustment(
        source_confidence
    )
    if source_points:
        score += source_points
        adjustments.append(
            score_adjustment(
                "source_confidence",
                source_points,
                f"source confidence {normalized_confidence}",
            )
        )

    if query.lower() in name:
        score += 15
        adjustments.append(
            score_adjustment("query_name_exact", 15, "query appears in title")
        )
    elif has_query_term(name, terms):
        score += 10
        adjustments.append(
            score_adjustment("query_name_term", 10, "query term appears in title")
        )

    if any(query.lower() in t for t in tags):
        score += 10
        adjustments.append(
            score_adjustment("query_tag_exact", 10, "query appears in tags")
        )
    elif any(has_query_term(tag, terms) for tag in tags):
        score += 5
        adjustments.append(
            score_adjustment("query_tag_term", 5, "query term appears in tags")
        )

    if 10 <= ioc_count <= 500:
        score += 20
        adjustments.append(
            score_adjustment("indicator_volume", 20, "moderate indicator volume")
        )
    elif 500 < ioc_count <= 2000:
        score += 10
        adjustments.append(
            score_adjustment("indicator_volume", 10, "large indicator volume")
        )
    elif ioc_count > 2000:
        score -= 10
        adjustments.append(
            score_adjustment("indicator_volume", -10, "oversized indicator volume")
        )

    if age is not None:
        if age < 30:
            score += 20
            adjustments.append(score_adjustment("recency", 20, "fresh intelligence"))
        elif age < 90:
            score += 10
            adjustments.append(score_adjustment("recency", 10, "recent intelligence"))
        elif age > 365:
            score -= 10
            adjustments.append(score_adjustment("recency", -10, "older intelligence"))

    return {
        "base_score": BASE_SCORE,
        "source_confidence": normalized_confidence,
        "adjustments": adjustments,
        "raw_score": score,
        "final_score": clamp_score(score),
    }


def calculate_score(pulse, query, source_confidence=NEUTRAL_SOURCE_CONFIDENCE):
    return calculate_score_details(pulse, query, source_confidence)["final_score"]
