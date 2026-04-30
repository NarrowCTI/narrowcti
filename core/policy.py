from core.scoring import age_days


def should_ingest(pulse, score, quarantine_score_threshold, enable_quarantine, min_score_to_ingest, max_days_old, min_score_for_old_pulse):
    created = pulse.get("created")
    days = age_days(created)

    if score < quarantine_score_threshold:
        if enable_quarantine:
            return "quarantine", "low score"
        return False, "very low score"

    if score < min_score_to_ingest:
        return False, "below minimum score"

    if days and days > max_days_old and score < min_score_for_old_pulse:
        return False, "old pulse with low score"

    return True, "ok"
