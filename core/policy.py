from core.scoring import age_days


def should_ingest(
    pulse,
    score,
    quarantine_score_threshold,
    enable_quarantine,
    min_score_to_ingest,
    max_days_old,
    min_score_for_old_pulse,
    max_days_hard_filter=0,
):
    created = pulse.get("created")
    days = age_days(created)

    if max_days_hard_filter > 0 and days is not None and days > max_days_hard_filter:
        return False, f"older than hard filter ({days}d > {max_days_hard_filter}d)"

    if score < quarantine_score_threshold:
        if enable_quarantine:
            return "quarantine", "low score"
        return False, "very low score"

    if score < min_score_to_ingest:
        return False, "below minimum score"

    if days is not None and days > max_days_old and score < min_score_for_old_pulse:
        return False, (
            f"old pulse with low score "
            f"({days}d > {max_days_old}d and score {score} < {min_score_for_old_pulse})"
        )

    return True, "ok"
