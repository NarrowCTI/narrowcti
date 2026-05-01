from dataclasses import dataclass

from core.scoring import age_days


@dataclass(frozen=True)
class PolicyConfig:
    quarantine_score_threshold: int
    enable_quarantine: bool
    min_score_to_ingest: int
    max_days_old: int
    min_score_for_old_pulse: int
    max_days_hard_filter: int = 0


def should_ingest(pulse, score, config):
    created = pulse.get("created")
    days = age_days(created)

    if (
        config.max_days_hard_filter > 0
        and days is not None
        and days > config.max_days_hard_filter
    ):
        return False, (
            f"older than hard filter ({days}d > {config.max_days_hard_filter}d)"
        )

    if score < config.quarantine_score_threshold:
        if config.enable_quarantine:
            return "quarantine", "low score"
        return False, "very low score"

    if score < config.min_score_to_ingest:
        return False, "below minimum score"

    if (
        days is not None
        and days > config.max_days_old
        and score < config.min_score_for_old_pulse
    ):
        return False, (
            f"old pulse with low score "
            f"({days}d > {config.max_days_old}d "
            f"and score {score} < {config.min_score_for_old_pulse})"
        )

    return True, "ok"
