import random


def retry_delay(attempt, backoff_seconds, jitter_seconds=0, random_fn=random.uniform):
    base_delay = max(0, int(attempt)) * max(0, int(backoff_seconds))
    jitter = max(0, int(jitter_seconds))
    if not jitter:
        return base_delay
    return base_delay + random_fn(0, jitter)
