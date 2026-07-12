def require_nonnegative(name, value):
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def require_positive(name, value):
    if value < 1:
        raise ValueError(f"{name} must be greater than zero")
    return value
