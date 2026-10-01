"""Named process exit semantics shared by Community CLI entrypoints."""

RUN_ONCE_SOURCE_FAILURE_EXIT_CODE = 2


def run_once_exit_code(summary) -> int:
    return (
        RUN_ONCE_SOURCE_FAILURE_EXIT_CODE
        if int(getattr(summary, "failed", 0) or 0) > 0
        else 0
    )


__all__ = ["RUN_ONCE_SOURCE_FAILURE_EXIT_CODE", "run_once_exit_code"]
