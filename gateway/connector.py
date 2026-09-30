"""Historical gateway entrypoint with a preserved monkeypatch surface."""

from narrowcti.infrastructure.config.settings import load_settings
from narrowcti.infrastructure.runtime.gateway_composition import default_source_registry
from gateway.runtime import run_gateway_loop, run_gateway_once
from narrowcti.cli.worker import WORKER_LEASE_HELD_EXIT_CODE, WorkerLeaseUnavailable, run_worker
from narrowcti.cli.exit_codes import run_once_exit_code


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def main():
    settings = load_settings()
    registry = default_source_registry(log, settings)
    try:
        result = run_worker(
            settings,
            registry,
            log,
            run_once=run_gateway_once,
            run_loop=run_gateway_loop,
        )
    except WorkerLeaseUnavailable as exc:
        log(str(exc))
        return WORKER_LEASE_HELD_EXIT_CODE
    return run_once_exit_code(result) if settings.run_once else 0


if __name__ == "__main__":
    raise SystemExit(main())
