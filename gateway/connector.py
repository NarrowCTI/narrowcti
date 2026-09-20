"""Historical gateway entrypoint with a preserved monkeypatch surface."""

from narrowcti.infrastructure.config.settings import load_settings
from narrowcti.infrastructure.runtime.gateway_composition import default_source_registry
from gateway.runtime import run_gateway_loop, run_gateway_once


def log(msg):
    print(f"[INFO] {msg}", flush=True)


def main():
    settings = load_settings()
    registry = default_source_registry(log, settings)
    if settings.run_once:
        run_gateway_once(settings, registry, log)
        return
    run_gateway_loop(settings, registry, log)


if __name__ == "__main__":
    main()
