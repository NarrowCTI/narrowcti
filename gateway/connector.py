from gateway.runtime import run_gateway_loop, run_gateway_once
from gateway.settings import load_settings
from gateway.sources import default_source_registry


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
