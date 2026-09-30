"""Explicit bounded MISP/OTX readiness diagnostic for the Ops role."""

from __future__ import annotations

import argparse
import json

from narrowcti.infrastructure.config.web_settings import load_web_settings
from narrowcti.infrastructure.runtime.web_composition import build_source_explorer


def main() -> int:
    parser = argparse.ArgumentParser(description="Check bounded read-only MISP/OTX Explorer readiness.")
    parser.add_argument("--json", action="store_true", help="Print safe machine-readable results.")
    args = parser.parse_args()

    results = build_source_explorer(load_web_settings().sources).check_readiness_all()
    if args.json:
        print(json.dumps([item.to_dict() for item in results], sort_keys=True))
    else:
        print("NarrowCTI provider readiness (bounded, read-only)")
        for item in results:
            print(f"{item.provider_key}={item.state.value} checked_at={item.checked_at}: {item.message}")
    # Exit 0 means the diagnostic completed and reported each provider state;
    # readiness itself is communicated explicitly in each result.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
