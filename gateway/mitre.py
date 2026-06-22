import argparse
import json

from core.mitre_attack import (
    DEFAULT_MITRE_STIX_URL,
    MITREAttackResolver,
    build_attack_cache,
    load_attack_cache,
    refresh_attack_cache,
    save_attack_cache,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Manage the local NarrowCTI MITRE ATT&CK reference cache.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_cache = subparsers.add_parser(
        "build-cache",
        help="Build a normalized cache from a local ATT&CK STIX bundle.",
    )
    build_cache.add_argument("--bundle", required=True, help="Input STIX bundle JSON.")
    build_cache.add_argument(
        "--cache-file",
        required=True,
        help="Output normalized MITRE cache JSON.",
    )

    refresh_cache = subparsers.add_parser(
        "refresh-cache",
        help="Download ATT&CK STIX data and write the normalized cache.",
    )
    refresh_cache.add_argument(
        "--cache-file",
        required=True,
        help="Output normalized MITRE cache JSON.",
    )
    refresh_cache.add_argument(
        "--url",
        default=DEFAULT_MITRE_STIX_URL,
        help="ATT&CK STIX bundle URL.",
    )
    refresh_cache.add_argument("--timeout", type=int, default=60)

    resolve = subparsers.add_parser(
        "resolve",
        help="Resolve ATT&CK technique ids from a local cache.",
    )
    resolve.add_argument("--cache-file", required=True)
    resolve.add_argument("attack_ids", nargs="+")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.command == "build-cache":
        bundle = load_json(args.bundle)
        cache = build_attack_cache(bundle)
        save_attack_cache(cache, args.cache_file)
        print(json.dumps(cache_summary(cache), sort_keys=True))
        return 0

    if args.command == "refresh-cache":
        cache = refresh_attack_cache(
            args.cache_file,
            stix_url=args.url,
            timeout=args.timeout,
        )
        print(json.dumps(cache_summary(cache), sort_keys=True))
        return 0

    if args.command == "resolve":
        resolver = MITREAttackResolver(cache=load_attack_cache(args.cache_file))
        print(json.dumps(resolver.resolve(args.attack_ids), sort_keys=True))
        return 0

    return 1


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def cache_summary(cache):
    return {
        "source": cache.get("source", "mitre-attack"),
        "generated_at": cache.get("generated_at", ""),
        "technique_count": cache.get("technique_count", 0),
    }


if __name__ == "__main__":
    raise SystemExit(main())
