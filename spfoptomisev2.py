#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import json
import sys
from typing import Dict, List, Set, Tuple

import dns.resolver


MAX_TXT_CHUNK = 255
MAX_RECORD_LENGTH = 450
DEFAULT_CHILD_PREFIX = "_spf"


def txt_record_to_string(txt_record) -> str:
    if hasattr(txt_record, "strings"):
        return "".join(
            part.decode("utf-8") if isinstance(part, bytes) else str(part)
            for part in txt_record.strings
        )

    return txt_record.to_text().strip('"')


def get_spf_record(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except Exception as e:
        raise RuntimeError(f"DNS TXT lookup failed for {domain}: {e}")

    spf_records = []

    for txt in answers:
        record = txt_record_to_string(txt).strip()

        if record.lower().startswith("v=spf1"):
            spf_records.append(record)

    if not spf_records:
        raise RuntimeError(f"No SPF record found for {domain}")

    if len(spf_records) > 1:
        raise RuntimeError(f"Multiple SPF records found for {domain}")

    return spf_records[0]


def contains_spf_macro(value: str) -> bool:
    return "%{" in value or "%" in value


def parse_ip_mechanism(token: str):
    try:
        if token.startswith("ip4:"):
            value = token[4:]
            if "/" not in value:
                value += "/32"
            return ipaddress.ip_network(value, strict=False)

        if token.startswith("ip6:"):
            value = token[4:]
            if "/" not in value:
                value += "/128"
            return ipaddress.ip_network(value, strict=False)

    except ValueError:
        return None

    return None


def expand_spf(
    domain: str,
    visited: Set[str] = None,
    depth: int = 0,
    max_depth: int = 10,
) -> Tuple[List[ipaddress._BaseNetwork], List[str], List[str], int]:

    if visited is None:
        visited = set()

    if depth > max_depth:
        raise RuntimeError(f"Maximum SPF recursion depth exceeded at {domain}")

    if domain in visited:
        return [], [], [f"Skipped recursive SPF reference: {domain}"], 0

    visited.add(domain)

    record = get_spf_record(domain)
    tokens = record.split()

    networks = []
    preserved_mechanisms = []
    warnings = []
    lookups = 0

    for token in tokens[1:]:
        clean = token.lstrip("+-~?")

        parsed = parse_ip_mechanism(clean)
        if parsed:
            networks.append(parsed)
            continue

        if clean.startswith("include:"):
            include_domain = clean.split(":", 1)[1]

            if contains_spf_macro(include_domain):
                preserved_mechanisms.append(token)
                warnings.append(f"Preserved macro include without DNS lookup: {token}")
                continue

            lookups += 1
            child_networks, child_preserved, child_warnings, child_lookups = expand_spf(
                include_domain,
                visited,
                depth + 1,
                max_depth,
            )

            networks.extend(child_networks)
            preserved_mechanisms.extend(child_preserved)
            warnings.extend(child_warnings)
            lookups += child_lookups
            continue

        if clean.startswith("redirect="):
            redirect_domain = clean.split("=", 1)[1]

            if contains_spf_macro(redirect_domain):
                preserved_mechanisms.append(token)
                warnings.append(f"Preserved macro redirect without DNS lookup: {token}")
                continue

            lookups += 1
            child_networks, child_preserved, child_warnings, child_lookups = expand_spf(
                redirect_domain,
                visited,
                depth + 1,
                max_depth,
            )

            networks.extend(child_networks)
            preserved_mechanisms.extend(child_preserved)
            warnings.extend(child_warnings)
            lookups += child_lookups
            continue

    return networks, preserved_mechanisms, warnings, lookups


def collapse_and_sort_networks(networks: List[ipaddress._BaseNetwork]):
    ipv4 = [n for n in networks if n.version == 4]
    ipv6 = [n for n in networks if n.version == 6]

    collapsed_v4 = list(ipaddress.collapse_addresses(ipv4))
    collapsed_v6 = list(ipaddress.collapse_addresses(ipv6))

    sorted_v4 = sorted(
        collapsed_v4,
        key=lambda n: (int(n.network_address), n.prefixlen),
    )

    sorted_v6 = sorted(
        collapsed_v6,
        key=lambda n: (int(n.network_address), n.prefixlen),
    )

    return sorted_v4 + sorted_v6, len(ipv4), len(collapsed_v4), len(ipv6), len(collapsed_v6)


def network_to_spf_mechanism(network: ipaddress._BaseNetwork) -> str:
    if network.version == 4:
        if network.prefixlen == 32:
            return f"ip4:{network.network_address}"
        return f"ip4:{network}"

    if network.prefixlen == 128:
        return f"ip6:{network.network_address}"
    return f"ip6:{network}"


def split_txt_chunks(value: str) -> str:
    """
    Split TXT records into quoted chunks under 255 characters.
    Prefer splitting on spaces so SPF mechanisms remain readable.
    """
    words = value.split()
    chunks = []
    current = ""

    for word in words:
        if not current:
            current = word
            continue

        test = f"{current} {word}"

        if len(test) > MAX_TXT_CHUNK:
            chunks.append(current)
            current = word
        else:
            current = test

    if current:
        chunks.append(current)

    return " ".join(f'"{chunk}"' for chunk in chunks)


def build_records(
    networks: List[ipaddress._BaseNetwork],
    preserved_mechanisms: List[str],
    domain: str,
    all_mechanism: str,
    child_prefix: str = DEFAULT_CHILD_PREFIX,
) -> Dict:

    mechanisms = [network_to_spf_mechanism(n) for n in networks]
    mechanisms.extend(preserved_mechanisms)

    records = []
    current = "v=spf1"

    for mechanism in mechanisms:
        test_record = f"{current} {mechanism} {all_mechanism}"

        if len(test_record) > MAX_RECORD_LENGTH and current != "v=spf1":
            records.append(f"{current} {all_mechanism}")
            current = f"v=spf1 {mechanism}"
        else:
            current += f" {mechanism}"

    if current != "v=spf1":
        records.append(f"{current} {all_mechanism}")
    else:
        records.append(f"v=spf1 {all_mechanism}")

    if len(records) == 1:
        return {
            "parent_name": domain,
            "parent_record": records[0],
            "children": [],
        }

    children = []
    includes = []

    for index, record in enumerate(records, start=1):
        child_name = f"{child_prefix}{index}.{domain}"

        children.append(
            {
                "name": child_name,
                "record": record,
            }
        )

        includes.append(f"include:{child_name}")

    parent_record = f"v=spf1 {' '.join(includes)} {all_mechanism}"

    return {
        "parent_name": domain,
        "parent_record": parent_record,
        "children": children,
    }


def render_terminal(result: Dict, stats: Dict, warnings: List[str]):
    print("\n============================================================")
    print(f"  SPF Optimizer: {result['parent_name']}")
    print("============================================================")

    print("\n[Original SPF Record]")
    print(f"  {stats['original_record']}")
    print(f"\n  DNS lookups in original : {stats['dns_lookups']}")
    print(f"  Length                  : {stats['original_length']} chars")

    print("\n[Expanding includes / redirects...]")
    print(f"  Raw IP mechanisms collected: {stats['raw_ip_mechanisms']}")
    print(f"  Preserved mechanisms       : {stats['preserved_mechanisms']}")

    print("\n[IP Consolidation]")
    print(f"  IPv4 ranges : {stats['ipv4_before']} -> {stats['ipv4_after']} after collapse")
    print(f"  IPv6 ranges : {stats['ipv6_before']} -> {stats['ipv6_after']} after collapse")

    print("\n[Result]")
    if result["children"]:
        print("  Parent and child SPF records required.")
    else:
        print("  Everything fits in a single record. No chaining needed.")

    print("\nParent:")
    print(f"  {result['parent_name']} TXT {result['parent_record']}")

    if result["children"]:
        print("\nChildren:")
        for child in result["children"]:
            print(f"  {child['name']} TXT {child['record']}")

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  - {warning}")


def render_zone(result: Dict):
    lines = []

    lines.append(
        f'{result["parent_name"]}. IN TXT {split_txt_chunks(result["parent_record"])}'
    )

    for child in result["children"]:
        lines.append(
            f'{child["name"]}. IN TXT {split_txt_chunks(child["record"])}'
        )

    return "\n".join(lines)


def render_csv(result: Dict):
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["type", "name", "record"],
    )

    writer.writeheader()

    writer.writerow(
        {
            "type": "parent",
            "name": result["parent_name"],
            "record": result["parent_record"],
        }
    )

    for child in result["children"]:
        writer.writerow(
            {
                "type": "child",
                "name": child["name"],
                "record": child["record"],
            }
        )


def normalize_all(value: str) -> str:
    mapping = {
        "softfail": "~all",
        "fail": "-all",
        "~all": "~all",
        "-all": "-all",
    }

    if value not in mapping:
        raise ValueError("Only ~all and -all are supported.")

    return mapping[value]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Flatten and optimize SPF records into IP-only SPF output, while preserving SPF macros."
    )

    parser.add_argument(
        "domain",
        help="Domain to read SPF from, for example example.com",
    )

    parser.add_argument(
        "--all",
        dest="all_mechanism",
        choices=["~all", "-all", "softfail", "fail"],
        default="~all",
        help="SPF all mechanism. Use '~all', '-all', 'softfail', or 'fail'. For '-all', use --all=-all or --all=fail.",
    )

    parser.add_argument(
        "--output",
        choices=["terminal", "zone", "csv", "json"],
        default="terminal",
        help="Output format.",
    )

    parser.add_argument(
        "--child-prefix",
        default=DEFAULT_CHILD_PREFIX,
        help="Prefix for generated child records. Default: _spf",
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum include or redirect recursion depth. Default: 10.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        all_mechanism = normalize_all(args.all_mechanism)

        original_record = get_spf_record(args.domain)

        networks, preserved_mechanisms, warnings, lookups = expand_spf(
            args.domain,
            max_depth=args.max_depth,
        )

        collapsed, ipv4_before, ipv4_after, ipv6_before, ipv6_after = collapse_and_sort_networks(
            networks
        )

        result = build_records(
            collapsed,
            preserved_mechanisms,
            args.domain,
            all_mechanism,
            args.child_prefix,
        )

        stats = {
            "original_record": original_record,
            "original_length": len(original_record),
            "dns_lookups": lookups,
            "raw_ip_mechanisms": len(networks),
            "preserved_mechanisms": len(preserved_mechanisms),
            "ipv4_before": ipv4_before,
            "ipv4_after": ipv4_after,
            "ipv6_before": ipv6_before,
            "ipv6_after": ipv6_after,
        }

        if args.output == "terminal":
            render_terminal(result, stats, warnings)

        elif args.output == "zone":
            print(render_zone(result))

        elif args.output == "csv":
            render_csv(result)

        elif args.output == "json":
            print(
                json.dumps(
                    {
                        "domain": args.domain,
                        "original_record": original_record,
                        "stats": stats,
                        "result": result,
                        "preserved_mechanisms": preserved_mechanisms,
                        "warnings": warnings,
                    },
                    indent=2,
                )
            )

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()