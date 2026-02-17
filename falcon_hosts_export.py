#!/usr/bin/env python3
"""
CrowdStrike Falcon Host Exporter
=================================
Uses the FalconPy library to authenticate with the CrowdStrike Falcon API,
retrieve all hosts, fetch their details, and export everything to a CSV file.

Requirements:
    pip install crowdstrike-falconpy

Usage:
    # Set environment variables (recommended):
    export FALCON_CLIENT_ID="your_client_id"
    export FALCON_CLIENT_SECRET="your_client_secret"

    # Then run:
    python falcon_hosts_export.py

    # Or pass credentials directly (less secure):
    python falcon_hosts_export.py --client_id YOUR_ID --client_secret YOUR_SECRET

    # Optional: specify output file and batch size
    python falcon_hosts_export.py --output my_hosts.csv --batch_size 500

    # Export only hidden (suppressed) hosts
    python falcon_hosts_export.py --hidden_only
"""

import os
import csv
import argparse
import sys
from datetime import datetime

try:
    from falconpy import Hosts
except ImportError:
    print("ERROR: FalconPy is not installed. Install it with: pip install crowdstrike-falconpy")
    sys.exit(1)


# ── Configuration ────────────────────────────────────────────────────────────

# Fields to extract from host details. Adjust this list to include/exclude columns.
# These are the most commonly useful fields returned by GetDeviceDetails.
HOST_FIELDS = [
    "device_id",
    "cid",
    "hostname",
    "local_ip",
    "external_ip",
    "mac_address",
    "os_version",
    "os_product_name",
    "platform_name",
    "system_manufacturer",
    "system_product_name",
    "product_type_desc",
    "status",
    "agent_version",
    "bios_manufacturer",
    "bios_version",
    "site_name",
    "ou",
    "machine_domain",
    "last_seen",
    "first_seen",
    "provision_status",
    "reduced_functionality_mode",
    "serial_number",
    "service_pack_major",
    "tags",
    "group_hash",
    "kernel_version",
    "cpu_signature",
    "config_id_base",
    "config_id_build",
    "config_id_platform",
    "chassis_type_desc",
    "connection_ip",
    "default_gateway_ip",
    "modified_timestamp",
    "meta",
]

# Maximum IDs per detail request (API limit is 5000)
DEFAULT_BATCH_SIZE = 500

# Maximum IDs per scroll request (API limit is 10000)
SCROLL_LIMIT = 5000


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export all CrowdStrike Falcon hosts and their details to CSV."
    )
    parser.add_argument(
        "--client_id",
        default=os.environ.get("FALCON_CLIENT_ID"),
        help="Falcon API Client ID (or set FALCON_CLIENT_ID env var)",
    )
    parser.add_argument(
        "--client_secret",
        default=os.environ.get("FALCON_CLIENT_SECRET"),
        help="Falcon API Client Secret (or set FALCON_CLIENT_SECRET env var)",
    )
    parser.add_argument(
        "--base_url",
        default=os.environ.get("FALCON_BASE_URL", "auto"),
        help="Falcon API base URL (default: auto-detect). Examples: us-1, us-2, eu-1, us-gov-1",
    )
    parser.add_argument(
        "--member_cid",
        default=os.environ.get("FALCON_MEMBER_CID"),
        help="Member CID for MSSP / Flight Control scenarios",
    )
    parser.add_argument(
        "--output",
        default=f"falcon_hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV filename (default: falcon_hosts_<timestamp>.csv)",
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Number of host IDs to fetch details for per request (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--hidden_only",
        action="store_true",
        default=False,
        help="Export only hidden (suppressed) hosts instead of active hosts",
    )
    parser.add_argument(
        "--filter",
        default=None,
        help="Optional FQL filter to narrow hosts (e.g. \"platform_name:'Windows'\")",
    )
    parser.add_argument(
        "--sort",
        default="hostname.asc",
        help="Sort order for results (default: hostname.asc)",
    )
    return parser.parse_args()


def authenticate(client_id: str, client_secret: str, base_url: str, member_cid: str = None) -> Hosts:
    """Create and return an authenticated Hosts service class instance."""
    kwargs = {
        "client_id": client_id,
        "client_secret": client_secret,
        "base_url": base_url,
    }
    if member_cid:
        kwargs["member_cid"] = member_cid

    falcon = Hosts(**kwargs)

    # Verify authentication by making a small test call
    test = falcon.query_devices_by_filter_scroll(limit=1)
    status_code = test["status_code"]
    if status_code == 401:
        print("ERROR: Authentication failed. Check your Client ID and Client Secret.")
        sys.exit(1)
    elif status_code == 403:
        print("ERROR: Authorization failed. Ensure your API key has 'Hosts: Read' scope.")
        sys.exit(1)
    elif status_code != 200:
        print(f"ERROR: Unexpected API response (HTTP {status_code}):")
        print(test["body"])
        sys.exit(1)

    print("✓ Successfully authenticated to CrowdStrike Falcon API")
    return falcon


def get_all_host_ids(falcon: Hosts, fql_filter: str = None, sort: str = "hostname.asc", hidden_only: bool = False) -> list:
    """
    Retrieve ALL host IDs using pagination.
    When hidden_only=True, uses query_hidden_devices (integer offset pagination).
    Otherwise, uses query_devices_by_filter_scroll (scroll/token pagination).
    Returns a list of device_id strings.
    """
    all_ids = []
    label = "hidden host" if hidden_only else "host"

    print(f"Retrieving {label} IDs...", end="", flush=True)

    if hidden_only:
        # query_hidden_devices uses integer-based offset pagination
        offset = 0
        while True:
            kwargs = {"limit": SCROLL_LIMIT, "sort": sort, "offset": offset}
            if fql_filter:
                kwargs["filter"] = fql_filter

            response = falcon.query_hidden_devices(**kwargs)

            if response["status_code"] != 200:
                print(f"\nERROR: Failed to query hidden hosts (HTTP {response['status_code']}):")
                print(response["body"])
                sys.exit(1)

            body = response["body"]
            resources = body.get("resources", [])

            if not resources:
                break

            all_ids.extend(resources)
            print(f"\r  Retrieved {len(all_ids)} {label} IDs so far...", end="", flush=True)

            total = body.get("meta", {}).get("pagination", {}).get("total", 0)
            offset += len(resources)

            if len(all_ids) >= total:
                break
    else:
        # query_devices_by_filter_scroll uses scroll/token-based pagination
        offset = None
        while True:
            kwargs = {"limit": SCROLL_LIMIT, "sort": sort}
            if offset:
                kwargs["offset"] = offset
            if fql_filter:
                kwargs["filter"] = fql_filter

            response = falcon.query_devices_by_filter_scroll(**kwargs)

            if response["status_code"] != 200:
                print(f"\nERROR: Failed to query hosts (HTTP {response['status_code']}):")
                print(response["body"])
                sys.exit(1)

            body = response["body"]
            resources = body.get("resources", [])

            if not resources:
                break

            all_ids.extend(resources)
            print(f"\r  Retrieved {len(all_ids)} {label} IDs so far...", end="", flush=True)

            offset = body.get("meta", {}).get("pagination", {}).get("offset")
            total = body.get("meta", {}).get("pagination", {}).get("total", 0)

            if not offset or len(all_ids) >= total:
                break

    print(f"\r✓ Retrieved {len(all_ids)} total {label} IDs.           ")
    return all_ids


def get_host_details(falcon: Hosts, host_ids: list, batch_size: int) -> list:
    """
    Fetch full details for all hosts in batches.
    Returns a list of host detail dictionaries.
    """
    all_details = []
    total = len(host_ids)

    print("Fetching host details...")

    for i in range(0, total, batch_size):
        batch = host_ids[i : i + batch_size]
        response = falcon.get_device_details(ids=batch)

        if response["status_code"] != 200:
            print(f"\n  WARNING: Batch {i // batch_size + 1} failed (HTTP {response['status_code']}). Skipping.")
            continue

        resources = response["body"].get("resources", [])
        all_details.extend(resources)

        fetched = min(i + batch_size, total)
        print(f"\r  Fetched details for {fetched}/{total} hosts...", end="", flush=True)

    print(f"\r✓ Fetched details for {len(all_details)} hosts.           ")
    return all_details


def flatten_value(value):
    """Flatten a value for CSV output. Lists become semicolon-separated, dicts become JSON-like strings."""
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def discover_all_fields(host_details: list) -> list:
    """Discover all unique keys across all host records for complete CSV output."""
    all_keys = set()
    for host in host_details:
        all_keys.update(host.keys())
    # Put preferred fields first (if they exist), then the rest alphabetically
    preferred = [f for f in HOST_FIELDS if f in all_keys]
    remaining = sorted(all_keys - set(preferred))
    return preferred + remaining


def export_to_csv(host_details: list, output_file: str):
    """Write host details to a CSV file."""
    if not host_details:
        print("WARNING: No host details to export.")
        return

    # Use all discovered fields for comprehensive output
    fieldnames = discover_all_fields(host_details)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for host in host_details:
            row = {field: flatten_value(host.get(field, "")) for field in fieldnames}
            writer.writerow(row)

    print(f"✓ Exported {len(host_details)} hosts to: {output_file}")


def main():
    args = parse_args()

    # Validate credentials
    if not args.client_id or not args.client_secret:
        print("ERROR: API credentials are required.")
        print("  Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables,")
        print("  or pass --client_id and --client_secret arguments.")
        sys.exit(1)

    print("=" * 60)
    print("  CrowdStrike Falcon Host Exporter")
    if args.hidden_only:
        print("  Mode: HIDDEN HOSTS ONLY")
    print("=" * 60)

    # Step 1: Authenticate
    falcon = authenticate(args.client_id, args.client_secret, args.base_url, args.member_cid)

    # Step 2: Retrieve all host IDs (with optional filter)
    host_ids = get_all_host_ids(falcon, fql_filter=args.filter, sort=args.sort, hidden_only=args.hidden_only)

    if not host_ids:
        print("No hosts found matching the criteria.")
        sys.exit(0)

    # Step 3: Fetch full details for each host
    host_details = get_host_details(falcon, host_ids, args.batch_size)

    # Step 4: Export to CSV
    export_to_csv(host_details, args.output)

    print("=" * 60)
    print("  Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()
