#!/usr/bin/env python3
"""
CrowdStrike Falcon Host Exporter (v2 — with CID Labels & Host Group Names)
============================================================================
Uses the FalconPy library to authenticate with the CrowdStrike Falcon API,
retrieve all hosts, fetch their details, resolve CID names via Flight Control,
resolve host group names via Host Group API, and export everything to a CSV
file with "cid_name" and "group_names" columns.

Requirements:
    pip install crowdstrike-falconpy

Usage:
    # Set environment variables (recommended):
    export FALCON_CLIENT_ID="your_client_id"
    export FALCON_CLIENT_SECRET="your_client_secret"

    # Then run:
    python falcon_hosts_export_v2.py

    # Or pass credentials directly (less secure):
    python falcon_hosts_export_v2.py --client_id YOUR_ID --client_secret YOUR_SECRET

    # Optional: specify output file and batch size
    python falcon_hosts_export_v2.py --output my_hosts.csv --batch_size 500

    # Export only hidden (suppressed) hosts
    python falcon_hosts_export_v2.py --hidden_only

    # Skip CID label resolution (if you don't have Flight Control / MSSP)
    python falcon_hosts_export_v2.py --skip_cid_lookup

    # Skip host group name resolution
    python falcon_hosts_export_v2.py --skip_group_lookup
"""

import os
import csv
import argparse
import sys
from datetime import datetime

try:
    from falconpy import Hosts, FlightControl, HostGroup
except ImportError:
    print("ERROR: FalconPy is not installed. Install it with: pip install crowdstrike-falconpy")
    sys.exit(1)


# ── Configuration ────────────────────────────────────────────────────────────

# Fields to include in the CSV output (in this order).
# Comment out or remove any field you don't need — it will be excluded from the CSV.
# To include ALL fields from the API (including unlisted ones), use --all_fields.
# "cid_name" and "group_names" are injected by this script (not returned by the API).
HOST_FIELDS = [
    "device_id",
    "cid",
    "cid_name",
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
    "groups",
    "group_names",
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
        description="Export all CrowdStrike Falcon hosts and their details to CSV (with CID & group labels)."
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
        "--all_fields",
        action="store_true",
        default=False,
        help="Include ALL fields from the API response. By default, only fields listed in HOST_FIELDS are exported.",
    )
    parser.add_argument(
        "--skip_cid_lookup",
        action="store_true",
        default=False,
        help="Skip CID name resolution (use if you don't have Flight Control / MSSP access)",
    )
    parser.add_argument(
        "--skip_group_lookup",
        action="store_true",
        default=False,
        help="Skip host group name resolution (use if you don't have Host Group Read access)",
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


def build_auth_kwargs(client_id: str, client_secret: str, base_url: str, member_cid: str = None) -> dict:
    """Build the common authentication keyword arguments."""
    kwargs = {
        "client_id": client_id,
        "client_secret": client_secret,
        "base_url": base_url,
    }
    if member_cid:
        kwargs["member_cid"] = member_cid
    return kwargs


def authenticate_hosts(auth_kwargs: dict) -> Hosts:
    """Create and return an authenticated Hosts service class instance."""
    falcon = Hosts(**auth_kwargs)

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


# ── CID Label Resolution ────────────────────────────────────────────────────

def build_cid_name_map(auth_kwargs: dict) -> dict:
    """
    Build a mapping of CID -> tenant name using the Flight Control (MSSP) API.

    Uses:
      1. FlightControl.query_children() to list all child CID IDs
      2. FlightControl.get_children(ids=...) to get details (name, child_cid)

    Returns a dict like {"abcdef123456...": "Acme Corp", ...}.
    Returns an empty dict if Flight Control access is unavailable.
    """
    cid_map = {}

    try:
        fc = FlightControl(**auth_kwargs)
    except Exception as e:
        print(f"  WARNING: Could not initialize FlightControl: {e}")
        return cid_map

    # Step 1: Query all child CID IDs
    all_child_ids = []
    offset = 0
    limit = 500

    while True:
        response = fc.query_children(offset=offset, limit=limit)
        status_code = response["status_code"]

        if status_code == 403:
            print("  WARNING: No Flight Control (MSSP) permission. CID names will be empty.")
            print("           Use --skip_cid_lookup to suppress this warning.")
            return cid_map
        elif status_code != 200:
            print(f"  WARNING: query_children failed (HTTP {status_code}). CID names will be empty.")
            return cid_map

        resources = response["body"].get("resources", [])
        if not resources:
            break

        all_child_ids.extend(resources)
        total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)

        if len(all_child_ids) >= total:
            break

    if not all_child_ids:
        print("  INFO: No child CIDs found (single-tenant environment). CID name column will be empty.")
        return cid_map

    # Step 2: Get child details in batches (name, child_cid, etc.)
    for i in range(0, len(all_child_ids), 500):
        batch = all_child_ids[i : i + 500]
        response = fc.get_children(ids=batch)

        if response["status_code"] != 200:
            print(f"  WARNING: get_children batch failed (HTTP {response['status_code']}). Partial CID names.")
            continue

        for child in response["body"].get("resources", []):
            child_cid = child.get("child_cid", "")
            child_name = child.get("name", "")
            if child_cid:
                # CIDs from hosts are lowercase without hyphens; normalize
                cid_map[child_cid.lower().replace("-", "")] = child_name

    print(f"✓ Resolved {len(cid_map)} CID label(s) via Flight Control")
    return cid_map


def enrich_with_cid_names(host_details: list, cid_map: dict) -> list:
    """Add a 'cid_name' field to each host record based on the CID lookup map."""
    for host in host_details:
        cid = host.get("cid", "").lower().replace("-", "")
        host["cid_name"] = cid_map.get(cid, "")
    return host_details


# ── Host Group Name Resolution ──────────────────────────────────────────────

def build_group_name_map(auth_kwargs: dict) -> dict:
    """
    Build a mapping of host group ID -> group name using the HostGroup API.

    Uses query_combined_host_groups to retrieve all groups with their details
    (paginated). Returns a dict like {"abc123def456...": "My Host Group", ...}.
    Returns an empty dict if Host Group access is unavailable.
    """
    group_map = {}

    try:
        hg = HostGroup(**auth_kwargs)
    except Exception as e:
        print(f"  WARNING: Could not initialize HostGroup: {e}")
        return group_map

    offset = 0
    limit = 500

    while True:
        response = hg.query_combined_host_groups(offset=offset, limit=limit)
        status_code = response["status_code"]

        if status_code == 403:
            print("  WARNING: No Host Group Read permission. Group names will be empty.")
            print("           Use --skip_group_lookup to suppress this warning.")
            return group_map
        elif status_code != 200:
            print(f"  WARNING: query_combined_host_groups failed (HTTP {status_code}). Group names will be empty.")
            return group_map

        resources = response["body"].get("resources", [])
        if not resources:
            break

        for group in resources:
            group_id = group.get("id", "")
            group_name = group.get("name", "")
            if group_id:
                group_map[group_id] = group_name

        total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)

        if len(group_map) >= total:
            break

    print(f"✓ Resolved {len(group_map)} host group name(s)")
    return group_map


def enrich_with_group_names(host_details: list, group_map: dict) -> list:
    """
    Add a 'group_names' field to each host record.
    Resolves group IDs from the 'groups' field to their human-readable names.
    Multiple groups are joined with '; '.
    Unresolved IDs are omitted (they remain visible in the 'groups' column).
    """
    for host in host_details:
        group_ids = host.get("groups", []) or []
        if isinstance(group_ids, str):
            group_ids = [group_ids]

        names = []
        for gid in group_ids:
            name = group_map.get(gid, "")
            if name:
                names.append(name)

        host["group_names"] = "; ".join(names) if names else ""

    return host_details


# ── Host ID and Detail Retrieval ─────────────────────────────────────────────

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


# ── CSV Export ───────────────────────────────────────────────────────────────

def flatten_value(value):
    """Flatten a value for CSV output. Lists become semicolon-separated, dicts become JSON-like strings."""
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def discover_all_fields(host_details: list, all_fields: bool = False) -> list:
    """
    Determine which fields to include in the CSV output.

    By default (all_fields=False), only fields listed in HOST_FIELDS are included.
    Comment out or remove entries from HOST_FIELDS to exclude them from the CSV.

    When all_fields=True, HOST_FIELDS are listed first (in order), followed by
    any additional fields discovered in the API response (sorted alphabetically).
    """
    all_keys = set()
    for host in host_details:
        all_keys.update(host.keys())

    # Preferred fields: only those in HOST_FIELDS that actually exist in the data
    preferred = [f for f in HOST_FIELDS if f in all_keys]

    if all_fields:
        # Include everything: preferred fields first, then the rest alphabetically
        remaining = sorted(all_keys - set(preferred))
        return preferred + remaining
    else:
        # Strict mode: only include fields explicitly listed in HOST_FIELDS
        return preferred


def export_to_csv(host_details: list, output_file: str, all_fields: bool = False):
    """Write host details to a CSV file."""
    if not host_details:
        print("WARNING: No host details to export.")
        return

    # Determine columns based on mode
    fieldnames = discover_all_fields(host_details, all_fields=all_fields)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for host in host_details:
            row = {field: flatten_value(host.get(field, "")) for field in fieldnames}
            writer.writerow(row)

    print(f"✓ Exported {len(host_details)} hosts to: {output_file}")


# ── Main ─────────────────────────────────────────────────────────────────────

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
    print("  v2 — with CID Labels & Host Group Names")
    if args.hidden_only:
        print("  Mode: HIDDEN HOSTS ONLY")
    print("=" * 60)

    # Build shared auth kwargs
    auth_kwargs = build_auth_kwargs(args.client_id, args.client_secret, args.base_url, args.member_cid)

    # Step 1: Authenticate (Hosts)
    falcon = authenticate_hosts(auth_kwargs)

    # Step 2: Resolve CID names via Flight Control (unless skipped)
    cid_map = {}
    if not args.skip_cid_lookup:
        print("Resolving CID labels via Flight Control...")
        cid_map = build_cid_name_map(auth_kwargs)
    else:
        print("Skipping CID label resolution (--skip_cid_lookup)")

    # Step 3: Resolve host group names (unless skipped)
    group_map = {}
    if not args.skip_group_lookup:
        print("Resolving host group names...")
        group_map = build_group_name_map(auth_kwargs)
    else:
        print("Skipping host group name resolution (--skip_group_lookup)")

    # Step 4: Retrieve all host IDs (with optional filter)
    host_ids = get_all_host_ids(falcon, fql_filter=args.filter, sort=args.sort, hidden_only=args.hidden_only)

    if not host_ids:
        print("No hosts found matching the criteria.")
        sys.exit(0)

    # Step 5: Fetch full details for each host
    host_details = get_host_details(falcon, host_ids, args.batch_size)

    # Step 6: Enrich host records with CID names
    if cid_map:
        host_details = enrich_with_cid_names(host_details, cid_map)
    else:
        for host in host_details:
            host.setdefault("cid_name", "")

    # Step 7: Enrich host records with host group names
    host_details = enrich_with_group_names(host_details, group_map)

    # Step 8: Export to CSV
    export_to_csv(host_details, args.output, all_fields=args.all_fields)

    print("=" * 60)
    print("  Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()
