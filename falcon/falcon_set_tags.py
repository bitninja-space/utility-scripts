#!/usr/bin/env python3
"""
CrowdStrike Falcon Grouping Tag Setter
========================================
Reads a CSV input file containing hostnames (or device IDs) and tags to apply,
then uses the FalconPy SDK to append FalconGroupingTags to each host.

The "add" action APPENDS tags — existing tags on the host are preserved.

Input CSV format:
    hostname,tags
    WORKSTATION-01,tag1;tag2
    SERVER-02,tag3

Or using device_id directly:
    device_id,tags
    abc123def456...,tag1;tag2

Requirements:
    pip install crowdstrike-falconpy

Usage:
    export FALCON_CLIENT_ID="your_client_id"
    export FALCON_CLIENT_SECRET="your_client_secret"

    python falcon_set_tags.py --input devices_tags.csv
    python falcon_set_tags.py --input devices_tags.csv --id_column hostname
    python falcon_set_tags.py --input devices_tags.csv --id_column device_id
    python falcon_set_tags.py --input devices_tags.csv --dry_run
"""

import os
import csv
import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from falconpy import Hosts
except ImportError:
    print("ERROR: FalconPy is not installed. Install it with: pip install crowdstrike-falconpy")
    sys.exit(1)


# Maximum device IDs per update_device_tags call
TAG_BATCH_SIZE = 100

# Maximum IDs per query_devices_by_filter_scroll call
SCROLL_LIMIT = 5000


def parse_args():
    parser = argparse.ArgumentParser(
        description="Set FalconGroupingTags on hosts from a CSV input file."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the input CSV file",
    )
    parser.add_argument(
        "--id_column",
        default=None,
        help=(
            "Column name used to identify hosts. Supported values: 'hostname', "
            "'device_id', or any column present in the CSV. Auto-detected if not "
            "specified (looks for 'hostname' first, then 'device_id')."
        ),
    )
    parser.add_argument(
        "--tag_column",
        default="tags",
        help="Column name containing the tags to apply (default: 'tags')",
    )
    parser.add_argument(
        "--tag_separator",
        default=";",
        help="Separator for multiple tags within a single cell (default: ';')",
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
        "--dry_run",
        action="store_true",
        default=False,
        help="Preview changes without actually applying tags",
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=TAG_BATCH_SIZE,
        help=f"Number of device IDs per update_device_tags call (default: {TAG_BATCH_SIZE})",
    )
    parser.add_argument(
        "--rate_limit_delay",
        type=float,
        default=0.5,
        help="Seconds to wait between tag API calls to avoid rate limiting (default: 0.5)",
    )
    return parser.parse_args()


# ── Authentication ────────────────────────────────────────────────────────────

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

    # Verify authentication
    test = falcon.query_devices_by_filter_scroll(limit=1)
    status_code = test["status_code"]
    if status_code == 401:
        print("ERROR: Authentication failed. Check your Client ID and Client Secret.")
        sys.exit(1)
    elif status_code == 403:
        print("ERROR: Authorization failed. Ensure your API key has 'Hosts: Read + Write' scope.")
        sys.exit(1)
    elif status_code != 200:
        print(f"ERROR: Unexpected API response (HTTP {status_code}):")
        print(test["body"])
        sys.exit(1)

    print("✓ Successfully authenticated to CrowdStrike Falcon API")
    return falcon


# ── CSV Parsing ───────────────────────────────────────────────────────────────

def read_input_csv(filepath: str, id_column: str, tag_column: str, tag_separator: str) -> list:
    """
    Read the input CSV and return a list of dicts:
        [{"identifier": "WORKSTATION-01", "tags": ["tag1", "tag2"]}, ...]

    Auto-detects the id_column if not specified.
    """
    if not os.path.isfile(filepath):
        print(f"ERROR: Input file not found: {filepath}")
        sys.exit(1)

    # Detect encoding — try UTF-8 first, fall back to latin-1
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(filepath, "r", encoding=encoding) as f:
                f.read(1024)
            break
        except UnicodeDecodeError:
            continue

    with open(filepath, "r", encoding=encoding, newline="") as f:
        reader = csv.DictReader(f)
        headers = [h.strip().lower() for h in reader.fieldnames] if reader.fieldnames else []

        if not headers:
            print("ERROR: Input CSV has no headers.")
            sys.exit(1)

        # Normalize header mapping (lowercase -> original)
        header_map = {}
        for original in reader.fieldnames:
            header_map[original.strip().lower()] = original

        # Auto-detect id_column
        if id_column is None:
            if "hostname" in headers:
                id_column = "hostname"
            elif "device_id" in headers:
                id_column = "device_id"
            else:
                print(f"ERROR: Could not auto-detect ID column. Available headers: {reader.fieldnames}")
                print("       Use --id_column to specify which column identifies hosts.")
                sys.exit(1)
            print(f"  Auto-detected ID column: '{id_column}'")

        # Validate columns exist
        id_col_lower = id_column.strip().lower()
        tag_col_lower = tag_column.strip().lower()

        if id_col_lower not in headers:
            print(f"ERROR: ID column '{id_column}' not found in CSV. Available: {reader.fieldnames}")
            sys.exit(1)
        if tag_col_lower not in headers:
            print(f"ERROR: Tag column '{tag_column}' not found in CSV. Available: {reader.fieldnames}")
            sys.exit(1)

        id_col_original = header_map[id_col_lower]
        tag_col_original = header_map[tag_col_lower]

        records = []
        line_num = 1  # header is line 1
        for row in reader:
            line_num += 1
            identifier = (row.get(id_col_original) or "").strip()
            raw_tags = (row.get(tag_col_original) or "").strip()

            if not identifier:
                print(f"  WARNING: Skipping line {line_num} — empty identifier.")
                continue
            if not raw_tags:
                print(f"  WARNING: Skipping line {line_num} ({identifier}) — no tags specified.")
                continue

            # Parse tags: split by separator, strip whitespace, remove empties
            tags = [t.strip() for t in raw_tags.split(tag_separator) if t.strip()]

            # Ensure FalconGroupingTags/ prefix
            normalized_tags = []
            for tag in tags:
                if tag.startswith("FalconGroupingTags/"):
                    normalized_tags.append(tag)
                else:
                    normalized_tags.append(f"FalconGroupingTags/{tag}")

            if normalized_tags:
                records.append({
                    "identifier": identifier,
                    "tags": normalized_tags,
                })

    return records, id_col_lower


# ── Hostname → Device ID Resolution ──────────────────────────────────────────

def _fetch_all_host_ids_and_hostnames(falcon: Hosts) -> dict:
    """
    Fetch ALL device IDs and their hostnames from the Falcon API in bulk.
    Uses query_devices_by_filter_scroll (scroll-token pagination) to get IDs,
    then get_device_details in batches to get hostnames.

    Returns a dict mapping hostname (lowercase) -> list of device_ids.
    """
    print("    Fetching all host IDs from tenant...")

    # Step 1: Scroll through all device IDs
    all_ids = []
    offset = None  # scroll token

    while True:
        kwargs = {"limit": SCROLL_LIMIT}
        if offset:
            kwargs["offset"] = offset

        response = falcon.query_devices_by_filter_scroll(**kwargs)
        if response["status_code"] != 200:
            print(f"    WARNING: query_devices_by_filter_scroll failed (HTTP {response['status_code']})")
            break

        resources = response["body"].get("resources", [])
        if not resources:
            break

        all_ids.extend(resources)
        offset = response["body"].get("meta", {}).get("pagination", {}).get("offset", "")

        if not offset:
            break

    print(f"    Found {len(all_ids)} total host(s) in tenant.")

    if not all_ids:
        return {}

    # Step 2: Fetch hostname for each device in batches
    hostname_map = defaultdict(list)
    detail_batch = 500

    for i in range(0, len(all_ids), detail_batch):
        batch = all_ids[i : i + detail_batch]
        response = falcon.get_device_details(ids=batch)

        if response["status_code"] != 200:
            print(f"    WARNING: get_device_details batch failed (HTTP {response['status_code']})")
            continue

        for host in response["body"].get("resources", []):
            hostname = (host.get("hostname") or "").lower()
            device_id = host.get("device_id", "")
            if hostname and device_id:
                hostname_map[hostname].append(device_id)

        if (i + detail_batch) % 5000 == 0 or (i + detail_batch) >= len(all_ids):
            print(f"    Fetched details: {min(i + detail_batch, len(all_ids))}/{len(all_ids)}...")

    return hostname_map


def resolve_hostnames_to_ids(falcon: Hosts, hostnames: list) -> dict:
    """
    Resolve a list of hostnames to device IDs via the Falcon API.

    For small lists (<50 hostnames), resolves one-by-one via FQL filter.
    For larger lists, fetches ALL hosts from the tenant and matches locally.
    This avoids 20,000+ individual API calls for large input files.

    Returns a dict mapping hostname (lowercase) -> list of device_ids.
    """
    total = len(hostnames)
    print(f"  Resolving {total} hostname(s) to device IDs...")

    hostname_to_ids = defaultdict(list)

    if total <= 50:
        # Small list — resolve one-by-one (fewer API calls than bulk fetch)
        for idx, hostname in enumerate(hostnames, 1):
            fql_filter = f"hostname:'{hostname}'"

            response = falcon.query_devices_by_filter_scroll(
                filter=fql_filter,
                limit=10,
            )

            if response["status_code"] != 200:
                print(f"    WARNING: Failed to look up '{hostname}' (HTTP {response['status_code']})")
                continue

            device_ids = response["body"].get("resources", [])
            if not device_ids:
                print(f"    WARNING: No host found for hostname '{hostname}'")
                continue

            if len(device_ids) > 1:
                print(f"    INFO: Hostname '{hostname}' matched {len(device_ids)} device(s) — tagging all.")

            hostname_to_ids[hostname.lower()] = device_ids

            if idx % 50 == 0 or idx == total:
                print(f"    Resolved {idx}/{total}...")
    else:
        # Large list — bulk fetch all hosts, then match locally
        print(f"    Large batch detected ({total} hosts). Using bulk resolution...")
        all_hosts_map = _fetch_all_host_ids_and_hostnames(falcon)

        # Match requested hostnames against the full map
        lookup_set = {h.lower() for h in hostnames}

        for hostname_lower in lookup_set:
            if hostname_lower in all_hosts_map:
                device_ids = all_hosts_map[hostname_lower]
                hostname_to_ids[hostname_lower] = device_ids
                if len(device_ids) > 1:
                    print(f"    INFO: Hostname '{hostname_lower}' matched {len(device_ids)} device(s) — tagging all.")
            else:
                # Find original case for the warning message
                original = next((h for h in hostnames if h.lower() == hostname_lower), hostname_lower)
                print(f"    WARNING: No host found for hostname '{original}'")

    resolved = sum(len(ids) for ids in hostname_to_ids.values())
    print(f"  ✓ Resolved {resolved} device ID(s) from {len(hostname_to_ids)} hostname(s).")
    return hostname_to_ids


# ── Tag Application ───────────────────────────────────────────────────────────

def apply_tags(falcon: Hosts, device_ids: list, tags: list,
               dry_run: bool = False, batch_size: int = TAG_BATCH_SIZE,
               rate_limit_delay: float = 0.5) -> dict:
    """
    Apply (append) FalconGroupingTags to a list of device IDs.

    The 'add' action appends tags — it does NOT remove or replace existing tags.
    Includes retry logic for HTTP 429 (rate limiting) with exponential backoff.

    Returns a dict with counts and per-device results:
        {
            "success": N,
            "failed": N,
            "errors": [...],
            "device_results": [{"device_id": "...", "status": "success"|"failed", "error": "..."}]
        }
    """
    result = {"success": 0, "failed": 0, "errors": [], "device_results": []}
    max_retries = 5

    if dry_run:
        result["success"] = len(device_ids)
        for did in device_ids:
            result["device_results"].append({"device_id": did, "status": "dry_run", "error": ""})
        return result

    total_batches = (len(device_ids) + batch_size - 1) // batch_size

    # Batch device IDs (API has limits per call)
    for batch_num, i in enumerate(range(0, len(device_ids), batch_size), 1):
        batch = device_ids[i : i + batch_size]

        # Retry loop for rate limiting
        for attempt in range(max_retries):
            response = falcon.update_device_tags(
                action_name="add",
                ids=batch,
                tags=tags,
            )

            status_code = response["status_code"]

            if status_code == 429:
                # Rate limited — wait and retry with exponential backoff
                retry_after = response.get("headers", {}).get("X-RateLimit-RetryAfter", "")
                wait_time = (2 ** attempt) + 1  # 2, 3, 5, 9, 17 seconds
                print(f"    Rate limited (HTTP 429). Retrying batch {batch_num}/{total_batches} "
                      f"in {wait_time}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait_time)
                continue
            else:
                break  # Not rate limited, proceed
        else:
            # Exhausted all retries
            status_code = 429

        if status_code in (200, 202):
            result["success"] += len(batch)
            for did in batch:
                result["device_results"].append({"device_id": did, "status": "success", "error": ""})
        else:
            result["failed"] += len(batch)
            error_msg = response["body"].get("errors", [])
            error_str = str(error_msg)
            result["errors"].append({
                "status_code": status_code,
                "device_count": len(batch),
                "errors": error_msg,
            })
            for did in batch:
                result["device_results"].append({
                    "device_id": did,
                    "status": "failed",
                    "error": f"HTTP {status_code}: {error_str}",
                })

        # Progress update for large batches
        if total_batches > 10 and (batch_num % 10 == 0 or batch_num == total_batches):
            print(f"    Progress: batch {batch_num}/{total_batches} "
                  f"({result['success']} OK, {result['failed']} failed)")

        # Rate limit delay between calls
        if rate_limit_delay > 0 and i + batch_size < len(device_ids):
            time.sleep(rate_limit_delay)

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def write_results_csv(all_device_results: list, unresolved_hosts: list, output_path: str):
    """
    Write a results CSV showing the outcome for every device/hostname.
    This file can be used to identify failures and re-run only those.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["identifier", "device_id", "tags", "status", "error"])

        for entry in all_device_results:
            writer.writerow([
                entry.get("identifier", ""),
                entry["device_id"],
                entry["tags_display"],
                entry["status"],
                entry["error"],
            ])

        # Append unresolved hostnames
        for hostname in unresolved_hosts:
            writer.writerow([hostname, "", "", "unresolved", "No host found for hostname"])

    print(f"  Results log: {output_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  CrowdStrike Falcon Grouping Tag Setter")
    print("=" * 60)

    args = parse_args()

    # Validate credentials
    if not args.client_id or not args.client_secret:
        print("ERROR: Falcon API credentials required.")
        print("       Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET env vars,")
        print("       or use --client_id and --client_secret.")
        sys.exit(1)

    # Read input CSV
    print(f"\nReading input file: {args.input}")
    records, id_type = read_input_csv(
        filepath=args.input,
        id_column=args.id_column,
        tag_column=args.tag_column,
        tag_separator=args.tag_separator,
    )

    if not records:
        print("ERROR: No valid records found in input file.")
        sys.exit(1)

    print(f"  ✓ Loaded {len(records)} record(s) from CSV.")

    # Authenticate
    print("\nAuthenticating...")
    falcon = authenticate(
        client_id=args.client_id,
        client_secret=args.client_secret,
        base_url=args.base_url,
        member_cid=args.member_cid,
    )

    # If using hostnames, resolve to device IDs
    use_hostname = id_type in ("hostname",)
    hostname_to_ids = {}
    unresolved_hosts = []

    if use_hostname:
        unique_hostnames = list(set(r["identifier"] for r in records))
        hostname_to_ids = resolve_hostnames_to_ids(falcon, unique_hostnames)
        # Track hostnames that could not be resolved
        unresolved_hosts = [h for h in unique_hostnames if h.lower() not in hostname_to_ids]

    # Build a mapping: device_id -> identifier (for results tracking)
    device_id_to_identifier = {}

    # Group records by tag set for efficient batching
    # (devices getting the same tags can be tagged in one API call)
    tag_groups = defaultdict(list)

    for record in records:
        identifier = record["identifier"]
        tags = tuple(sorted(record["tags"]))  # hashable key

        if use_hostname:
            device_ids = hostname_to_ids.get(identifier.lower(), [])
            if not device_ids:
                continue  # Already warned during resolution
            tag_groups[tags].extend(device_ids)
            for did in device_ids:
                device_id_to_identifier[did] = identifier
        else:
            # identifier is already a device_id
            tag_groups[tags].append(identifier)
            device_id_to_identifier[identifier] = identifier

    if not tag_groups:
        print("\nERROR: No devices could be resolved. Nothing to tag.")
        sys.exit(1)

    # Preview
    total_devices = sum(len(ids) for ids in tag_groups.values())
    total_tag_sets = len(tag_groups)

    print(f"\n{'DRY RUN — ' if args.dry_run else ''}Tag Application Summary:")
    print(f"  Devices to tag:  {total_devices}")
    print(f"  Unique tag sets: {total_tag_sets}")
    if unresolved_hosts:
        print(f"  Unresolved hosts: {len(unresolved_hosts)}")
    print()

    for tags, device_ids in tag_groups.items():
        tag_display = [t.replace("FalconGroupingTags/", "") for t in tags]
        print(f"  Tags: {', '.join(tag_display)}")
        print(f"    → {len(device_ids)} device(s)")

    if args.dry_run:
        print("\n" + "=" * 60)
        print("  DRY RUN COMPLETE — no changes were made.")
        print("  Remove --dry_run to apply tags.")
        print("=" * 60)
        return

    # Apply tags
    print(f"\nApplying tags...")

    total_success = 0
    total_failed = 0
    all_errors = []
    all_device_results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_path = f"falcon_tag_results_{timestamp}.csv"

    try:
        for tags, device_ids in tag_groups.items():
            tag_list = list(tags)
            tag_display = [t.replace("FalconGroupingTags/", "") for t in tag_list]
            tag_display_str = "; ".join(tag_display)

            result = apply_tags(falcon, device_ids, tag_list, dry_run=args.dry_run,
                                batch_size=args.batch_size, rate_limit_delay=args.rate_limit_delay)
            total_success += result["success"]
            total_failed += result["failed"]
            all_errors.extend(result["errors"])

            # Enrich device results with identifier and tag info
            for dr in result["device_results"]:
                dr["identifier"] = device_id_to_identifier.get(dr["device_id"], "")
                dr["tags_display"] = tag_display_str
                all_device_results.append(dr)

            status = "✓" if result["failed"] == 0 else "✗"
            print(f"  {status} [{', '.join(tag_display)}] → {result['success']} OK, {result['failed']} failed")

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user. Saving progress...")
    except Exception as e:
        print(f"\n\n  Unexpected error: {e}. Saving progress...")
    finally:
        # Always write results — even on crash, interrupt, or partial failure
        write_results_csv(all_device_results, unresolved_hosts, results_path)

    # Summary
    print()
    print("=" * 60)
    if total_failed == 0 and not unresolved_hosts:
        print(f"  ✓ Successfully tagged {total_success} device(s).")
    else:
        print(f"  Tagged {total_success} device(s), {total_failed} failed.")
        if unresolved_hosts:
            print(f"  {len(unresolved_hosts)} hostname(s) could not be resolved.")
        for err in all_errors:
            print(f"    HTTP {err['status_code']}: {err['device_count']} device(s) — {err['errors']}")
        print(f"\n  Review {results_path} for details.")
        print("  Re-run the script with the same input — already-tagged devices are safe to retry.")
    print("=" * 60)


if __name__ == "__main__":
    main()
