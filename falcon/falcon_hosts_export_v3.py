#!/usr/bin/env python3
"""
CrowdStrike Falcon Host Exporter (v3 — with CID Labels, Host Group Names & Policy Names)
==========================================================================================
Uses the FalconPy library to authenticate with the CrowdStrike Falcon API,
retrieve all hosts, fetch their details, and enrich them with:

  - CID tenant names (via Flight Control)
  - Host group names (via Host Group API, including across child CIDs)
  - Prevention policy names and applied status
  - Sensor update policy names and applied status

Exports everything to a CSV file.

Requirements:
    pip install crowdstrike-falconpy

Usage:
    # Set environment variables (recommended):
    export FALCON_CLIENT_ID="your_client_id"
    export FALCON_CLIENT_SECRET="your_client_secret"

    # Then run:
    python falcon_hosts_export_v3.py

    # Or pass credentials directly (less secure):
    python falcon_hosts_export_v3.py --client_id YOUR_ID --client_secret YOUR_SECRET

    # Optional: specify output file and batch size
    python falcon_hosts_export_v3.py --output my_hosts.csv --batch_size 500

    # Export only hidden (suppressed) hosts
    python falcon_hosts_export_v3.py --hidden_only

    # Skip optional lookups
    python falcon_hosts_export_v3.py --skip_cid_lookup
    python falcon_hosts_export_v3.py --skip_group_lookup
    python falcon_hosts_export_v3.py --skip_policy_lookup
"""

import os
import csv
import argparse
import sys
from datetime import datetime

try:
    from falconpy import Hosts, FlightControl, HostGroup, PreventionPolicy, SensorUpdatePolicy
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
    "prevention_policy",
    "prevention_policy_applied",
    "sensor_update_policy",
    "sensor_update_policy_applied",
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
        "--skip_policy_lookup",
        action="store_true",
        default=False,
        help="Skip policy name resolution (use if you don't have Prevention/Sensor Update Policy Read access)",
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

def _fetch_groups_for_cid(auth_kwargs: dict, member_cid: str = None) -> list:
    """
    Fetch all host groups for a single CID (parent or child).
    Returns a list of group resource dicts.
    """
    kwargs = dict(auth_kwargs)
    if member_cid:
        kwargs["member_cid"] = member_cid

    try:
        hg = HostGroup(**kwargs)
    except Exception as e:
        print(f"    WARNING: Could not initialize HostGroup for CID {member_cid or 'parent'}: {e}")
        return []

    all_groups = []
    offset = 0
    limit = 500

    while True:
        response = hg.query_combined_host_groups(offset=offset, limit=limit)
        status_code = response["status_code"]

        if status_code in (401, 403):
            # No permission for this CID — skip silently
            return all_groups
        elif status_code != 200:
            return all_groups

        resources = response["body"].get("resources", [])
        if not resources:
            break

        all_groups.extend(resources)
        total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)

        if offset >= total:
            break

    return all_groups


def build_group_name_map_from_hosts(auth_kwargs: dict, host_details: list) -> dict:
    """
    Build a mapping of group identifier -> group name.

    In MSSP / Flight Control environments, host groups are defined at the
    child CID level. Hosts exported from the parent contain group IDs that
    belong to their respective child CIDs. To resolve them, this function:

      1. Collects all unique group IDs from host records
      2. Fetches host groups from the parent CID
      3. Discovers child CIDs via Flight Control
      4. Fetches host groups from each child CID (authenticating with member_cid)
      5. Indexes every group by all available identifier fields (id, group_hash)

    Returns a dict mapping group identifiers to names.
    """
    # Step 1: Collect all unique group IDs from host records
    host_group_ids = set()
    for host in host_details:
        group_ids = host.get("groups", []) or []
        if isinstance(group_ids, str):
            group_ids = [group_ids]
        host_group_ids.update(group_ids)

    if not host_group_ids:
        print("  INFO: No group IDs found in host records. Group names column will be empty.")
        return {}

    print(f"  Found {len(host_group_ids)} unique group ID(s) in host records.")

    group_map = {}
    group_count = 0

    def index_groups(groups: list):
        """Add groups to the map, indexed by every plausible identifier."""
        nonlocal group_count
        for group in groups:
            group_name = group.get("name", "")
            for key in ("id", "group_hash", "hash"):
                val = group.get(key, "")
                if val:
                    group_map[val] = group_name
                    group_map[val.lower()] = group_name
            group_count += 1

    # Step 2: Fetch host groups from the parent CID
    print("  Fetching host groups from parent CID...")
    parent_groups = _fetch_groups_for_cid(auth_kwargs)
    index_groups(parent_groups)
    print(f"    Found {len(parent_groups)} group(s) at parent level.")

    # Check if we already resolved everything
    resolved = sum(1 for gid in host_group_ids if gid in group_map or gid.lower() in group_map)
    if resolved >= len(host_group_ids):
        print(f"✓ Resolved all {resolved} group ID(s) from parent CID.")
        return group_map

    # Step 3: Discover child CIDs via Flight Control and fetch their groups
    print(f"  {len(host_group_ids) - resolved} group ID(s) unresolved. Checking child CIDs...")

    try:
        fc = FlightControl(**auth_kwargs)
        all_child_cids = []
        offset = 0

        while True:
            response = fc.query_children(offset=offset, limit=500)
            if response["status_code"] != 200:
                print("    WARNING: Could not query child CIDs. Some group names may be missing.")
                break

            resources = response["body"].get("resources", [])
            if not resources:
                break

            all_child_cids.extend(resources)
            total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
            offset += len(resources)
            if len(all_child_cids) >= total:
                break

        if all_child_cids:
            # Get child CID details to obtain actual child_cid values
            child_cid_values = []
            for i in range(0, len(all_child_cids), 500):
                batch = all_child_cids[i : i + 500]
                resp = fc.get_children(ids=batch)
                if resp["status_code"] == 200:
                    for child in resp["body"].get("resources", []):
                        ccid = child.get("child_cid", "")
                        if ccid:
                            child_cid_values.append(ccid)

            print(f"  Found {len(child_cid_values)} child CID(s). Fetching their host groups...")

            for idx, ccid in enumerate(child_cid_values, 1):
                child_groups = _fetch_groups_for_cid(auth_kwargs, member_cid=ccid)
                if child_groups:
                    index_groups(child_groups)
                    print(f"    Child {idx}/{len(child_cid_values)} ({ccid[:8]}...): {len(child_groups)} group(s)")

                # Check if we've resolved everything — stop early if so
                resolved = sum(1 for gid in host_group_ids if gid in group_map or gid.lower() in group_map)
                if resolved >= len(host_group_ids):
                    break
        else:
            print("    No child CIDs found.")

    except Exception as e:
        print(f"    WARNING: Flight Control lookup failed: {e}")

    # Final tally
    resolved = sum(1 for gid in host_group_ids if gid in group_map or gid.lower() in group_map)
    print(f"✓ Resolved {resolved} of {len(host_group_ids)} host group ID(s) across {group_count} total group(s).")

    if resolved < len(host_group_ids):
        unresolved = [gid for gid in host_group_ids if gid not in group_map and gid.lower() not in group_map]
        print(f"  WARNING: {len(unresolved)} group ID(s) could not be resolved (may be deleted or inaccessible).")
        print(f"           Sample: {unresolved[:3]}")

    return group_map


def enrich_with_group_names(host_details: list, group_map: dict) -> list:
    """
    Add a 'group_names' field to each host record.
    Resolves group IDs from the 'groups' field to their human-readable names.
    Multiple groups are joined with '; '.
    Unresolved IDs are omitted (they remain visible in the 'groups' column).
    """
    resolved_count = 0
    unresolved_ids = set()

    for host in host_details:
        group_ids = host.get("groups", []) or []
        if isinstance(group_ids, str):
            group_ids = [group_ids]

        names = []
        for gid in group_ids:
            # Try exact match first, then lowercase
            name = group_map.get(gid) or group_map.get(gid.lower(), "")
            if name:
                names.append(name)
                resolved_count += 1
            else:
                unresolved_ids.add(gid)

        host["group_names"] = "; ".join(names) if names else ""

    if unresolved_ids:
        print(f"  WARNING: {len(unresolved_ids)} unique group ID(s) from host records could not be resolved.")
        sample = list(unresolved_ids)[:3]
        print(f"           Sample unresolved IDs: {sample}")
        if group_map:
            sample_keys = list(group_map.keys())[:3]
            print(f"           Sample group map keys: {sample_keys}")
        print("           This may indicate the 'groups' field uses a different ID format than the Host Group API.")

    return host_details


# ── Policy Name Resolution ────────────────────────────────────────────────────

def _fetch_all_policies(policy_class, auth_kwargs: dict, label: str) -> dict:
    """
    Fetch all policies of a given type and return a dict mapping policy_id -> policy_name.
    Works for both parent and child CIDs in MSSP environments.

    Uses query_combined_policies (or query_combined_policies_v2 for SensorUpdatePolicy)
    to get policy details including names.
    """
    policy_map = {}

    try:
        policy_client = policy_class(**auth_kwargs)
    except Exception as e:
        print(f"  WARNING: Could not initialize {label} policy client: {e}")
        return policy_map

    offset = 0
    limit = 500

    while True:
        # SensorUpdatePolicy uses query_combined_policies_v2 for uninstall protection support
        if policy_class == SensorUpdatePolicy:
            response = policy_client.query_combined_policies_v2(offset=offset, limit=limit)
        else:
            response = policy_client.query_combined_policies(offset=offset, limit=limit)

        status_code = response["status_code"]

        if status_code in (401, 403):
            print(f"  WARNING: No {label} Policy Read permission (HTTP {status_code}).")
            return policy_map
        elif status_code != 200:
            print(f"  WARNING: {label} policy query failed (HTTP {status_code}).")
            return policy_map

        resources = response["body"].get("resources", [])
        if not resources:
            break

        for policy in resources:
            pid = policy.get("id", "")
            pname = policy.get("name", "")
            if pid:
                policy_map[pid] = pname

        total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)
        if offset >= total:
            break

    return policy_map


def build_policy_name_maps(auth_kwargs: dict, host_details: list) -> tuple:
    """
    Build mappings of policy_id -> policy_name for prevention and sensor update policies.

    Like host groups, policies may be defined at the child CID level in MSSP environments.
    This function:
      1. Collects all unique policy IDs from host records
      2. Fetches policies from the parent CID
      3. If unresolved IDs remain, discovers child CIDs and fetches their policies

    Returns a tuple of (prevention_map, sensor_update_map).
    """
    # Step 1: Collect unique policy IDs from host records
    prevention_ids = set()
    sensor_update_ids = set()

    for host in host_details:
        policies = host.get("device_policies", {}) or {}

        prev_policy = policies.get("prevention", {}) or {}
        prev_id = prev_policy.get("policy_id", "")
        if prev_id:
            prevention_ids.add(prev_id)

        su_policy = policies.get("sensor_update", {}) or {}
        su_id = su_policy.get("policy_id", "")
        if su_id:
            sensor_update_ids.add(su_id)

    print(f"  Found {len(prevention_ids)} unique prevention policy ID(s) "
          f"and {len(sensor_update_ids)} sensor update policy ID(s) in host records.")

    if not prevention_ids and not sensor_update_ids:
        return {}, {}

    # Step 2: Fetch policies from parent CID
    print("  Fetching policies from parent CID...")
    prevention_map = _fetch_all_policies(PreventionPolicy, auth_kwargs, "Prevention")
    sensor_update_map = _fetch_all_policies(SensorUpdatePolicy, auth_kwargs, "Sensor Update")

    prev_resolved = sum(1 for pid in prevention_ids if pid in prevention_map)
    su_resolved = sum(1 for pid in sensor_update_ids if pid in sensor_update_map)
    print(f"    Parent: resolved {prev_resolved}/{len(prevention_ids)} prevention, "
          f"{su_resolved}/{len(sensor_update_ids)} sensor update")

    # Check if we need child CIDs
    all_resolved = (prev_resolved >= len(prevention_ids) and su_resolved >= len(sensor_update_ids))

    if not all_resolved:
        unresolved_count = (len(prevention_ids) - prev_resolved) + (len(sensor_update_ids) - su_resolved)
        print(f"  {unresolved_count} policy ID(s) unresolved. Checking child CIDs...")

        try:
            fc = FlightControl(**auth_kwargs)
            all_child_cids = []
            offset = 0

            while True:
                response = fc.query_children(offset=offset, limit=500)
                if response["status_code"] != 200:
                    print("    WARNING: Could not query child CIDs for policy resolution.")
                    break

                resources = response["body"].get("resources", [])
                if not resources:
                    break

                all_child_cids.extend(resources)
                total = response["body"].get("meta", {}).get("pagination", {}).get("total", 0)
                offset += len(resources)
                if len(all_child_cids) >= total:
                    break

            if all_child_cids:
                child_cid_values = []
                for i in range(0, len(all_child_cids), 500):
                    batch = all_child_cids[i : i + 500]
                    resp = fc.get_children(ids=batch)
                    if resp["status_code"] == 200:
                        for child in resp["body"].get("resources", []):
                            ccid = child.get("child_cid", "")
                            if ccid:
                                child_cid_values.append(ccid)

                print(f"  Found {len(child_cid_values)} child CID(s). Fetching their policies...")

                for idx, ccid in enumerate(child_cid_values, 1):
                    child_kwargs = dict(auth_kwargs)
                    child_kwargs["member_cid"] = ccid

                    child_prev = _fetch_all_policies(PreventionPolicy, child_kwargs, "Prevention")
                    child_su = _fetch_all_policies(SensorUpdatePolicy, child_kwargs, "Sensor Update")

                    if child_prev or child_su:
                        prevention_map.update(child_prev)
                        sensor_update_map.update(child_su)
                        print(f"    Child {idx}/{len(child_cid_values)} ({ccid[:8]}...): "
                              f"{len(child_prev)} prevention, {len(child_su)} sensor update")

                    # Check if fully resolved — stop early
                    prev_resolved = sum(1 for pid in prevention_ids if pid in prevention_map)
                    su_resolved = sum(1 for pid in sensor_update_ids if pid in sensor_update_map)
                    if prev_resolved >= len(prevention_ids) and su_resolved >= len(sensor_update_ids):
                        break

        except Exception as e:
            print(f"    WARNING: Child CID policy lookup failed: {e}")

    # Final tally
    prev_resolved = sum(1 for pid in prevention_ids if pid in prevention_map)
    su_resolved = sum(1 for pid in sensor_update_ids if pid in sensor_update_map)
    print(f"  ✓ Resolved {prev_resolved}/{len(prevention_ids)} prevention "
          f"and {su_resolved}/{len(sensor_update_ids)} sensor update policy ID(s).")

    return prevention_map, sensor_update_map


def enrich_with_policy_names(host_details: list, prevention_map: dict, sensor_update_map: dict) -> list:
    """
    Inject prevention_policy, prevention_policy_applied, sensor_update_policy,
    and sensor_update_policy_applied columns into each host record.
    """
    for host in host_details:
        policies = host.get("device_policies", {}) or {}

        # Prevention policy
        prev_policy = policies.get("prevention", {}) or {}
        prev_id = prev_policy.get("policy_id", "")
        host["prevention_policy"] = prevention_map.get(prev_id, prev_id)  # fallback to ID
        host["prevention_policy_applied"] = str(prev_policy.get("applied", ""))

        # Sensor update policy
        su_policy = policies.get("sensor_update", {}) or {}
        su_id = su_policy.get("policy_id", "")
        host["sensor_update_policy"] = sensor_update_map.get(su_id, su_id)  # fallback to ID
        host["sensor_update_policy_applied"] = str(su_policy.get("applied", ""))

    return host_details

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
    print("  v3 — CID Labels, Host Groups & Policy Names")
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

    # Step 3: Retrieve all host IDs (with optional filter)
    host_ids = get_all_host_ids(falcon, fql_filter=args.filter, sort=args.sort, hidden_only=args.hidden_only)

    if not host_ids:
        print("No hosts found matching the criteria.")
        sys.exit(0)

    # Step 4: Fetch full details for each host
    host_details = get_host_details(falcon, host_ids, args.batch_size)

    # Step 5: Enrich host records with CID names
    if cid_map:
        host_details = enrich_with_cid_names(host_details, cid_map)
    else:
        for host in host_details:
            host.setdefault("cid_name", "")

    # Step 6: Resolve host group names from IDs found in host records (unless skipped)
    group_map = {}
    if not args.skip_group_lookup:
        print("Resolving host group names...")
        group_map = build_group_name_map_from_hosts(auth_kwargs, host_details)
    else:
        print("Skipping host group name resolution (--skip_group_lookup)")

    # Step 7: Enrich host records with host group names
    host_details = enrich_with_group_names(host_details, group_map)

    # Step 8: Resolve policy names (unless skipped)
    prevention_map = {}
    sensor_update_map = {}
    if not args.skip_policy_lookup:
        print("Resolving policy names...")
        prevention_map, sensor_update_map = build_policy_name_maps(auth_kwargs, host_details)
    else:
        print("Skipping policy name resolution (--skip_policy_lookup)")

    # Step 9: Enrich host records with policy names
    host_details = enrich_with_policy_names(host_details, prevention_map, sensor_update_map)

    # Step 10: Export to CSV
    export_to_csv(host_details, args.output, all_fields=args.all_fields)

    print("=" * 60)
    print("  Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()
