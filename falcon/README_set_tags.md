# CrowdStrike Falcon Grouping Tag Setter

Bulk-apply **FalconGroupingTags** to hosts from a CSV input file. Tags are **appended** — existing tags on each host are preserved. The script handles hostname-to-device-ID resolution, MSSP multi-tenant environments, rate limiting, and produces a detailed results log.

Built with the [FalconPy](https://falconpy.io/) SDK.

---

## Prerequisites

- Python 3.7+
- The `crowdstrike-falconpy` package
- A CrowdStrike Falcon API key with **Hosts: Read + Write** scope

## Installation

```bash
pip install crowdstrike-falconpy
```

---

## Input CSV Format

The input file is a standard CSV with two columns — one to identify the host and one for the tags to apply.

### Using Hostnames (recommended)

```csv
hostname,tags
WORKSTATION-01,environment-prod;department-finance
SERVER-02,environment-staging
LAPTOP-03,department-IT;location-NYC;vip
```

### Using Device IDs

```csv
device_id,tags
a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8,environment-prod;department-finance
f8e7d6c5b4a3f8e7d6c5b4a3f8e7d6c5,environment-staging
```

### CSV Rules

- First row **must** be a header row
- The ID column can be `hostname` or `device_id` (auto-detected), or any column name specified with `--id_column`
- Tags are separated by **semicolons** by default (change with `--tag_separator`)
- The `FalconGroupingTags/` prefix is **optional** — the script adds it automatically if missing, so `environment-prod` and `FalconGroupingTags/environment-prod` are treated identically
- Rows with an empty identifier or empty tags are skipped with a warning
- UTF-8, UTF-8 with BOM, and Latin-1 encoded files are all supported

### Tip

You can use the output from the companion **falcon_hosts_export_v2.py** script as a starting point. Export your hosts, add or modify the `tags` column in the CSV, then feed it into this script.

---

## Authentication

Credentials can be provided via **environment variables** (recommended) or **command-line arguments**.

### Environment Variables

```bash
export FALCON_CLIENT_ID="your_client_id"
export FALCON_CLIENT_SECRET="your_client_secret"
```

### Command-Line Arguments

```bash
python falcon_set_tags.py --input devices_tags.csv --client_id YOUR_ID --client_secret YOUR_SECRET
```

> **Note:** Environment variables only persist for the current terminal session unless added to your shell profile (`~/.zshrc` or `~/.bash_profile`).

---

## Usage

### Basic — Apply Tags

```bash
python falcon_set_tags.py --input devices_tags.csv
```

### Dry Run — Preview Without Applying

```bash
python falcon_set_tags.py --input devices_tags.csv --dry_run
```

This shows exactly which devices would be tagged and with which tags, without making any API changes.

### Specify ID Column

```bash
# Use device_id instead of hostname
python falcon_set_tags.py --input devices_tags.csv --id_column device_id
```

### Custom Tag Column or Separator

```bash
# Tag column is named "new_tags" instead of "tags"
python falcon_set_tags.py --input devices_tags.csv --tag_column new_tags

# Tags are comma-separated instead of semicolons
python falcon_set_tags.py --input devices_tags.csv --tag_separator ","
```

### Specify Cloud Region

```bash
python falcon_set_tags.py --input devices_tags.csv --base_url eu-1
```

### MSSP — Target a Specific Child CID

```bash
python falcon_set_tags.py --input devices_tags.csv --member_cid "CHILD_CID_HERE"
```

### Tune Performance for Large Batches

```bash
# Aggressive — larger batches, shorter delay
python falcon_set_tags.py --input big_file.csv --batch_size 500 --rate_limit_delay 0.2

# Conservative — smaller batches, longer delay
python falcon_set_tags.py --input big_file.csv --batch_size 50 --rate_limit_delay 2.0
```

---

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `--input` | *(required)* | Path to the input CSV file |
| `--id_column` | Auto-detect | Column identifying hosts (`hostname`, `device_id`, or custom) |
| `--tag_column` | `tags` | Column containing tags to apply |
| `--tag_separator` | `;` | Separator for multiple tags in a single cell |
| `--client_id` | `$FALCON_CLIENT_ID` | Falcon API Client ID |
| `--client_secret` | `$FALCON_CLIENT_SECRET` | Falcon API Client Secret |
| `--base_url` | `auto` | Falcon cloud region (`us-1`, `us-2`, `eu-1`, `us-gov-1`) |
| `--member_cid` | `$FALCON_MEMBER_CID` | Target a specific child CID (MSSP) |
| `--dry_run` | `false` | Preview changes without applying |
| `--batch_size` | `100` | Device IDs per `update_device_tags` API call |
| `--rate_limit_delay` | `0.5` | Seconds to wait between API calls |

---

## How It Works

### Step-by-Step Flow

1. **Read CSV** — Parses the input file, auto-detects the ID column, normalizes tags (adds `FalconGroupingTags/` prefix if missing), and validates all rows.

2. **Authenticate** — Creates a `Hosts` Service Class instance and verifies credentials.

3. **Resolve Hostnames** *(if using hostnames)* — Converts hostnames to device IDs:
   - **Small batches (≤50 hosts):** Resolves one-by-one via FQL filter — faster than a bulk fetch for small lists.
   - **Large batches (>50 hosts):** Fetches ALL hosts from the tenant in bulk (scroll pagination + batch detail fetch), then matches hostnames locally in memory. This reduces 20,000 individual API calls down to ~50 calls total.

4. **Group by Tag Set** — Devices receiving the same set of tags are grouped together for efficient batching (one API call can tag many devices at once).

5. **Apply Tags** — Calls `update_device_tags` with `action_name="add"` in configurable batches. The `add` action **appends** tags — existing tags on the host are never removed or replaced.

6. **Write Results CSV** — Every device gets a row in `falcon_tag_results_<timestamp>.csv` recording its outcome.

### Tag Behavior

The `add` action is **idempotent**:

- If a host already has the tag, it's kept as-is (no duplicates created)
- If a host has other tags, they're preserved — only the new tags are added
- Re-running the same input file is always safe

This means if a run partially fails, you can re-run the exact same command. Already-tagged devices are unaffected, and previously-failed devices get retried.

---

## Results CSV

Every run produces a `falcon_tag_results_<timestamp>.csv` file that logs the outcome for every device:

```csv
identifier,device_id,tags,status,error
WORKSTATION-01,abc123...,environment-prod; department-finance,success,
SERVER-02,def456...,environment-staging,success,
LAPTOP-03,ghi789...,department-IT; location-NYC,failed,HTTP 403: [{'message': 'access denied'}]
UNKNOWN-HOST,,,unresolved,No host found for hostname
```

### Status Values

| Status | Meaning |
|---|---|
| `success` | Tags applied successfully (HTTP 200 or 202) |
| `failed` | API call failed — error details in the `error` column |
| `unresolved` | Hostname could not be found in the tenant |
| `dry_run` | Dry run mode — no changes were made |

### Crash Safety

The results CSV is written inside a `finally` block. Even if the script is interrupted (Ctrl+C), encounters a network error, or crashes unexpectedly, all progress collected up to that point is saved to the results file. Nothing is lost.

---

## Handling Large Batches

The script is optimized for large-scale operations (20,000+ hosts):

| Hosts | Estimated Time | Notes |
|---|---|---|
| 1,000 | ~15 seconds | Default settings work well |
| 20,000 | ~2 minutes | Bulk hostname resolution kicks in automatically |
| 50,000 | ~5 minutes | Consider `--batch_size 200` |
| 100,000 | ~10 minutes | Consider `--batch_size 500 --rate_limit_delay 0.2` |

### Performance Features

- **Bulk hostname resolution** — For >50 hostnames, all hosts are fetched once in bulk instead of individual lookups
- **Tag set grouping** — Devices with identical tags are batched into single API calls
- **Rate limit handling** — Automatic retry with exponential backoff (2s, 3s, 5s, 9s, 17s) on HTTP 429
- **Configurable pacing** — `--batch_size` and `--rate_limit_delay` let you tune throughput vs. rate limit risk
- **Progress reporting** — Prints progress every 10 batches for large runs

---

## MSSP / Flight Control Notes

When authenticated at the **parent CID level**, hostname resolution searches across all child CIDs. If the same hostname exists in two different child CIDs, both devices are found and both get tagged.

To restrict tagging to a specific child CID:

```bash
python falcon_set_tags.py --input devices_tags.csv --member_cid "CHILD_CID_HERE"
```

Alternatively, use `device_id` instead of `hostname` in your CSV — device IDs are globally unique, so there's no ambiguity.

---

## API Scope Required

| Scope | Permission | Purpose |
|---|---|---|
| **Hosts** | Read | Resolve hostnames to device IDs |
| **Hosts** | Write | Apply FalconGroupingTags |

### How to Add API Scopes

1. Log in to the Falcon console
2. Navigate to **Support and resources → API clients and keys**
3. Edit your API client
4. Enable **Read** and **Write** checkboxes for the **Hosts** scope

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `HTTP 401` | Invalid credentials | Verify Client ID and Client Secret |
| `HTTP 403` on tagging | Missing Hosts Write scope | Add **Hosts: Write** to your API key |
| `No host found for hostname` | Host doesn't exist or is hidden | Verify hostname spelling; hidden hosts won't appear in standard queries |
| `Rate limited (HTTP 429)` | Too many API calls | Increase `--rate_limit_delay` or decrease `--batch_size` |
| Hostname matches multiple devices | Same hostname in multiple CIDs | Expected in MSSP — use `--member_cid` to scope to one CID, or use `device_id` |
| Script interrupted mid-run | Ctrl+C or network error | Results CSV is saved automatically; re-run the same input file safely |
| Tags not visible in console immediately | API accepted (202) but processing | FalconGroupingTags may take a few minutes to appear in the console |

---

## Example Output

```
============================================================
  CrowdStrike Falcon Grouping Tag Setter
============================================================

Reading input file: devices_tags.csv
  Auto-detected ID column: 'hostname'
  ✓ Loaded 500 record(s) from CSV.

Authenticating...
✓ Successfully authenticated to CrowdStrike Falcon API
  Resolving 500 hostname(s) to device IDs...
    Large batch detected (500 hosts). Using bulk resolution...
    Fetching all host IDs from tenant...
    Found 12000 total host(s) in tenant.
    Fetched details: 12000/12000...
  ✓ Resolved 498 device ID(s) from 496 hostname(s).

Tag Application Summary:
  Devices to tag:  498
  Unique tag sets: 3
  Unresolved hosts: 4

  Tags: environment-prod, department-finance
    → 200 device(s)
  Tags: environment-staging
    → 150 device(s)
  Tags: department-IT, location-NYC
    → 148 device(s)

Applying tags...
  ✓ [environment-prod, department-finance] → 200 OK, 0 failed
  ✓ [environment-staging] → 150 OK, 0 failed
  ✓ [department-IT, location-NYC] → 148 OK, 0 failed
  Results log: falcon_tag_results_20260330_143022.csv

============================================================
  Tagged 498 device(s), 0 failed.
  4 hostname(s) could not be resolved.

  Review falcon_tag_results_20260330_143022.csv for details.
  Re-run the script with the same input — already-tagged devices are safe to retry.
============================================================
```

---

## License

This script is provided as-is for use with your CrowdStrike Falcon tenant. See [FalconPy's license](https://github.com/CrowdStrike/falconpy/blob/main/LICENSE) for SDK terms.
