#!/usr/bin/env python3
"""
GCP Security Logging Estimator — SCC Premium (ETD / SHA)

A Flask web application that estimates 30-day Cloud Logging ingestion costs
for security log sources recommended by Google Cloud Security Command Center
Premium.  It queries live metrics from the Cloud Monitoring API over a 7-day
baseline window, extrapolates to 30 days, and applies per-log-type size
estimates at $0.50/GiB (standard Cloud Logging ingestion pricing).

Supports three estimation scopes:
    - Single GCP project
    - All projects under a GCP resource folder
    - All projects in a GCP organization

Authentication:
    1. Service account key file (JWT) — pass via  -k / --key-file  or set
       the GOOGLE_APPLICATION_CREDENTIALS environment variable.
    2. gcloud Application Default Credentials (ADC) — run
       ``gcloud auth application-default login`` before starting.

Usage:
    # Start with a service account key:
    python3 app.py -k /path/to/sa-key.json

    # Start with gcloud ADC (must already be logged in):
    python3 app.py

    # Custom host / port, debug mode:
    python3 app.py -k sa.json -H 0.0.0.0 -p 8080 -d

Required IAM permissions:
    - monitoring.timeSeries.list       (on every target project)
    - resourcemanager.projects.list    (on org/folder, for org-wide scans)
"""

import argparse
import json
import os
import sys
import time

from flask import Flask, render_template, request

# Google Cloud client libraries — imported at module level so import errors
# surface immediately rather than at first request time.
from google.cloud import monitoring_v3
from google.cloud import resourcemanager_v3
from google.auth import default as get_default_credentials
from google.auth.exceptions import DefaultCredentialsError
from google.auth.transport.requests import Request as AuthRequest

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    """Parse command-line arguments.

    Returns:
        argparse.Namespace with the following attributes:
            key_file (str|None) — path to a service account JSON key file
            host     (str)      — Flask listen address (default 127.0.0.1)
            port     (int)      — Flask listen port    (default 5000)
            debug    (bool)     — run Flask in debug mode
    """
    parser = argparse.ArgumentParser(
        description=(
            "GCP Security Logging Estimator — estimate 30-day Cloud Logging "
            "ingestion costs for SCC Premium (ETD / SHA) log sources."
        ),
        epilog=(
            "Authentication priority:\n"
            "  1. --key-file / -k  (service account JWT)\n"
            "  2. GOOGLE_APPLICATION_CREDENTIALS env var\n"
            "  3. gcloud Application Default Credentials\n\n"
            "If none are valid the app will print an error and exit.\n\n"
            "Examples:\n"
            "  %(prog)s -k ~/keys/scc-reader.json\n"
            "  %(prog)s -k sa.json -p 8080 -H 0.0.0.0 -d\n"
            "  %(prog)s                          # uses gcloud ADC\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # -- Authentication --
    parser.add_argument(
        "-k", "--key-file",
        metavar="PATH",
        help="Path to a GCP service account JSON key file (JWT). "
             "Overrides GOOGLE_APPLICATION_CREDENTIALS.",
    )

    # -- Server options --
    parser.add_argument(
        "-H", "--host",
        default="127.0.0.1",
        help="Host address to bind the Flask server (default: 127.0.0.1).",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5000,
        help="Port number for the Flask server (default: 5000).",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Run Flask in debug mode with auto-reload.",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Service account key validation
# ---------------------------------------------------------------------------

def validate_key_file(path):
    """Validate that *path* is a readable service account JSON key.

    Checks performed:
        1. File exists and is readable.
        2. Contents are valid JSON.
        3. ``type`` field equals ``service_account``.
        4. A short-lived access token can be minted (proves the key is not
           revoked and the SA exists).

    Args:
        path: Absolute or relative filesystem path to the key file.

    Returns:
        dict with ``valid`` (bool), ``identity`` (str), ``project`` (str|None),
        and ``error`` (str|None).
    """
    # -- Step 1: file exists? --
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        return {
            "valid": False,
            "error": f"Key file not found: {expanded}",
        }

    # -- Step 2 & 3: valid JSON with type=service_account? --
    try:
        with open(expanded) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        return {
            "valid": False,
            "error": f"Cannot read key file: {exc}",
        }

    key_type = data.get("type")
    if key_type != "service_account":
        return {
            "valid": False,
            "error": (
                f"Key file type is '{key_type}', expected 'service_account'. "
                "Authorized-user JSON files cannot be used with --key-file."
            ),
        }

    identity = data.get("client_email", "unknown")
    project = data.get("project_id")

    # -- Step 4: mint a token to prove the key is live --
    try:
        from google.oauth2 import service_account as sa_module
        creds = sa_module.Credentials.from_service_account_file(
            expanded,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        creds.refresh(AuthRequest())          # raises if key is revoked / SA deleted
    except Exception as exc:
        return {
            "valid": False,
            "error": f"Key file loaded but token mint failed: {exc}",
            "identity": identity,
            "project": project,
        }

    return {
        "valid": True,
        "identity": identity,
        "project": project,
        "path": expanded,
    }


def setup_auth(args):
    """Resolve and validate GCP credentials based on CLI args and env.

    Priority order:
        1. ``--key-file`` / ``-k`` CLI argument
        2. ``GOOGLE_APPLICATION_CREDENTIALS`` environment variable
        3. gcloud Application Default Credentials

    If a key file is explicitly passed (priority 1) and validation fails,
    the process prints a detailed error with alternative auth options and
    exits immediately — the app must not start with bad explicit credentials.

    For priorities 2 and 3 we still validate, but failure is non-fatal at
    startup; the UI will show the auth-error banner instead.
    """
    # -- Priority 1: explicit --key-file flag --
    if args.key_file:
        result = validate_key_file(args.key_file)
        if result["valid"]:
            # Point the standard env var at the validated file so all Google
            # Cloud client libraries pick it up automatically.
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = result["path"]
            print(f"[auth] Service account validated: {result['identity']}")
            if result.get("project"):
                print(f"[auth] Default project: {result['project']}")
            return
        else:
            # Explicit key file failed — hard exit with guidance.
            print(f"\nERROR: Service account key validation failed.", file=sys.stderr)
            print(f"  Reason: {result['error']}\n", file=sys.stderr)
            print("Alternative authentication options:", file=sys.stderr)
            print("  1. Fix the key file and re-run:", file=sys.stderr)
            print(f"       python3 {sys.argv[0]} -k /path/to/valid-key.json", file=sys.stderr)
            print("  2. Use gcloud ADC instead (no --key-file):", file=sys.stderr)
            print("       gcloud auth application-default login", file=sys.stderr)
            print(f"       python3 {sys.argv[0]}", file=sys.stderr)
            print("  3. Set the env var directly:", file=sys.stderr)
            print("       export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json", file=sys.stderr)
            print(f"       python3 {sys.argv[0]}\n", file=sys.stderr)
            sys.exit(1)

    # -- Priority 2: GOOGLE_APPLICATION_CREDENTIALS env var --
    env_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env_path:
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.expanduser(env_path)
        print(f"[auth] Using GOOGLE_APPLICATION_CREDENTIALS={os.environ['GOOGLE_APPLICATION_CREDENTIALS']}")
        return

    # -- Priority 3: gcloud ADC (validated lazily at first API call) --
    try:
        creds, project = get_default_credentials()
        identity = (
            getattr(creds, "service_account_email", None)
            or getattr(creds, "signer_email", None)
            or "gcloud-user"
        )
        print(f"[auth] Using gcloud ADC ({identity}, project={project})")
    except DefaultCredentialsError:
        # No credentials at all — print guidance but don't exit.  The UI will
        # show the auth-error banner so the user can still see the form.
        print(
            "\nWARNING: No GCP credentials found.  The app will start but "
            "API calls will fail.\n"
            "  Fix with one of:\n"
            "    python3 app.py -k /path/to/sa-key.json\n"
            "    gcloud auth application-default login\n"
            "    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\n",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Expand tilde early (covers env var set before this script runs)
# ---------------------------------------------------------------------------

if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.expanduser(
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
    )

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Log ingestion sources for SCC Premium — ETD and SHA
#
# Each entry in LOG_SOURCES describes one log type the estimator can project:
#
#   key                 — unique identifier; matches HTML form checkbox values
#   label               — human-readable name shown in the UI
#   category            — must_have | recommended | optional  (drives UI grouping)
#   description         — tooltip / help text for the UI
#   metric              — Cloud Monitoring metric type to query
#   metric_label_filter — (optional) extra filter appended to the API call to
#                         isolate a specific log within a shared metric
#   size_kb             — estimated kilobytes per log entry (proxy-metric mode)
#   use_bytes           — if True, the metric already reports raw bytes and
#                         size_kb is ignored
#   always_on           — if True, the log is always enabled (no user action)
#   packets_per_record  — (VPC Flow only) heuristic divisor converting packet
#                         counts into estimated flow-log records
#   supports_sampling   — (VPC Flow only) whether the sampling-rate slider
#                         should apply to this source
#   default_sampling    — (VPC Flow only) pre-selected sampling rate in the UI
#   manual_only         — if True, the source cannot be estimated via metrics
#                         and is shown as informational-only in the UI
#
# Categories align with the ETD/SHA best-practices guidance:
#   must_have    — Always ON, no extra Cloud Logging cost.  Admin Activity and
#                  System Event audit logs cannot be disabled.
#   recommended  — Highly recommended to enable for full ETD threat detection.
#                  These are OFF by default and incur Cloud Logging charges.
#   optional     — Enable based on environment and specific needs.
# ---------------------------------------------------------------------------

LOG_SOURCES = [
    # === MUST HAVE (Always ON — no user action, no extra Logging cost) ===
    {
        "key": "admin_activity",
        "label": "Cloud Audit Logs — Admin Activity",
        "category": "must_have",
        "description": (
            "Detects unauthorized config changes, service account manipulation, "
            "and privilege escalation. Always enabled."
        ),
        # Use byte_count so we report *actual* ingestion, not an estimate.
        "metric": "logging.googleapis.com/byte_count",
        "metric_label_filter": (
            'metric.label."log" = "cloudaudit.googleapis.com%2Factivity"'
        ),
        "use_bytes": True,   # metric value is raw bytes — no KB multiplier
        "always_on": True,
    },
    {
        "key": "system_event",
        "label": "Cloud Audit Logs — System Event",
        "category": "must_have",
        "description": "Google Cloud system actions on your resources. Always enabled.",
        "metric": "logging.googleapis.com/byte_count",
        "metric_label_filter": (
            'metric.label."log" = "cloudaudit.googleapis.com%2Fsystem_event"'
        ),
        "use_bytes": True,
        "always_on": True,
    },

    # === HIGHLY RECOMMENDED (OFF by default — enables broader ETD detection) ===
    {
        "key": "dns",
        "label": "Cloud DNS Logs",
        "category": "recommended",
        "description": (
            "Detects DNS tunneling, C2 beaconing, and cryptomining pool "
            "connections.  Enable on all VPC networks."
        ),
        # Proxy metric: each DNS query ≈ one log entry.
        "metric": "dns.googleapis.com/query/count",
        "size_kb": 0.5,   # avg ~500 bytes per DNS log entry
    },
    {
        "key": "vpc_flow",
        "label": "VPC Flow Logs",
        "category": "recommended",
        "description": (
            "Enables investigation of network ETD findings in Logs Explorer. "
            "ETD already analyzes an internal VPC Flow data stream at no cost, "
            "but exporting to Cloud Logging lets you query raw flow data."
        ),
        # Proxy metric: packet count → estimated flow records.
        "metric": "compute.googleapis.com/instance/network/received_packets_count",
        "size_kb": 1.5,              # avg ~1.5 KB per flow-log record
        "packets_per_record": 500,   # heuristic: ~500 pkts per record @ 5s agg
        "supports_sampling": True,   # UI shows sampling-rate slider
        "default_sampling": 0.5,     # pre-selected slider value
    },
    {
        "key": "gcs_data_access",
        "label": "GCS Data Access Audit Logs",
        "category": "recommended",
        "description": "Tracks who reads/downloads files in Cloud Storage buckets.",
        # Proxy metric: each GCS API call ≈ one audit-log entry.
        "metric": "storage.googleapis.com/api/request_count",
        "size_kb": 1.5,   # Data Access entries carry identity + resource metadata
    },
    {
        "key": "bq_data_access",
        "label": "BigQuery Data Access Audit Logs",
        "category": "recommended",
        "description": (
            "Required for ETD to detect anomalous table exports and data "
            "exfiltration."
        ),
        "metric": "bigquery.googleapis.com/query/count",
        "size_kb": 1.2,
    },
    {
        "key": "cloudsql_data_access",
        "label": "Cloud SQL Data Access Audit Logs",
        "category": "recommended",
        "description": "Monitors database connections for unauthorized data access.",
        # Proxy metric: connection count as a rough lower bound.
        "metric": "cloudsql.googleapis.com/database/network/connections",
        "size_kb": 1.0,
    },

    # === OPTIONAL (environment-specific) ===
    {
        "key": "workspace",
        "label": "Google Workspace Logs",
        "category": "optional",
        "description": (
            "Detects threats related to Workspace user accounts. "
            "Requires org-level SCC activation and Workspace log streaming "
            "to Cloud Logging."
        ),
        "manual_only": True,   # cannot be estimated via Cloud Monitoring
    },
]

# Fast lookup map:  key → source dict.
LOG_SOURCE_MAP = {s["key"]: s for s in LOG_SOURCES}

# Pricing and unit constants.
COST_PER_GIB = 0.50           # standard Cloud Logging ingestion rate
KB_PER_GIB = 1_048_576        # 1024 * 1024
BYTES_PER_GIB = 1_073_741_824 # 1024 ** 3


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

def get_auth_info():
    """Detect the active GCP credential and return a status dict for the UI.

    Returns:
        dict with keys:
            method   — "service_account" | "adc" | "none"
            valid    — bool
            identity — str  (email or label)
            project  — str | None  (default project from credential)
            file     — str | None  (path, if SA key)
            error    — str | None  (human-readable failure reason)
    """
    # Check 1: Is GOOGLE_APPLICATION_CREDENTIALS set and pointing at a file?
    sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if sa_path and os.path.isfile(sa_path):
        try:
            with open(sa_path) as fh:
                data = json.load(fh)
            return {
                "method": "service_account",
                "identity": data.get("client_email", "unknown"),
                "project": data.get("project_id"),
                "file": sa_path,
                "valid": True,
            }
        except (json.JSONDecodeError, OSError):
            return {
                "method": "service_account",
                "valid": False,
                "error": f"Invalid key file: {sa_path}",
            }

    # Check 2: Can the default credential chain resolve?
    try:
        credentials, project = get_default_credentials()
        identity = (
            getattr(credentials, "service_account_email", None)
            or getattr(credentials, "signer_email", None)
            or "gcloud ADC"
        )
        return {
            "method": "adc",
            "identity": identity,
            "project": project,
            "valid": True,
        }
    except DefaultCredentialsError as exc:
        return {"method": "none", "valid": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Org / folder project discovery
# ---------------------------------------------------------------------------

def list_org_projects(org_id):
    """Return a list of ``{project_id, display_name}`` dicts for every active
    project directly or transitively under *org_id*.

    Requires ``resourcemanager.projects.list`` on the organization.
    """
    client = resourcemanager_v3.ProjectsClient()
    query = f"parent=organizations/{org_id} state:ACTIVE"
    projects = []
    try:
        for project in client.search_projects(query=query):
            projects.append({
                "project_id": project.project_id,
                "display_name": project.display_name,
            })
    except Exception as exc:
        print(f"[error] listing org projects: {exc}")
    return projects


def list_folder_projects(folder_id):
    """Return a list of ``{project_id, display_name}`` dicts for every active
    project directly or transitively under *folder_id*.

    Requires ``resourcemanager.projects.list`` on the folder.
    """
    client = resourcemanager_v3.ProjectsClient()
    query = f"parent=folders/{folder_id} state:ACTIVE"
    projects = []
    try:
        for project in client.search_projects(query=query):
            projects.append({
                "project_id": project.project_id,
                "display_name": project.display_name,
            })
    except Exception as exc:
        print(f"[error] listing folder projects: {exc}")
    return projects


# ---------------------------------------------------------------------------
# Metric fetching and cost estimation
# ---------------------------------------------------------------------------

def fetch_metric_7d(project_id, source):
    """Query the Cloud Monitoring API for a single metric over the last 7 days.

    Args:
        project_id: GCP project to query (e.g. ``my-project``).
        source:     One entry from ``LOG_SOURCES``.

    Returns:
        float — raw summed metric value across all time-series points.
        Returns 0 on any API error (logged to stderr).
    """
    # Sources marked manual_only have no metric to query.
    if source.get("manual_only"):
        return 0

    client = monitoring_v3.MetricServiceClient()
    project_name = f"projects/{project_id}"

    # 7-day window ending now.
    now = time.time()
    interval = monitoring_v3.TimeInterval({
        "end_time": {"seconds": int(now)},
        "start_time": {"seconds": int(now - 604_800)},  # 60*60*24*7
    })

    # Build the Monitoring API filter string.
    api_filter = f'metric.type = "{source["metric"]}"'
    if source.get("metric_label_filter"):
        api_filter += f' AND {source["metric_label_filter"]}'

    try:
        results = client.list_time_series(
            name=project_name,
            filter=api_filter,
            interval=interval,
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        )
        # Sum across all returned time-series and their data points.
        total = 0
        for series in results:
            for point in series.points:
                # Metrics may report int64 or double; take whichever is non-zero.
                total += point.value.int64_value or point.value.double_value
        return total
    except Exception as exc:
        print(f"[error] fetching {source['metric']} for {project_id}: {exc}")
        return 0


def estimate_monthly_gib(source, raw_7d_total, sampling_rate=1.0):
    """Convert a 7-day raw metric total into an estimated 30-day GiB volume.

    Two estimation modes:
        * **Byte-count mode** (``use_bytes=True``): The metric already reports
          raw bytes (e.g. ``logging.googleapis.com/byte_count``).  We simply
          extrapolate and convert to GiB.
        * **Proxy-metric mode** (default): The metric reports a count
          (requests, queries, packets).  We multiply by ``size_kb`` to get an
          estimated log-entry payload, then convert to GiB.

    For VPC Flow Logs the packet count is first divided by
    ``packets_per_record`` to approximate the number of flow-log records, and
    the user-selected ``sampling_rate`` is applied.

    Args:
        source:        One entry from ``LOG_SOURCES``.
        raw_7d_total:  Raw sum from ``fetch_metric_7d``.
        sampling_rate: 0.0–1.0 multiplier for VPC Flow Log sampling.

    Returns:
        float — estimated 30-day ingestion in GiB.
    """
    # Extrapolate 7 days → 30 days.
    monthly_raw = (raw_7d_total / 7) * 30

    # -- Byte-count mode (always-on audit logs) --
    if source.get("use_bytes"):
        return monthly_raw / BYTES_PER_GIB

    # -- Proxy-metric mode --
    entry_count = monthly_raw

    # VPC Flow: convert raw packet count → estimated flow-log records.
    if source.get("packets_per_record"):
        entry_count = monthly_raw / source["packets_per_record"]

    # Multiply estimated log entries × avg entry size → GiB.
    gib = (entry_count * source.get("size_kb", 1.0)) / KB_PER_GIB

    # Apply sampling rate for sources that support it (VPC Flow Logs).
    if source.get("supports_sampling"):
        gib *= sampling_rate

    return gib


def estimate_project(project_id, selected_keys, sampling_rate):
    """Run cost estimates for every selected log source in a single project.

    Args:
        project_id:    GCP project ID to scan.
        selected_keys: List of ``LOG_SOURCES`` key strings chosen by the user.
        sampling_rate: VPC Flow Log sampling rate (0.0–1.0).

    Returns:
        Tuple of (items, total_gib) where *items* is a list of per-source
        result dicts and *total_gib* is the aggregate volume.
    """
    items = []
    total_gib = 0

    for key in selected_keys:
        source = LOG_SOURCE_MAP.get(key)
        if not source or source.get("manual_only"):
            continue

        # Fetch 7-day baseline and extrapolate.
        raw_7d = fetch_metric_7d(project_id, source)
        gib = estimate_monthly_gib(source, raw_7d, sampling_rate)
        cost = gib * COST_PER_GIB

        items.append({
            "name": source["label"],
            "category": source["category"],
            "volume_gib": round(gib, 3),
            "cost": round(cost, 2),
            "always_on": source.get("always_on", False),
        })
        total_gib += gib

    return items, total_gib


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    """Main (and only) route — renders the estimator form and results.

    GET  — display the empty form with current auth status.
    POST — run estimates for the selected scope/features, render results.
    """
    # Show current credential status in the UI header.
    auth_info = get_auth_info()
    results = None

    if request.method == "POST":
        # -- Collect form inputs --
        scope = request.form.get("scope", "project")
        project_id = request.form.get("project_id", "").strip()
        org_id = request.form.get("org_id", "").strip()
        folder_id = request.form.get("folder_id", "").strip()
        selected_keys = request.form.getlist("features")

        # Clamp sampling rate to the valid 0.0–1.0 range.
        sampling_rate = float(request.form.get("vpc_sampling_rate", 0.5))
        sampling_rate = max(0.0, min(1.0, sampling_rate))

        # -- Single-project scope --
        if scope == "project":
            items, total_gib = estimate_project(
                project_id, selected_keys, sampling_rate
            )
            results = {
                "scope": "project",
                "project_id": project_id,
                "items": items,
                "total_gib": round(total_gib, 3),
                "total_cost": round(total_gib * COST_PER_GIB, 2),
                "sampling_rate": sampling_rate,
            }

        # -- Organization-wide scope --
        elif scope == "org":
            projects = list_org_projects(org_id)
            project_results, grand_total_gib = _scan_projects(
                projects, selected_keys, sampling_rate
            )
            results = {
                "scope": "org",
                "org_id": org_id,
                "projects": project_results,
                "project_count": len(projects),
                "grand_total_gib": round(grand_total_gib, 3),
                "grand_total_cost": round(grand_total_gib * COST_PER_GIB, 2),
                "sampling_rate": sampling_rate,
            }

        # -- Folder scope --
        elif scope == "folder":
            projects = list_folder_projects(folder_id)
            project_results, grand_total_gib = _scan_projects(
                projects, selected_keys, sampling_rate
            )
            results = {
                "scope": "folder",
                "folder_id": folder_id,
                "projects": project_results,
                "project_count": len(projects),
                "grand_total_gib": round(grand_total_gib, 3),
                "grand_total_cost": round(grand_total_gib * COST_PER_GIB, 2),
                "sampling_rate": sampling_rate,
            }

    return render_template(
        "index.html",
        results=results,
        log_sources=LOG_SOURCES,
        auth_info=auth_info,
    )


def _scan_projects(projects, selected_keys, sampling_rate):
    """Iterate a list of discovered projects and collect per-project estimates.

    Args:
        projects:      List of ``{project_id, display_name}`` dicts.
        selected_keys: Log-source keys chosen by the user.
        sampling_rate: VPC Flow Log sampling rate.

    Returns:
        Tuple of (project_results, grand_total_gib).
    """
    project_results = []
    grand_total_gib = 0

    for proj in projects:
        pid = proj["project_id"]
        items, proj_gib = estimate_project(pid, selected_keys, sampling_rate)
        proj_cost = proj_gib * COST_PER_GIB
        grand_total_gib += proj_gib
        project_results.append({
            "project_id": pid,
            "display_name": proj["display_name"],
            "items": items,
            "total_gib": round(proj_gib, 3),
            "total_cost": round(proj_cost, 2),
        })

    return project_results, grand_total_gib


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = parse_args()

    # Validate / configure authentication before starting the server.
    setup_auth(args)

    # Start the Flask development server.
    app.run(host=args.host, port=args.port, debug=args.debug)
