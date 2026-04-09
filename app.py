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
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request

# Google Cloud client libraries — imported at module level so import errors
# surface immediately rather than at first request time.
from google.cloud import monitoring_v3
from google.cloud import resourcemanager_v3
from google.cloud import asset_v1
from google.api_core.exceptions import NotFound, GoogleAPICallError
from google.auth import default as get_default_credentials
from google.auth.exceptions import DefaultCredentialsError
from google.auth.transport.requests import Request as AuthRequest

# Suppress noisy gRPC C-core warnings about file descriptors after fork.
# These are harmless diagnostics from the gRPC event-polling layer.
os.environ.setdefault("GRPC_POLL_STRATEGY", "epoll1")
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

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

    # -- Scope --
    parser.add_argument(
        "-o", "--org-id",
        metavar="ORG_ID",
        help="GCP Organization ID. When set, the UI defaults to org-wide "
             "scope and pre-fills the organization ID field.",
    )

    # -- Preflight --
    parser.add_argument(
        "-c", "--preflight",
        metavar="PROJECT",
        help="Run preflight checks against PROJECT (verify API access, "
             "required APIs enabled) and exit.  Useful for validating "
             "credentials before running the full estimator.",
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
        # Use log_entry_count so we can reliably query always-on audit logs.
        # The "log" label uses URL-encoded log IDs (same as Cloud Logging API).
        "metric": "logging.googleapis.com/log_entry_count",
        "metric_label_filter": (
            'metric.label."log" = "cloudaudit.googleapis.com%2Factivity"'
        ),
        "size_kb": 1.0,      # avg ~1 KB per admin activity entry
        "always_on": True,
        # No asset_types — always-on logs apply to every project.
    },
    {
        "key": "system_event",
        "label": "Cloud Audit Logs — System Event",
        "category": "must_have",
        "description": "Google Cloud system actions on your resources. Always enabled.",
        "metric": "logging.googleapis.com/log_entry_count",
        "metric_label_filter": (
            'metric.label."log" = "cloudaudit.googleapis.com%2Fsystem_event"'
        ),
        "size_kb": 0.8,
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
        "metric": "dns.googleapis.com/query/count",
        "size_kb": 0.5,
        # Cloud Asset types that indicate DNS is in use.
        "asset_types": ["dns.googleapis.com/ManagedZone"],
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
        "metric": "compute.googleapis.com/instance/network/received_packets_count",
        "size_kb": 1.5,
        "packets_per_record": 500,
        "supports_sampling": True,
        "default_sampling": 0.5,
        "network_log": True,
        "asset_types": [
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/Subnetwork",
        ],
    },
    {
        "key": "gcs_data_access",
        "label": "GCS Data Access Audit Logs",
        "category": "recommended",
        "description": "Tracks who reads/downloads files in Cloud Storage buckets.",
        "metric": "storage.googleapis.com/api/request_count",
        "size_kb": 1.5,
        "asset_types": ["storage.googleapis.com/Bucket"],
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
        "asset_types": ["bigquery.googleapis.com/Dataset"],
    },
    {
        "key": "cloudsql_data_access",
        "label": "Cloud SQL Data Access Audit Logs",
        "category": "recommended",
        "description": "Monitors database connections for unauthorized data access.",
        "metric": "cloudsql.googleapis.com/database/network/connections",
        "size_kb": 1.0,
        "asset_types": ["sqladmin.googleapis.com/Instance"],
    },
    {
        "key": "firewall",
        "label": "VPC Firewall Rules Logs",
        "category": "recommended",
        "description": (
            "Logs allowed/denied connections per firewall rule. Critical for "
            "detecting lateral movement and policy violations."
        ),
        "metric": "firewallinsights.googleapis.com/subnet/firewall_hit_count",
        "size_kb": 1.0,
        "asset_types": ["compute.googleapis.com/Firewall"],
    },
    {
        "key": "cloud_nat",
        "label": "Cloud NAT Gateway Logs",
        "category": "recommended",
        "description": (
            "Logs NAT translation events. Helps detect outbound data exfiltration "
            "and unexpected egress traffic from private VMs."
        ),
        "metric": "router.googleapis.com/nat/allocated_ports",
        "size_kb": 1.0,
        "network_log": True,
        "asset_types": ["compute.googleapis.com/Router"],
    },
    {
        "key": "iap",
        "label": "IAP (Identity-Aware Proxy) Access Logs",
        "category": "recommended",
        "description": (
            "Logs every request through Identity-Aware Proxy. Detects "
            "unauthorized access attempts to IAP-protected applications."
        ),
        "metric": "iap.googleapis.com/request_count",
        "size_kb": 0.7,
        "asset_types": ["iap.googleapis.com/Brand"],
    },
    {
        "key": "lb",
        "label": "HTTP(S) Load Balancer Logs",
        "category": "recommended",
        "description": (
            "Logs external request patterns. Provides visibility into "
            "potential DDoS, web attacks, and suspicious traffic."
        ),
        "metric": "loadbalancing.googleapis.com/https/request_count",
        "size_kb": 1.0,
        "network_log": True,
        "asset_types": [
            "compute.googleapis.com/UrlMap",
            "compute.googleapis.com/TargetHttpsProxy",
        ],
    },
    {
        "key": "artifact_registry",
        "label": "Artifact Registry Data Access Audit Logs",
        "category": "recommended",
        "description": (
            "Tracks image pulls, pushes, and vulnerability scan access. "
            "Detects supply-chain tampering and unauthorized image usage."
        ),
        # Proxy metric: API request count for Artifact Registry operations.
        "metric": "artifactregistry.googleapis.com/request_count",
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
COST_PER_GIB_NETWORK = 0.25   # discounted rate for vended network logs
KB_PER_GIB = 1_048_576        # 1024 * 1024
BYTES_PER_GIB = 1_073_741_824 # 1024 ** 3

# Concurrency: max parallel Cloud Monitoring API calls.
# Each call is I/O-bound (network), so threads work well.
MAX_WORKERS = 10

# Shared API clients — reused across requests to avoid per-call overhead
# from channel creation and auth token refresh.
_monitoring_client = None
_projects_client = None
_folders_client = None
_asset_client = None


def _get_monitoring_client():
    """Return a shared MetricServiceClient (created once, reused)."""
    global _monitoring_client
    if _monitoring_client is None:
        _monitoring_client = monitoring_v3.MetricServiceClient()
    return _monitoring_client


def _get_projects_client():
    """Return a shared ProjectsClient (created once, reused)."""
    global _projects_client
    if _projects_client is None:
        _projects_client = resourcemanager_v3.ProjectsClient()
    return _projects_client


def _get_folders_client():
    """Return a shared FoldersClient (created once, reused)."""
    global _folders_client
    if _folders_client is None:
        _folders_client = resourcemanager_v3.FoldersClient()
    return _folders_client


def _get_asset_client():
    """Return a shared AssetServiceClient (created once, reused)."""
    global _asset_client
    if _asset_client is None:
        _asset_client = asset_v1.AssetServiceClient()
    return _asset_client

# ---------------------------------------------------------------------------
# Required IAM roles and permissions
#
# These are the minimum IAM bindings the authenticated identity needs.
# Organised by scope so the UI and preflight can show exactly what applies.
#
# Each entry has:
#   role        — the predefined IAM role that grants the permission(s)
#   permissions — the specific IAM permissions the estimator exercises
#   scope       — "project" (always needed) or "org" (only for org/folder scans)
#   reason      — why the permission is needed (shown in UI + preflight)
# ---------------------------------------------------------------------------
REQUIRED_IAM = [
    {
        "role": "roles/monitoring.viewer",
        "permissions": ["monitoring.timeSeries.list"],
        "scope": "project",
        "reason": "Read Cloud Monitoring metrics for each target project.",
    },
    {
        "role": "roles/resourcemanager.organizationViewer",
        "permissions": [
            "resourcemanager.projects.list",
            "resourcemanager.projects.get",
            "resourcemanager.folders.list",
        ],
        "scope": "org",
        "reason": (
            "Discover projects and folders under an organization or folder. "
            "Folders are enumerated recursively to find nested projects. "
            "Only required for org-wide or folder-wide scans."
        ),
    },
    {
        "role": "roles/browser",
        "permissions": ["resourcemanager.projects.get"],
        "scope": "project",
        "reason": (
            "Read basic project metadata (used by preflight checks). "
            "Included in most viewer roles."
        ),
    },
    {
        "role": "roles/cloudasset.viewer",
        "permissions": ["cloudasset.assets.searchAllResources"],
        "scope": "project",
        "reason": (
            "Discover deployed resources via Cloud Asset Inventory. "
            "Used to skip metric queries for unused services. "
            "Falls back gracefully if not granted."
        ),
    },
]


# ---------------------------------------------------------------------------
# Cloud Logging free-tier reference
#
# Some log types are always free (stored in the _Required bucket with 400-day
# retention).  All other log types get a 50 GiB/project/month free allotment
# before standard ingestion charges apply.
#
# This data is shown in the UI and the preflight output so users understand
# which logs already flow at no cost vs. which ones will add to their bill.
# ---------------------------------------------------------------------------
FREE_TIER_LOGS = [
    # -- Always free, unlimited volume, _Required bucket, 400-day retention --
    {
        "name": "Admin Activity Audit Logs",
        "bucket": "_Required",
        "retention": "400 days",
        "cost": "Free (always)",
        "coverage": (
            "All administrative actions: IAM policy changes, resource "
            "creation/deletion/modification, service account key operations. "
            "Cannot be disabled."
        ),
    },
    {
        "name": "System Event Audit Logs",
        "bucket": "_Required",
        "retention": "400 days",
        "cost": "Free (always)",
        "coverage": (
            "Google-initiated system events: automated resource migrations, "
            "maintenance operations, quota adjustments, system-driven "
            "configuration changes."
        ),
    },
    {
        "name": "Access Transparency Logs",
        "bucket": "_Required",
        "retention": "400 days",
        "cost": "Free (always)",
        "coverage": (
            "Records when Google staff access your data for support cases "
            "or service operations. Requires Access Transparency to be "
            "enabled (available with Premium/Enterprise support)."
        ),
    },
    {
        "name": "Google Workspace Admin Audit Logs",
        "bucket": "_Required",
        "retention": "400 days",
        "cost": "Free (always)",
        "coverage": (
            "Administrative actions in Google Workspace Admin Console: "
            "user management, group changes, application settings, "
            "domain-level configuration. Requires Workspace log streaming."
        ),
    },
    {
        "name": "Google Workspace Login Audit Logs",
        "bucket": "_Required",
        "retention": "400 days",
        "cost": "Free (always)",
        "coverage": (
            "User sign-in events for Google Workspace: successful/failed "
            "logins, suspicious login attempts, 2FA events. "
            "Requires Workspace log streaming."
        ),
    },
    {
        "name": "Enterprise Groups Audit Logs",
        "bucket": "_Required",
        "retention": "400 days",
        "cost": "Free (always)",
        "coverage": (
            "Changes to Google Groups membership and settings when managed "
            "through Cloud Identity / Workspace."
        ),
    },
]

# Logs that are NOT free but have a per-project free allotment.
PAID_LOG_TIERS = {
    "standard": {
        "free_allotment": "50 GiB/project/month",
        "rate": "$0.50/GiB",
        "bucket": "_Default or user-defined",
        "default_retention": "30 days",
        "extended_retention_cost": "$0.01/GiB/month",
        "examples": [
            "Data Access Audit Logs",
            "Cloud DNS Logs",
            "Firewall Rules Logs",
            "Cloud NAT Logs",
            "IAP Access Logs",
            "Artifact Registry Audit Logs",
            "Application / platform logs",
        ],
    },
    "network": {
        "free_allotment": "Included in standard 50 GiB",
        "rate": "$0.25/GiB (discounted)",
        "bucket": "_Default or user-defined",
        "default_retention": "30 days",
        "extended_retention_cost": "$0.01/GiB/month",
        "examples": [
            "VPC Flow Logs",
            "HTTP(S) Load Balancer Logs",
            "Cloud NAT Logs",
            "Network Intelligence Center logs",
        ],
        "note": (
            "Vended network telemetry logs are billed at a discounted rate "
            "of $0.25/GiB instead of the standard $0.50/GiB."
        ),
    },
}

# Items that are always free regardless (no charge for API usage).
FREE_OPERATIONS = [
    "Log routing (forwarding to any supported destination)",
    "Cloud Logging API calls",
    "Creating log scopes and analytics views",
    "Log Analytics SQL queries",
]


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

def _list_folders_recursive(parent_name):
    """Recursively enumerate all folder IDs under *parent_name*.

    Args:
        parent_name: Resource name like ``organizations/123`` or ``folders/456``.

    Returns:
        List of folder resource names (e.g. ``["folders/111", "folders/222"]``).
    """
    client = _get_folders_client()
    found = []
    try:
        for folder in client.list_folders(parent=parent_name):
            found.append(folder.name)
            # Recurse into sub-folders.
            found.extend(_list_folders_recursive(folder.name))
    except Exception as exc:
        print(f"[warn] listing sub-folders of {parent_name}: {exc}")
    return found


def list_org_projects(org_id):
    """Return a list of ``{project_id, display_name}`` dicts for every active
    project under *org_id*, including projects nested inside sub-folders at
    any depth.

    Requires ``resourcemanager.projects.list`` on the organization and
    ``resourcemanager.folders.list`` for folder traversal.
    """
    projects_client = _get_projects_client()
    projects = []

    # Collect all parents to scan: the org itself + every nested folder.
    parents = [f"organizations/{org_id}"]
    parents.extend(_list_folders_recursive(f"organizations/{org_id}"))
    print(f"[info] org scan: found {len(parents)} parent(s) to search "
          f"(1 org + {len(parents) - 1} folders)")

    for parent in parents:
        try:
            query = f"parent={parent} state:ACTIVE"
            for project in projects_client.search_projects(query=query):
                projects.append({
                    "project_id": project.project_id,
                    "display_name": project.display_name,
                })
        except Exception as exc:
            print(f"[error] listing projects under {parent}: {exc}")

    print(f"[info] org scan: found {len(projects)} active project(s) total")
    return projects


def list_folder_projects(folder_id):
    """Return a list of ``{project_id, display_name}`` dicts for every active
    project under *folder_id*, including projects nested in sub-folders at
    any depth.

    Requires ``resourcemanager.projects.list`` and
    ``resourcemanager.folders.list`` on the folder.
    """
    projects_client = _get_projects_client()
    projects = []

    # Collect: the folder itself + every nested sub-folder.
    parents = [f"folders/{folder_id}"]
    parents.extend(_list_folders_recursive(f"folders/{folder_id}"))
    print(f"[info] folder scan: found {len(parents)} parent(s) to search")

    for parent in parents:
        try:
            query = f"parent={parent} state:ACTIVE"
            for project in projects_client.search_projects(query=query):
                projects.append({
                    "project_id": project.project_id,
                    "display_name": project.display_name,
                })
        except Exception as exc:
            print(f"[error] listing projects under {parent}: {exc}")

    print(f"[info] folder scan: found {len(projects)} active project(s) total")
    return projects


# ---------------------------------------------------------------------------
# Cloud Asset Inventory — resource discovery
#
# Uses the Cloud Asset API to discover what resources are actually deployed
# in a project/org.  This lets us skip metric queries for services that
# have zero resources (e.g. no Cloud SQL instances → skip cloudsql metrics).
#
# One API call returns all resource types, which is vastly more efficient
# than querying each service API individually.
# ---------------------------------------------------------------------------

def _all_asset_types():
    """Collect the unique set of Cloud Asset types across all LOG_SOURCES."""
    types = set()
    for src in LOG_SOURCES:
        for at in src.get("asset_types", []):
            types.add(at)
    return sorted(types)


def discover_assets(scope):
    """Discover deployed resources using the Cloud Asset Inventory API.

    Args:
        scope: Resource scope — ``projects/my-project``,
               ``organizations/123``, or ``folders/456``.

    Returns:
        dict mapping ``project_id`` → set of asset type strings found in
        that project.  Example::

            {"my-project": {"compute.googleapis.com/Instance",
                            "storage.googleapis.com/Bucket"}}
    """
    client = _get_asset_client()
    wanted_types = _all_asset_types()

    # project_id → set of asset type strings
    assets_by_project = {}

    start = time.time()
    try:
        request = asset_v1.SearchAllResourcesRequest(
            scope=scope,
            asset_types=wanted_types,
            # We only need the resource type and project, not full metadata.
            read_mask="name,assetType,project",
            page_size=500,
        )
        for resource in client.search_all_resources(request=request):
            # resource.project is like "projects/12345" (numeric).
            # Extract the project ID from the resource name instead.
            # Resource names look like:
            #   //compute.googleapis.com/projects/my-project/zones/...
            #   //storage.googleapis.com/projects/_/buckets/my-bucket
            project_id = _extract_project_id(resource.name, resource.project)
            if project_id:
                assets_by_project.setdefault(project_id, set())
                assets_by_project[project_id].add(resource.asset_type)

    except GoogleAPICallError as exc:
        print(f"[asset] Cloud Asset API error for {scope}: {exc}")
        print(f"[asset] Falling back to querying all metrics (slower).")
        return None
    except Exception as exc:
        print(f"[asset] Unexpected error: {exc}")
        print(f"[asset] Falling back to querying all metrics (slower).")
        return None

    elapsed = time.time() - start
    total_types = sum(len(v) for v in assets_by_project.values())
    print(f"[asset] Discovered {total_types} resource types across "
          f"{len(assets_by_project)} project(s) in {elapsed:.1f}s")
    for pid, types in sorted(assets_by_project.items()):
        print(f"[asset]   {pid}: {', '.join(sorted(types))}")

    return assets_by_project


def _extract_project_id(resource_name, project_field):
    """Extract the project ID from a Cloud Asset resource.

    Args:
        resource_name: Full resource name (e.g.
            ``//compute.googleapis.com/projects/my-project/zones/...``).
        project_field: The ``project`` field from the API response
            (e.g. ``projects/123456``).

    Returns:
        str project ID or None.
    """
    # Try extracting from the resource name (most reliable for project ID).
    # Pattern: //service/projects/{project_id}/...
    if "/projects/" in resource_name:
        parts = resource_name.split("/projects/", 1)
        if len(parts) == 2:
            pid = parts[1].split("/")[0]
            # Skip numeric-only IDs (project numbers) — we want the string ID.
            if pid and pid != "_":
                return pid

    # Fallback: use the project field (may be numeric).
    if project_field and project_field.startswith("projects/"):
        return project_field.split("/", 1)[1]

    return None


def should_query_metric(source, project_assets):
    """Decide whether to query a metric based on discovered assets.

    Args:
        source:         One entry from ``LOG_SOURCES``.
        project_assets: Set of asset type strings for this project,
                        or None if asset discovery failed/was skipped.

    Returns:
        (should_query: bool, resource_count: int or None)
    """
    # Always query always-on logs (they have no asset_types filter).
    if source.get("always_on"):
        return True, None

    # If asset discovery failed, fall back to querying everything.
    if project_assets is None:
        return True, None

    # Check if any of the source's asset types were found.
    source_types = source.get("asset_types", [])
    if not source_types:
        # No asset types defined — query the metric unconditionally.
        return True, None

    found = [t for t in source_types if t in project_assets]
    if found:
        return True, len(found)
    else:
        return False, 0


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

    client = _get_monitoring_client()
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

    print(f"[metric] {project_id}: {api_filter}")

    try:
        results = client.list_time_series(
            name=project_name,
            filter=api_filter,
            interval=interval,
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        )
        # Sum across all returned time-series and their data points.
        total = 0
        series_count = 0
        for series in results:
            series_count += 1
            for point in series.points:
                # Metrics may report int64 or double; take whichever is non-zero.
                total += point.value.int64_value or point.value.double_value

        print(f"[metric] {project_id}: {source['metric']} → "
              f"{series_count} series, total={total}")
        return total

    except NotFound:
        # 404 = the metric type doesn't exist in this project.  This is
        # expected when the corresponding GCP service is not in use (e.g.
        # no Cloud DNS zones, no Cloud SQL instances).
        print(f"[metric] {project_id}: {source['metric']} → "
              f"no data (service not in use)")
        return 0

    except GoogleAPICallError as exc:
        # Real API errors (permission denied, quota, server errors).
        print(f"[metric] {project_id}: {source['metric']} → "
              f"API ERROR: {exc}")
        return 0

    except Exception as exc:
        # Unexpected errors.
        print(f"[metric] {project_id}: {source['metric']} → "
              f"UNEXPECTED ERROR: {exc}")
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


def estimate_project(project_id, selected_keys, sampling_rate,
                     project_assets=None):
    """Run cost estimates for every selected log source in a single project.

    Uses Cloud Asset Inventory data (if available) to skip metrics for
    services that have no deployed resources.  Remaining metrics are
    fetched in parallel via a thread pool.

    Args:
        project_id:     GCP project ID to scan.
        selected_keys:  List of ``LOG_SOURCES`` key strings chosen by the user.
        sampling_rate:  VPC Flow Log sampling rate (0.0–1.0).
        project_assets: Set of asset type strings found in this project
                        (from ``discover_assets``), or None to query all.

    Returns:
        Tuple of (estimates, total_gib, total_cost).
    """
    # Filter to valid, estimable sources.
    sources = []
    for key in selected_keys:
        source = LOG_SOURCE_MAP.get(key)
        if source and not source.get("manual_only"):
            sources.append(source)

    if not sources:
        return [], 0, 0

    # Decide which sources actually need a metric query based on assets.
    sources_to_query = []
    skipped_sources = []
    for source in sources:
        should_q, _count = should_query_metric(source, project_assets)
        if should_q:
            sources_to_query.append(source)
        else:
            skipped_sources.append(source)

    if skipped_sources:
        names = [s["label"] for s in skipped_sources]
        print(f"[asset] {project_id}: skipping {len(names)} source(s) "
              f"(no resources): {', '.join(names)}")

    # Fetch metrics in parallel for sources that have deployed resources.
    raw_results = {}
    if sources_to_query:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            future_to_key = {
                pool.submit(fetch_metric_7d, project_id, src): src["key"]
                for src in sources_to_query
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    raw_results[key] = future.result()
                except Exception as exc:
                    print(f"[error] thread exception for {key}: {exc}")
                    raw_results[key] = 0

    # Build estimates (preserves original selection order).
    estimates = []
    total_gib = 0
    total_cost = 0

    for source in sources:
        raw_7d = raw_results.get(source["key"], 0)
        gib = estimate_monthly_gib(source, raw_7d, sampling_rate)

        rate = COST_PER_GIB_NETWORK if source.get("network_log") else COST_PER_GIB
        cost = gib * rate
        has_data = raw_7d > 0

        # Determine resource status for UI.
        was_skipped = source in skipped_sources
        _, resource_count = should_query_metric(source, project_assets)

        estimates.append({
            "name": source["label"],
            "category": source["category"],
            "volume_gib": round(gib, 3),
            "cost": round(cost, 2),
            "always_on": source.get("always_on", False),
            "has_data": has_data,
            "network_log": source.get("network_log", False),
            "skipped": was_skipped,
            "resource_count": resource_count,
        })
        total_gib += gib
        total_cost += cost

    return estimates, total_gib, total_cost


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
            # Discover assets for this project (one API call).
            assets = discover_assets(f"projects/{project_id}")
            pa = assets.get(project_id) if assets else None

            estimates, total_gib, total_cost = estimate_project(
                project_id, selected_keys, sampling_rate,
                project_assets=pa,
            )
            results = {
                "scope": "project",
                "project_id": project_id,
                "estimates": estimates,
                "total_gib": round(total_gib, 3),
                "total_cost": round(total_cost, 2),
                "sampling_rate": sampling_rate,
            }

        # -- Organization-wide scope --
        elif scope == "org":
            # One asset discovery call for the entire org — returns all
            # resources across all projects, grouped by project.
            assets = discover_assets(f"organizations/{org_id}")

            projects = list_org_projects(org_id)
            project_results, grand_total_gib, grand_total_cost = _scan_projects(
                projects, selected_keys, sampling_rate,
                assets_by_project=assets,
            )
            results = {
                "scope": "org",
                "org_id": org_id,
                "projects": project_results,
                "project_count": len(projects),
                "grand_total_gib": round(grand_total_gib, 3),
                "grand_total_cost": round(grand_total_cost, 2),
                "sampling_rate": sampling_rate,
            }

        # -- Folder scope --
        elif scope == "folder":
            assets = discover_assets(f"folders/{folder_id}")

            projects = list_folder_projects(folder_id)
            project_results, grand_total_gib, grand_total_cost = _scan_projects(
                projects, selected_keys, sampling_rate,
                assets_by_project=assets,
            )
            results = {
                "scope": "folder",
                "folder_id": folder_id,
                "projects": project_results,
                "project_count": len(projects),
                "grand_total_gib": round(grand_total_gib, 3),
                "grand_total_cost": round(grand_total_cost, 2),
                "sampling_rate": sampling_rate,
            }

    # Pre-fill org ID from CLI flag if provided.
    cli_org_id = app.config.get("CLI_ORG_ID", "")

    return render_template(
        "index.html",
        results=results,
        log_sources=LOG_SOURCES,
        auth_info=auth_info,
        required_iam=REQUIRED_IAM,
        free_tier_logs=FREE_TIER_LOGS,
        paid_log_tiers=PAID_LOG_TIERS,
        free_operations=FREE_OPERATIONS,
        cli_org_id=cli_org_id,
    )


def _scan_projects(projects, selected_keys, sampling_rate,
                   assets_by_project=None):
    """Scan multiple projects in parallel and collect per-project estimates.

    Each project's metrics are already fetched concurrently inside
    ``estimate_project``.  This function adds a second level of parallelism
    by running multiple projects simultaneously.

    Args:
        projects:          List of ``{project_id, display_name}`` dicts.
        selected_keys:     Log-source keys chosen by the user.
        sampling_rate:     VPC Flow Log sampling rate.
        assets_by_project: Dict from ``discover_assets`` mapping project_id
                           to set of asset types, or None.

    Returns:
        Tuple of (project_results, grand_total_gib, grand_total_cost).
    """
    if not projects:
        return [], 0, 0

    start = time.time()
    results_by_pid = {}

    def _estimate_one(proj):
        pid = proj["project_id"]
        pa = assets_by_project.get(pid) if assets_by_project else None
        estimates, proj_gib, proj_cost = estimate_project(
            pid, selected_keys, sampling_rate, project_assets=pa
        )
        return pid, proj["display_name"], estimates, proj_gib, proj_cost

    # Run projects in parallel (capped to avoid overwhelming the API).
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_estimate_one, p): p for p in projects}
        for future in as_completed(futures):
            try:
                pid, name, estimates, gib, cost = future.result()
                results_by_pid[pid] = (name, estimates, gib, cost)
            except Exception as exc:
                proj = futures[future]
                print(f"[error] scanning {proj['project_id']}: {exc}")

    # Rebuild in the original project order.
    project_results = []
    grand_total_gib = 0
    grand_total_cost = 0
    for proj in projects:
        pid = proj["project_id"]
        if pid not in results_by_pid:
            continue
        name, estimates, proj_gib, proj_cost = results_by_pid[pid]
        grand_total_gib += proj_gib
        grand_total_cost += proj_cost
        project_results.append({
            "project_id": pid,
            "display_name": name,
            "estimates": estimates,
            "total_gib": round(proj_gib, 3),
            "total_cost": round(proj_cost, 2),
        })

    elapsed = time.time() - start
    print(f"[perf] scanned {len(project_results)} project(s) in {elapsed:.1f}s")

    return project_results, grand_total_gib, grand_total_cost


# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

# APIs the estimator needs and the gcloud command to enable each one.
REQUIRED_APIS = [
    {
        "name": "Cloud Monitoring API",
        "service": "monitoring.googleapis.com",
        "check": lambda pid: _check_monitoring_api(pid),
    },
    {
        "name": "Cloud Resource Manager API",
        "service": "cloudresourcemanager.googleapis.com",
        "check": lambda pid: _check_resource_manager_api(pid),
    },
    {
        "name": "Cloud Asset API",
        "service": "cloudasset.googleapis.com",
        "check": lambda pid: _check_asset_api(pid),
    },
]


def _check_monitoring_api(project_id):
    """Attempt a lightweight Monitoring API call to verify access.

    Returns (ok: bool, detail: str).
    """
    try:
        client = _get_monitoring_client()
        # list_time_series with an impossible metric type — we only care
        # whether the API responds (200/403/404) vs rejects (permission
        # denied or API-not-enabled).
        now = time.time()
        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now)},
            "start_time": {"seconds": int(now - 60)},
        })
        list(client.list_time_series(
            name=f"projects/{project_id}",
            filter='metric.type = "logging.googleapis.com/byte_count"',
            interval=interval,
            view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.HEADERS,
        ))
        return True, "OK"
    except NotFound:
        # 404 = metric not found, but the API itself is reachable.
        return True, "OK (API enabled, metric not yet present)"
    except GoogleAPICallError as exc:
        if "has not been used" in str(exc) or "is not enabled" in str(exc):
            return False, (
                f"API not enabled. Run:\n"
                f"  gcloud services enable monitoring.googleapis.com "
                f"--project={project_id}"
            )
        if "PERMISSION_DENIED" in str(exc) or exc.code == 403:
            return False, (
                f"Permission denied. The authenticated identity needs "
                f"monitoring.timeSeries.list on project {project_id}."
            )
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _check_resource_manager_api(project_id):
    """Verify the Resource Manager API is accessible (needed for org scans).

    Returns (ok: bool, detail: str).
    """
    try:
        client = _get_projects_client()
        # Just try to get the project — lightweight read.
        client.get_project(name=f"projects/{project_id}")
        return True, "OK"
    except NotFound:
        return False, f"Project '{project_id}' not found."
    except GoogleAPICallError as exc:
        if "has not been used" in str(exc) or "is not enabled" in str(exc):
            return False, (
                f"API not enabled. Run:\n"
                f"  gcloud services enable cloudresourcemanager.googleapis.com "
                f"--project={project_id}"
            )
        if "PERMISSION_DENIED" in str(exc) or exc.code == 403:
            return False, (
                f"Permission denied. The authenticated identity needs "
                f"resourcemanager.projects.get on project {project_id}."
            )
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _check_asset_api(project_id):
    """Verify the Cloud Asset API is accessible (needed for resource discovery).

    Returns (ok: bool, detail: str).
    """
    try:
        client = _get_asset_client()
        # Minimal search — just check if the API responds.
        request = asset_v1.SearchAllResourcesRequest(
            scope=f"projects/{project_id}",
            asset_types=["compute.googleapis.com/Instance"],
            page_size=1,
        )
        list(client.search_all_resources(request=request))
        return True, "OK"
    except GoogleAPICallError as exc:
        if "has not been used" in str(exc) or "is not enabled" in str(exc):
            return False, (
                f"API not enabled. Run:\n"
                f"  gcloud services enable cloudasset.googleapis.com "
                f"--project={project_id}"
            )
        if "PERMISSION_DENIED" in str(exc) or exc.code == 403:
            return False, (
                f"Permission denied. The authenticated identity needs "
                f"cloudasset.assets.searchAllResources."
            )
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _check_iam_permissions(project_id):
    """Test which required IAM permissions the caller actually has.

    Uses the Resource Manager ``testIamPermissions`` API to check all
    project-scoped permissions in one call.

    Returns:
        List of (permission: str, granted: bool, role_hint: str) tuples.
    """
    # Collect all project-scoped permissions to test.
    perms_to_test = []
    perm_to_role = {}
    for entry in REQUIRED_IAM:
        for perm in entry["permissions"]:
            if perm not in perm_to_role:
                perms_to_test.append(perm)
                perm_to_role[perm] = entry["role"]

    try:
        client = _get_projects_client()
        response = client.test_iam_permissions(
            resource=f"projects/{project_id}",
            permissions=perms_to_test,
        )
        granted = set(response.permissions)
    except Exception as exc:
        logger.warning("testIamPermissions failed for %s: %s", project_id, exc)
        # If we can't test, return unknown status.
        return [(p, None, perm_to_role[p]) for p in perms_to_test]

    return [
        (perm, perm in granted, perm_to_role[perm])
        for perm in perms_to_test
    ]


def run_preflight(project_id):
    """Run all preflight checks against *project_id* and print results.

    Checks:
        1. Authentication is valid.
        2. Required GCP APIs are enabled and accessible.
        3. Required IAM permissions are granted.

    Returns:
        True if all checks pass, False otherwise.
    """
    print(f"\n{'='*60}")
    print(f"  Preflight checks — project: {project_id}")
    print(f"{'='*60}\n")

    all_ok = True

    # -- 1. Auth check --
    print("  --- Authentication ---")
    auth = get_auth_info()
    if auth["valid"]:
        print(f"  [PASS] {auth['method']} ({auth.get('identity', 'unknown')})")
    else:
        print(f"  [FAIL] {auth.get('error', 'no credentials')}")
        all_ok = False
    print()

    # -- 2. API checks --
    print("  --- Required APIs ---")
    for api in REQUIRED_APIS:
        ok, detail = api["check"](project_id)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {api['name']}: {detail}")
        if not ok:
            all_ok = False
    print()

    # -- 3. IAM permission checks --
    print("  --- IAM Permissions ---")
    iam_results = _check_iam_permissions(project_id)
    for perm, granted, role_hint in iam_results:
        if granted is None:
            print(f"  [ ?? ] {perm}  (could not test — see API errors above)")
        elif granted:
            print(f"  [PASS] {perm}")
        else:
            print(f"  [FAIL] {perm}")
            print(f"         Grant via: gcloud projects add-iam-policy-binding {project_id} \\")
            print(f"           --member='<IDENTITY>' --role='{role_hint}'")
            all_ok = False
    print()

    # -- 4. Required IAM roles reference table --
    print("  --- Required IAM Roles Reference ---")
    print(f"  {'Role':<45} {'Scope':<10} Reason")
    print(f"  {'-'*44}  {'-'*9} {'-'*40}")
    for entry in REQUIRED_IAM:
        print(f"  {entry['role']:<45} {entry['scope']:<10} {entry['reason']}")
    print()

    # -- Summary --
    print(f"{'='*60}")
    if all_ok:
        print("  All preflight checks passed.")
    else:
        print("  Some checks FAILED.  Fix the issues above before running")
        print("  the estimator.  Common fixes:")
        print()
        print(f"  # Enable required APIs:")
        print(f"    gcloud services enable monitoring.googleapis.com --project={project_id}")
        print(f"    gcloud services enable cloudresourcemanager.googleapis.com --project={project_id}")
        print()
        print(f"  # Grant required roles (replace <IDENTITY> with user/SA email):")
        for entry in REQUIRED_IAM:
            if entry["scope"] == "project":
                print(f"    gcloud projects add-iam-policy-binding {project_id} \\")
                print(f"      --member='serviceAccount:<IDENTITY>' --role='{entry['role']}'")
    print(f"{'='*60}\n")

    return all_ok


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = parse_args()

    # Validate / configure authentication before starting the server.
    setup_auth(args)

    # If --preflight was requested, run checks and exit.
    if args.preflight:
        ok = run_preflight(args.preflight)
        sys.exit(0 if ok else 1)

    # Store CLI org-id on the app config so the route can pre-fill the form.
    app.config["CLI_ORG_ID"] = args.org_id or ""

    # Start the Flask development server.
    app.run(host=args.host, port=args.port, debug=args.debug)
