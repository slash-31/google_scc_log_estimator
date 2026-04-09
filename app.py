import time
import os
import json
from flask import Flask, render_template, request
from google.cloud import monitoring_v3
from google.cloud import resourcemanager_v3
from google.auth import default as get_default_credentials
from google.auth.exceptions import DefaultCredentialsError

# Fix for GOOGLE_APPLICATION_CREDENTIALS if it contains an unexpanded tilde (~)
if os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.path.expanduser(
        os.environ['GOOGLE_APPLICATION_CREDENTIALS']
    )

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Log ingestion sources for SCC Premium — ETD and SHA
#
# Categories align with the ETD/SHA best-practices guidance:
#   must_have    — Always ON, no extra Cloud Logging cost
#   recommended  — Highly recommended to enable for ETD visibility
#   optional     — Enable based on environment and specific needs
#
# For "must_have" logs we query logging.googleapis.com/byte_count to show
# actual current ingestion (they are already flowing).
# For "recommended" logs we use proxy metrics (API request counts, etc.)
# multiplied by an estimated KB-per-entry to project what ingestion would
# look like once the log source is enabled.
# ---------------------------------------------------------------------------
LOG_SOURCES = [
    # === MUST HAVE (Always ON) ===
    {
        "key": "admin_activity",
        "label": "Cloud Audit Logs — Admin Activity",
        "category": "must_have",
        "description": "Detects unauthorized config changes, service account manipulation, and privilege escalation. Always enabled.",
        "metric": "logging.googleapis.com/byte_count",
        "metric_label_filter": 'metric.label.\"log\" = \"cloudaudit.googleapis.com%2Factivity\"',
        "use_bytes": True,
        "always_on": True,
    },
    {
        "key": "system_event",
        "label": "Cloud Audit Logs — System Event",
        "category": "must_have",
        "description": "Google Cloud system actions on your resources. Always enabled.",
        "metric": "logging.googleapis.com/byte_count",
        "metric_label_filter": 'metric.label.\"log\" = \"cloudaudit.googleapis.com%2Fsystem_event\"',
        "use_bytes": True,
        "always_on": True,
    },
    # === HIGHLY RECOMMENDED ===
    {
        "key": "dns",
        "label": "Cloud DNS Logs",
        "category": "recommended",
        "description": "Detects DNS tunneling, C2 beaconing, and cryptomining pool connections.",
        "metric": "dns.googleapis.com/query/count",
        "size_kb": 0.5,
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
    },
    {
        "key": "gcs_data_access",
        "label": "GCS Data Access Audit Logs",
        "category": "recommended",
        "description": "Tracks who reads/downloads files in Cloud Storage buckets.",
        "metric": "storage.googleapis.com/api/request_count",
        "size_kb": 1.5,
    },
    {
        "key": "bq_data_access",
        "label": "BigQuery Data Access Audit Logs",
        "category": "recommended",
        "description": "Required for ETD to detect anomalous table exports and data exfiltration.",
        "metric": "bigquery.googleapis.com/query/count",
        "size_kb": 1.2,
    },
    {
        "key": "cloudsql_data_access",
        "label": "Cloud SQL Data Access Audit Logs",
        "category": "recommended",
        "description": "Monitors database connections for unauthorized data access.",
        "metric": "cloudsql.googleapis.com/database/network/connections",
        "size_kb": 1.0,
    },
    # === OPTIONAL ===
    {
        "key": "workspace",
        "label": "Google Workspace Logs",
        "category": "optional",
        "description": (
            "Detects threats related to Workspace user accounts. "
            "Requires org-level SCC activation and Workspace log streaming to Cloud Logging."
        ),
        "manual_only": True,
    },
]

LOG_SOURCE_MAP = {s["key"]: s for s in LOG_SOURCES}

COST_PER_GIB = 0.50
KB_PER_GIB = 1048576  # 1024 * 1024
BYTES_PER_GIB = 1073741824  # 1024^3


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

def get_auth_info():
    """Return a dict describing the current authentication state."""
    sa_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
    if sa_path and os.path.isfile(sa_path):
        try:
            with open(sa_path) as f:
                data = json.load(f)
            return {
                "method": "service_account",
                "identity": data.get("client_email", "unknown"),
                "project": data.get("project_id"),
                "file": sa_path,
                "valid": True,
            }
        except (json.JSONDecodeError, OSError):
            return {"method": "service_account", "valid": False,
                    "error": f"Invalid key file: {sa_path}"}

    try:
        credentials, project = get_default_credentials()
        identity = getattr(credentials, 'service_account_email', None) \
            or getattr(credentials, 'signer_email', None) \
            or 'gcloud ADC'
        return {
            "method": "adc",
            "identity": identity,
            "project": project,
            "valid": True,
        }
    except DefaultCredentialsError as e:
        return {"method": "none", "valid": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Org-level project discovery
# ---------------------------------------------------------------------------

def list_org_projects(org_id):
    """List all active projects under an organization."""
    client = resourcemanager_v3.ProjectsClient()
    query = f"parent=organizations/{org_id} state:ACTIVE"
    projects = []
    try:
        for project in client.search_projects(query=query):
            projects.append({
                "project_id": project.project_id,
                "display_name": project.display_name,
            })
    except Exception as e:
        print(f"Error listing org projects: {e}")
    return projects


def list_folder_projects(folder_id):
    """List all active projects under a folder (recursive)."""
    client = resourcemanager_v3.ProjectsClient()
    query = f"parent=folders/{folder_id} state:ACTIVE"
    projects = []
    try:
        for project in client.search_projects(query=query):
            projects.append({
                "project_id": project.project_id,
                "display_name": project.display_name,
            })
    except Exception as e:
        print(f"Error listing folder projects: {e}")
    return projects


# ---------------------------------------------------------------------------
# Metric fetching and estimation
# ---------------------------------------------------------------------------

def fetch_metric_7d(project_id, source):
    """Fetch 7 days of a Cloud Monitoring metric and return the raw total."""
    if source.get("manual_only"):
        return 0

    client = monitoring_v3.MetricServiceClient()
    project_name = f"projects/{project_id}"

    now = time.time()
    interval = monitoring_v3.TimeInterval({
        "end_time": {"seconds": int(now)},
        "start_time": {"seconds": int(now - 604800)},  # 7 days
    })

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
        total = 0
        for series in results:
            for point in series.points:
                total += point.value.int64_value or point.value.double_value
        return total
    except Exception as e:
        print(f"Error fetching {source['metric']} for {project_id}: {e}")
        return 0


def estimate_monthly_gib(source, raw_7d_total, sampling_rate=1.0):
    """Convert a 7-day raw metric total into an estimated 30-day GiB volume."""
    monthly_raw = (raw_7d_total / 7) * 30

    if source.get("use_bytes"):
        return monthly_raw / BYTES_PER_GIB

    entry_count = monthly_raw
    if source.get("packets_per_record"):
        entry_count = monthly_raw / source["packets_per_record"]

    gib = (entry_count * source.get("size_kb", 1.0)) / KB_PER_GIB

    if source.get("supports_sampling"):
        gib *= sampling_rate

    return gib


def estimate_project(project_id, selected_keys, sampling_rate):
    """Run estimates for a single project. Returns (items_list, total_gib)."""
    items = []
    total_gib = 0

    for key in selected_keys:
        source = LOG_SOURCE_MAP.get(key)
        if not source or source.get("manual_only"):
            continue

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

@app.route('/', methods=['GET', 'POST'])
def index():
    auth_info = get_auth_info()
    results = None

    if request.method == 'POST':
        scope = request.form.get('scope', 'project')
        project_id = request.form.get('project_id', '').strip()
        org_id = request.form.get('org_id', '').strip()
        folder_id = request.form.get('folder_id', '').strip()
        selected_keys = request.form.getlist('features')
        sampling_rate = float(request.form.get('vpc_sampling_rate', 0.5))
        sampling_rate = max(0.0, min(1.0, sampling_rate))

        if scope == 'project':
            items, total_gib = estimate_project(
                project_id, selected_keys, sampling_rate)
            results = {
                "scope": "project",
                "project_id": project_id,
                "items": items,
                "total_gib": round(total_gib, 3),
                "total_cost": round(total_gib * COST_PER_GIB, 2),
                "sampling_rate": sampling_rate,
            }

        elif scope == 'org':
            projects = list_org_projects(org_id)
            project_results = []
            grand_total_gib = 0

            for proj in projects:
                pid = proj["project_id"]
                items, proj_gib = estimate_project(
                    pid, selected_keys, sampling_rate)
                proj_cost = proj_gib * COST_PER_GIB
                grand_total_gib += proj_gib
                project_results.append({
                    "project_id": pid,
                    "display_name": proj["display_name"],
                    "items": items,
                    "total_gib": round(proj_gib, 3),
                    "total_cost": round(proj_cost, 2),
                })

            results = {
                "scope": "org",
                "org_id": org_id,
                "projects": project_results,
                "project_count": len(projects),
                "grand_total_gib": round(grand_total_gib, 3),
                "grand_total_cost": round(grand_total_gib * COST_PER_GIB, 2),
                "sampling_rate": sampling_rate,
            }

        elif scope == 'folder':
            projects = list_folder_projects(folder_id)
            project_results = []
            grand_total_gib = 0

            for proj in projects:
                pid = proj["project_id"]
                items, proj_gib = estimate_project(
                    pid, selected_keys, sampling_rate)
                proj_cost = proj_gib * COST_PER_GIB
                grand_total_gib += proj_gib
                project_results.append({
                    "project_id": pid,
                    "display_name": proj["display_name"],
                    "items": items,
                    "total_gib": round(proj_gib, 3),
                    "total_cost": round(proj_cost, 2),
                })

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
        'index.html',
        results=results,
        log_sources=LOG_SOURCES,
        auth_info=auth_info,
    )


if __name__ == '__main__':
    app.run(port=5000, debug=True)
