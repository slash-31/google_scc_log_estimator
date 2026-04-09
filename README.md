# Google Cloud Security Logging Estimator

A tool for security engineers to estimate 30-day Cloud Logging ingestion costs when enabling log sources recommended by Security Command Center (SCC) Premium for Event Threat Detection (ETD) and Security Health Analytics (SHA).

It queries live traffic metrics from the Cloud Monitoring API over a 7-day baseline, extrapolates to 30 days, and applies per-log-type size estimates at $0.50/GiB.

## Features

- **Live Metric Analysis** — fetches real-time traffic data from the last 7 days via the Cloud Monitoring API.
- **ETD/SHA-Aligned Categories** — log sources grouped as Must Have, Highly Recommended, and Optional per GCP best practices.
- **Multi-Scope Scanning** — estimate a single project, all projects under a folder, or an entire organization.
- **VPC Flow Log Sampling** — adjustable sampling rate slider (0.1–1.0) for cost modeling.
- **Dual Auth Support** — service account key file (JWT) via CLI flag, or gcloud Application Default Credentials.

### Supported Log Sources

| Category | Log Type | Metric Source |
|---|---|---|
| Must Have (always on) | Admin Activity Audit Logs | `logging.googleapis.com/byte_count` |
| Must Have (always on) | System Event Audit Logs | `logging.googleapis.com/byte_count` |
| Recommended | Cloud DNS Logs | `dns.googleapis.com/query/count` |
| Recommended | VPC Flow Logs | `compute.googleapis.com/instance/network/received_packets_count` |
| Recommended | GCS Data Access Audit Logs | `storage.googleapis.com/api/request_count` |
| Recommended | BigQuery Data Access Audit Logs | `bigquery.googleapis.com/query/count` |
| Recommended | Cloud SQL Data Access Audit Logs | `cloudsql.googleapis.com/database/network/connections` |
| Optional | Google Workspace Logs | Manual estimate only |

## Prerequisites

- **Python 3.x**
- **Google Cloud SDK** (`gcloud`) — for ADC authentication
- **IAM Permissions:**
  - `monitoring.timeSeries.list` on target projects
  - `resourcemanager.projects.list` on the org/folder (for multi-project scans)

## Quick Start

```bash
git clone <repository-url>
cd google_scc_log_estimator
chmod +x start_web.sh
```

### Option A: Service Account Key (JWT)

```bash
./start_web.sh -k /path/to/sa-key.json
```

### Option B: gcloud ADC

```bash
gcloud auth application-default login
./start_web.sh
```

Then open http://127.0.0.1:5000 in your browser.

## CLI Reference

Both `start_web.sh` and `app.py` accept the same flags:

```
Usage: ./start_web.sh [OPTIONS]
       python3 app.py [OPTIONS]

Options:
  -k, --key-file PATH   Path to a GCP service account JSON key file (JWT).
                         Validated at startup; exits with guidance on failure.
  -p, --port PORT        Flask listen port           (default: 5000)
  -H, --host HOST        Flask listen address        (default: 127.0.0.1)
  -d, --debug            Run Flask in debug mode with auto-reload
  -h, --help             Show help text and exit
```

### Examples

```bash
# Service account key, custom port, debug mode
./start_web.sh -k ~/keys/scc-reader.json -p 8080 -d

# Bind to all interfaces (e.g. for Cloud Shell or a VM)
./start_web.sh -H 0.0.0.0

# Use app.py directly (skip venv setup)
python3 app.py -k sa.json -p 8080 -H 0.0.0.0 -d

# Show full help
python3 app.py --help
```

## Authentication Priority

Credentials are resolved in this order:

1. `--key-file` / `-k` CLI flag — validated immediately; hard exit on failure with guidance.
2. `GOOGLE_APPLICATION_CREDENTIALS` environment variable — used if set.
3. gcloud Application Default Credentials — used as fallback.

If no credentials are found, `start_web.sh` offers an interactive menu to log in via gcloud or provide a key file path. `app.py` prints a warning and starts (the UI shows an auth-error banner).

## How It Works

1. **Baseline** — retrieves metric counts for the previous 7 days from Cloud Monitoring.
2. **Extrapolation** — divides the 7-day total by 7 and multiplies by 30.
3. **Payload Estimation** — for always-on logs, uses actual `byte_count` data. For not-yet-enabled logs, applies an estimated KB-per-entry multiplier.
4. **Costing** — volume in GiB × $0.50 (standard Cloud Logging ingestion pricing).
5. **Multi-project** — for org/folder scope, discovers all active projects via the Resource Manager API and repeats steps 1–4 for each.

## Directory Structure

```
├── app.py                 # Flask app: CLI args, auth, metrics, estimation, routes
├── templates/
│   └── index.html         # Web UI: scope selector, log checkboxes, results
├── start_web.sh           # Setup script: venv, deps, auth gate, app launch
├── CLAUDE.md              # Claude Code guidance
└── README.md              # This file
```
