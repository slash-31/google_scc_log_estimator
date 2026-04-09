# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GCP Security Logging Cost Estimator — a Flask web app that estimates 30-day Cloud Logging ingestion costs for enabling security log sources recommended by SCC Premium (Event Threat Detection and Security Health Analytics).

It fetches real metric data from the Cloud Monitoring API over a 7-day window, extrapolates to 30 days, and applies per-log-type size estimates with $0.50/GiB pricing.

## Running the App

```bash
./start_web.sh          # creates venv, installs deps, validates auth, starts Flask on :5000
```

Or manually:
```bash
python3 -m venv venv && source venv/bin/activate
pip install flask google-cloud-monitoring google-cloud-resource-manager
python3 app.py          # serves on http://127.0.0.1:5000
```

## Authentication

Two auth methods are supported. The start script gates on one being valid before launching:

1. **Service account key (JWT):** Set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json`. The script validates the file is well-formed JSON with type=service_account.
2. **gcloud ADC:** `gcloud auth application-default login`. The script checks token retrieval works.

The app shows current auth status (method, identity, default project) in the UI header.

Required permissions:
- `monitoring.timeSeries.list` on target projects
- `resourcemanager.projects.list` on the org/folder (for org-wide scanning)

## Architecture

Single-file Flask app (`app.py`) with one route (`/`, GET+POST). No database, no tests.

- `app.py` — backend: auth detection, org project discovery, metric fetching, cost estimation
- `templates/index.html` — Jinja2 template with Bootstrap 5, scope selector, categorized form, results
- `start_web.sh` — setup/launch script with strict auth gating

## Key Design Decisions

**Scope levels:** Single project, folder, or entire organization. Org/folder modes use the Resource Manager API to discover active projects, then iterate metrics across all of them.

**Log source categories** mirror the ETD/SHA best-practices guidance:
- `must_have` — Admin Activity + System Event audit logs (always on, no extra cost)
- `recommended` — DNS, VPC Flow, GCS/BQ/Cloud SQL Data Access audit logs
- `optional` — Google Workspace logs (manual estimate only)

**Two estimation approaches** depending on log type:
- Always-on logs: query `logging.googleapis.com/byte_count` for actual ingestion bytes
- Not-yet-enabled logs: use proxy metrics (API request counts etc.) x estimated KB per entry

**VPC Flow Logs** support a user-adjustable sampling rate (0.1-1.0). Packet count is converted to estimated flow records using a configurable `packets_per_record` ratio.

**`LOG_SOURCES`** list in `app.py` is the central data structure. Each entry defines the metric to query, estimation method, category, and UI metadata. The HTML form checkbox values must match the `key` field.
