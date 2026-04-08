# Google Cloud Security Logging Estimator

A specialized tool designed to help security engineers estimate the 30-day costs associated with enabling critical security logs in Google Cloud Platform (GCP). 

This tool provides data-driven projections for Security Command Center (SCC) and Event Threat Detection (ETD) by analyzing live traffic metrics from your GCP project.

## Features

- **Live Metric Analysis**: Fetches real-time traffic data (request counts, query counts) from the last 7 days via the Google Cloud Monitoring API.
- **Cost Extrapolation**: Automatically calculates 30-day volume and cost projections based on current usage patterns.
- **Log Type Support**:
  - Cloud DNS Logs (Essential for ETD)
  - HTTP(S) Load Balancer Logs
  - Cloud Armor/WAF Logs
  - GCS Data Access (Audit) Logs
  - BigQuery Data Access (Audit) Logs
  - IAP Access Logs

## Prerequisites

- **Python 3.x**: Ensure Python 3 is installed on your system.
- **Google Cloud SDK (gcloud)**: Must be installed and configured.
- **Permissions**: The user or service account must have `monitoring.timeSeries.list` permissions on the target GCP projects.

## Getting Started

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd google_scc_log_estimator
   ```

2. **Run the setup and start script**:
   The provided `start_web.sh` script handles virtual environment creation, dependency installation, and authentication setup.
   ```bash
   chmod +x start_web.sh
   ./start_web.sh
   ```

3. **Access the application**:
   Once the script is running, open your browser and navigate to:
   `http://127.0.0.1:5000`

## How it Works

The estimator uses the following logic to derive its projections:

1. **Baseline**: It retrieves metric counts (e.g., `loadbalancing.googleapis.com/https/request_count`) for the previous 7 days.
2. **Extrapolation**: It divides the 7-day total by 7 and multiplies by 30 to estimate monthly activity.
3. **Payload Calculation**: It applies a weighted average KB size per log entry (based on GCP metadata overhead) for each log type.
4. **Costing**: Estimates are calculated using a standard rate of **$0.50 per GiB** (standard Cloud Logging ingestion pricing).

## Directory Structure

- `app.py`: The Flask application containing the backend logic and metric fetching.
- `templates/index.html`: The web interface built with Bootstrap.
- `start_web.sh`: Automation script for setup and deployment.
