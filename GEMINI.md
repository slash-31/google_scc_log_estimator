# Google Cloud Security Logging Estimator

A specialized tool for security engineers to estimate 30-day Cloud Logging ingestion costs when enabling log sources recommended by Security Command Center (SCC) Premium for Event Threat Detection (ETD) and Security Health Analytics (SHA).

## Project Overview

- **Purpose:** Analyzes live traffic metrics from the Cloud Monitoring API over a 7-day baseline to extrapolate and estimate 30-day logging costs.
- **Technology Stack:**
  - **Backend:** Python 3.x, Flask
  - **Frontend:** HTML/JS with Bootstrap 5
  - **APIs:** Google Cloud Monitoring, Resource Manager, Asset, and Auth
- **Architecture:** A single-page Flask application (`app.py`) that serves a web UI (`templates/index.html`) and handles metric collection and cost calculation on the backend.

## Building and Running

The project includes a helper script `start_web.sh` that automates environment setup and dependency installation.

### Prerequisites

- Python 3.x
- Google Cloud SDK (`gcloud`)

### Setup and Start

```bash
# Give execution permissions to the launcher script
chmod +x start_web.sh

# Start the application (automatically sets up venv and installs deps)
./start_web.sh
```

### CLI Arguments

Both `start_web.sh` and `app.py` support the following arguments:

- `-k, --key-file PATH`: Path to a GCP service account JSON key file.
- `-p, --port PORT`: Flask listen port (default: 5000).
- `-H, --host HOST`: Flask listen address (default: 127.0.0.1).
- `-d, --debug`: Run Flask in debug mode with auto-reload.
- `-o, --org-id ID`: Pre-fill the GCP Organization ID in the UI.

### Authentication

The application resolves credentials in the following priority:
1. `--key-file` / `-k` flag.
2. `GOOGLE_APPLICATION_CREDENTIALS` environment variable.
3. gcloud Application Default Credentials (ADC).

## Development Conventions

- **Python Standard:** Adheres to Python 3 standards.
- **Error Handling:** Robust validation for GCP credentials and API access during startup.
- **Concurrency:** Uses `ThreadPoolExecutor` in `app.py` for efficient scanning of multiple projects in Org/Folder scopes.
- **Frontend:** Minimalist design using Bootstrap 5, hosted via CDN to avoid local asset management overhead.
- **Logging:** Uses the standard `logging` module for console feedback and error reporting.
- **Scripting:** `start_web.sh` is the primary entry point for developers to ensure a consistent environment (venv, dependencies).
