#!/bin/bash
# ===========================================================================
# start_web.sh — GCP Security Logging Estimator launcher
#
# Sets up a Python virtual environment, installs dependencies, validates GCP
# authentication, and starts the Flask application.
#
# Usage:
#   ./start_web.sh [OPTIONS]
#
# Options:
#   -k, --key-file PATH     Path to a GCP service account JSON key file (JWT).
#                            If provided, the key is validated before the app
#                            starts.  On failure the script exits with guidance.
#   -c, --preflight PROJECT  Run preflight checks (auth, API access) against
#                            PROJECT and exit without starting the server.
#   -p, --port PORT          Flask listen port           (default: 5000)
#   -H, --host HOST          Flask listen address        (default: 127.0.0.1)
#   -d, --debug              Run Flask in debug mode with auto-reload
#   -h, --help               Show this help text and exit
#
# Authentication priority (same as app.py):
#   1. --key-file / -k  flag  (service account JWT)
#   2. GOOGLE_APPLICATION_CREDENTIALS environment variable
#   3. gcloud Application Default Credentials
#
# Examples:
#   ./start_web.sh -k ~/keys/scc-reader.json
#   ./start_web.sh -k sa.json -p 8080 -H 0.0.0.0 -d
#   ./start_web.sh                              # uses gcloud ADC
# ===========================================================================

# ----- Terminal colours ---------------------------------------------------
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # No Color

# ----- Default values for optional arguments ------------------------------
KEY_FILE=""
PREFLIGHT_PROJECT=""
PORT="5000"
HOST="127.0.0.1"
DEBUG_FLAG=""

# ----- Parse command-line arguments (long + short) ------------------------
# Supported:  -k/--key-file  -p/--port  -H/--host  -d/--debug  -h/--help
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            # Print the header comment block as a help message.
            sed -n '2,/^# =====/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        -k|--key-file)
            KEY_FILE="$2"
            shift 2
            ;;
        -c|--preflight)
            PREFLIGHT_PROJECT="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -H|--host)
            HOST="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG_FLAG="--debug"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Run  $0 --help  for usage."
            exit 1
            ;;
    esac
done

echo -e "${BLUE}--- GCP Log Estimator Setup ---${NC}"

# ----- 1. Verify Python 3 is installed -----------------------------------
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: python3 not found. Install Python 3 to continue.${NC}"
    exit 1
fi

# ----- 2. Create virtual environment if it doesn't already exist ----------
if [ ! -d "venv" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# ----- 3. Activate virtual environment -----------------------------------
# shellcheck disable=SC1091
source venv/bin/activate

# ----- 4. Install / update Python dependencies ---------------------------
echo -e "${BLUE}Installing dependencies...${NC}"
pip install --upgrade pip --quiet
pip install flask google-cloud-monitoring google-cloud-resource-manager \
            google-auth --quiet

# ===========================================================================
# 5. Authentication Gate
#
#    The app will NOT start unless one of these is satisfied:
#      (a) --key-file / -k  points to a valid SA key file (JWT)
#      (b) GOOGLE_APPLICATION_CREDENTIALS env var points to a valid key
#      (c) gcloud Application Default Credentials are active
#
#    If -k is provided and fails, we exit immediately with instructions.
#    If no method works, we offer an interactive menu.
# ===========================================================================

AUTH_OK=false

# Expand tilde in GOOGLE_APPLICATION_CREDENTIALS if already set.
if [[ "$GOOGLE_APPLICATION_CREDENTIALS" == "~"* ]]; then
    export GOOGLE_APPLICATION_CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS/#\~/$HOME}"
fi

# ----- Check (a): explicit --key-file flag --------------------------------
if [[ -n "$KEY_FILE" ]]; then
    # Expand tilde in the user-supplied path.
    KEY_FILE="${KEY_FILE/#\~/$HOME}"

    if [[ ! -f "$KEY_FILE" ]]; then
        echo ""
        echo -e "${RED}ERROR: Key file not found: ${KEY_FILE}${NC}"
        echo ""
        echo "Verify the path and try again, or use an alternative method:"
        echo "  1. Fix path:   $0 -k /correct/path/to/key.json"
        echo "  2. gcloud ADC: gcloud auth application-default login && $0"
        echo "  3. Env var:    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json && $0"
        exit 1
    fi

    # Validate the JSON key structure (must be type=service_account).
    if ! python3 -c "
import json, sys
try:
    d = json.load(open('${KEY_FILE}'))
    assert d.get('type') == 'service_account', \
        f\"type is '{d.get(\"type\")}', expected 'service_account'\"
    print(f\"Service account: {d.get('client_email', 'unknown')}\")
    print(f\"Project:         {d.get('project_id', 'N/A')}\")
except Exception as e:
    print(f'Validation failed: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
        echo ""
        echo -e "${RED}ERROR: ${KEY_FILE} is not a valid service account key.${NC}"
        echo ""
        echo "The file must be a JSON key downloaded from the GCP Console with"
        echo "  \"type\": \"service_account\""
        echo ""
        echo "Alternative authentication options:"
        echo "  1. gcloud ADC: gcloud auth application-default login && $0"
        echo "  2. Env var:    export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json && $0"
        exit 1
    fi

    # Key looks good — set the env var so Google client libs pick it up.
    export GOOGLE_APPLICATION_CREDENTIALS="$KEY_FILE"
    AUTH_OK=true
    echo -e "${GREEN}Authenticated via key file: ${KEY_FILE}${NC}"
fi

# ----- Check (b): GOOGLE_APPLICATION_CREDENTIALS env var ------------------
if [[ "$AUTH_OK" == false && -n "$GOOGLE_APPLICATION_CREDENTIALS" ]]; then
    SA_FILE="$GOOGLE_APPLICATION_CREDENTIALS"
    if [[ -f "$SA_FILE" ]]; then
        if python3 -c "
import json, sys
try:
    d = json.load(open('$SA_FILE'))
    assert d.get('type') in ('service_account', 'authorized_user'), 'bad type'
    print(f\"Auth: {d['type']} — {d.get('client_email', d.get('client_id', 'unknown'))}\")
except Exception as e:
    print(f'Invalid key file: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
            AUTH_OK=true
            echo -e "${GREEN}Authenticated via GOOGLE_APPLICATION_CREDENTIALS: ${SA_FILE}${NC}"
        else
            echo -e "${RED}GOOGLE_APPLICATION_CREDENTIALS is set but the file is not a valid key.${NC}"
            echo -e "${RED}File: $SA_FILE${NC}"
        fi
    else
        echo -e "${RED}GOOGLE_APPLICATION_CREDENTIALS is set but the file does not exist.${NC}"
        echo -e "${RED}Path: $SA_FILE${NC}"
    fi
fi

# ----- Check (c): gcloud Application Default Credentials ------------------
if [[ "$AUTH_OK" == false ]]; then
    echo -e "${BLUE}Checking gcloud Application Default Credentials...${NC}"
    if gcloud auth application-default print-access-token &> /dev/null; then
        AUTH_OK=true
        ACCT=$(gcloud config get-value account 2>/dev/null)
        echo -e "${GREEN}Authenticated via gcloud ADC (${ACCT})${NC}"
    fi
fi

# ----- Interactive fallback: no credentials found -------------------------
if [[ "$AUTH_OK" == false ]]; then
    echo ""
    echo -e "${YELLOW}No valid GCP credentials found.${NC}"
    echo ""
    echo "Choose an authentication method:"
    echo "  1) Log in with gcloud (opens browser for ADC)"
    echo "  2) Provide a service account key file path (JWT)"
    echo "  3) Exit"
    echo ""
    read -rp "Selection [1/2/3]: " AUTH_CHOICE

    case "$AUTH_CHOICE" in
        1)
            echo -e "${BLUE}Launching gcloud ADC login...${NC}"
            if gcloud auth application-default login; then
                AUTH_OK=true
                echo -e "${GREEN}gcloud ADC login successful.${NC}"
            else
                echo -e "${RED}gcloud ADC login failed.${NC}"
            fi
            ;;
        2)
            read -rp "Path to service account key JSON: " SA_PATH
            SA_PATH="${SA_PATH/#\~/$HOME}"
            if [[ -f "$SA_PATH" ]]; then
                if python3 -c "
import json, sys
d = json.load(open('$SA_PATH'))
assert d.get('type') == 'service_account', 'Not a service account key'
print(f\"Service account: {d.get('client_email', 'unknown')}\")
" 2>&1; then
                    export GOOGLE_APPLICATION_CREDENTIALS="$SA_PATH"
                    AUTH_OK=true
                    echo -e "${GREEN}Service account key validated and set.${NC}"
                else
                    echo -e "${RED}File is not a valid service account key.${NC}"
                fi
            else
                echo -e "${RED}File not found: ${SA_PATH}${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Exiting — authentication is required.${NC}"
            exit 1
            ;;
    esac
fi

# ----- Final gate: refuse to start without credentials --------------------
if [[ "$AUTH_OK" == false ]]; then
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED} FATAL: No valid GCP credentials found. ${NC}"
    echo -e "${RED} The app cannot start without auth.     ${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "Options:"
    echo "  • Pass a key file:  $0 -k /path/to/sa-key.json"
    echo "  • Use gcloud ADC:   gcloud auth application-default login"
    echo "  • Set env var:      export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json"
    exit 1
fi

# ===========================================================================
# 6. Launch the Flask application
#
# Forward CLI flags to app.py so the Python-side argparse sees them too.
# The --key-file is only forwarded if it was passed to this script, since
# the env var is already set and app.py will pick it up either way.
# ===========================================================================

# Build the app.py argument list.
APP_ARGS=("--host" "$HOST" "--port" "$PORT")
[[ -n "$DEBUG_FLAG" ]]        && APP_ARGS+=("--debug")
[[ -n "$KEY_FILE" ]]          && APP_ARGS+=("--key-file" "$KEY_FILE")
[[ -n "$PREFLIGHT_PROJECT" ]] && APP_ARGS+=("--preflight" "$PREFLIGHT_PROJECT")

# -- Preflight mode: run checks and exit -----------------------------------
if [[ -n "$PREFLIGHT_PROJECT" ]]; then
    echo ""
    echo -e "${BLUE}Running preflight checks against project: ${PREFLIGHT_PROJECT}${NC}"
    python3 app.py "${APP_ARGS[@]}"
    exit $?
fi

# -- Normal mode: launch the web server -----------------------------------
echo ""
echo -e "${GREEN}Authentication verified. Launching web app at http://${HOST}:${PORT}${NC}"
echo "Press Ctrl+C to stop the server."
python3 app.py "${APP_ARGS[@]}"
