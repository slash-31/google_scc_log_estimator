#!/bin/bash

# Define colors for terminal output
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}--- GCP Log Estimator Setup ---${NC}"

# 1. Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python3 could not be found. Please install Python 3 to continue.${NC}"
    exit 1
fi

# 2. Create Virtual Environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# 3. Activate Virtual Environment
source venv/bin/activate

# 4. Install/Update Requirements
echo -e "${BLUE}Installing dependencies...${NC}"
pip install --upgrade pip --quiet
pip install flask google-cloud-monitoring google-cloud-resource-manager --quiet

# ---------------------------------------------------------------------------
# 5. Authentication Gate
#    The app will NOT start unless one of these is satisfied:
#      (a) GOOGLE_APPLICATION_CREDENTIALS points to a valid SA key file (JWT)
#      (b) gcloud Application Default Credentials are active
# ---------------------------------------------------------------------------

AUTH_OK=false

# Expand tilde in GOOGLE_APPLICATION_CREDENTIALS if present
if [[ "$GOOGLE_APPLICATION_CREDENTIALS" == "~"* ]]; then
    export GOOGLE_APPLICATION_CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS/#\~/$HOME}"
fi

# --- Check (a): Service Account key file ---
if [[ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]]; then
    SA_FILE="$GOOGLE_APPLICATION_CREDENTIALS"
    if [[ -f "$SA_FILE" ]]; then
        # Validate it looks like a SA key JSON (has type + project_id fields)
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
            echo -e "${GREEN}Authenticated via service account key file: $SA_FILE${NC}"
        else
            echo -e "${RED}GOOGLE_APPLICATION_CREDENTIALS is set but the file is not a valid key.${NC}"
            echo -e "${RED}File: $SA_FILE${NC}"
        fi
    else
        echo -e "${RED}GOOGLE_APPLICATION_CREDENTIALS is set but the file does not exist.${NC}"
        echo -e "${RED}Path: $SA_FILE${NC}"
    fi
fi

# --- Check (b): gcloud ADC ---
if [[ "$AUTH_OK" == false ]]; then
    echo -e "${BLUE}Checking gcloud Application Default Credentials...${NC}"
    if gcloud auth application-default print-access-token &> /dev/null; then
        AUTH_OK=true
        ACCT=$(gcloud config get-value account 2>/dev/null)
        echo -e "${GREEN}Authenticated via gcloud ADC ($ACCT)${NC}"
    fi
fi

# --- Neither worked — offer options ---
if [[ "$AUTH_OK" == false ]]; then
    echo ""
    echo -e "${YELLOW}No valid authentication found.${NC}"
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
                echo -e "${RED}File not found: $SA_PATH${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Exiting — authentication is required.${NC}"
            exit 1
            ;;
    esac
fi

# --- Final gate ---
if [[ "$AUTH_OK" == false ]]; then
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED} FATAL: No valid GCP credentials found. ${NC}"
    echo -e "${RED} The app cannot start without auth.     ${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "Options:"
    echo "  • Run: gcloud auth application-default login"
    echo "  • Or set: export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json"
    exit 1
fi

# 6. Launch the App
echo ""
echo -e "${GREEN}Authentication verified. Launching web app at http://127.0.0.1:5000${NC}"
echo "Press Ctrl+C to stop the server."
python3 app.py
