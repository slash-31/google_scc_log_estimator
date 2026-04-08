#!/bin/bash

# Define colors for terminal output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${BLUE}--- GCP Log Estimator Setup ---${NC}"

# 1. Check if Python 3 is installed
if ! command -v python3 &> /dev/null
then
    echo "Python3 could not be found. Please install Python 3 to continue."
    exit
fi

# 2. Create Virtual Environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# 3. Activate Virtual Environment
source venv/bin/activate

# Expand tilde in GOOGLE_APPLICATION_CREDENTIALS if it exists
if [[ "$GOOGLE_APPLICATION_CREDENTIALS" == "~"* ]]; then
    export GOOGLE_APPLICATION_CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS/#\~/$HOME}"
fi

# 4. Install/Update Requirements
echo -e "${BLUE}Installing dependencies...${NC}"
pip install --upgrade pip
pip install flask google-cloud-monitoring

# 5. Check GCloud Auth (Silent check)
if ! gcloud auth application-default print-access-token &> /dev/null; then
    echo -e "${BLUE}ADC Credentials not found. Launching browser for authentication...${NC}"
    gcloud auth application-default login
fi

# 6. Launch the App
echo -e "${GREEN}Successfully configured. Launching web app at http://127.0.0.1:5000${NC}"
echo "Press Ctrl+C to stop the server."
python3 app.py
