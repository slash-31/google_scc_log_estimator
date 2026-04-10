#!/bin/bash
# Deployment script for GCP Security Logging Estimator
# Target Project: florida-cloudrunn-apps
# Secrets Project: core-services-e01c

set -e

PROJECT_ID="florida-cloudrunn-apps"
REGION="us-central1"
SERVICE_NAME="scc-log-estimator"
KEY_FILE="$HOME/.creds/terraform-admin-jwt.json"

# Check if we are in the right environment
echo "Preparing deployment for project: $PROJECT_ID"

# 1. Authenticate using the provided key file
if [ -f "$KEY_FILE" ]; then
    echo "Authenticating with $KEY_FILE..."
    gcloud auth activate-service-account --key-file="$KEY_FILE" --quiet
    gcloud config set project "$PROJECT_ID" --quiet
else
    echo "Error: Key file $KEY_FILE not found."
    echo "Please ensure your service account key is at $KEY_FILE"
    exit 1
fi

# 2. Enable required APIs in the deployment project
echo "Enabling required APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    monitoring.googleapis.com \
    cloudresourcemanager.googleapis.com \
    serviceusage.googleapis.com

# 3. Create Artifact Registry repository if it doesn't exist
REPO_NAME="cloud-run-source-deploy"
if ! gcloud artifacts repositories describe "$REPO_NAME" --location="$REGION" >/dev/null 2>&1; then
    echo "Creating Artifact Registry repository..."
    gcloud artifacts repositories create "$REPO_NAME" \
        --repository-format=docker \
        --location="$REGION" \
        --description="Docker repository for Cloud Run services"
fi

# 4. Build and Submit the container image
echo "Building and submitting image to Artifact Registry..."
IMAGE_TAG="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$SERVICE_NAME:latest"
gcloud builds submit --tag "$IMAGE_TAG" .

# 5. Deploy to Cloud Run
echo "Deploying to Cloud Run..."
gcloud run deploy "$SERVICE_NAME" \
    --image "$IMAGE_TAG" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --description "GCP Security Logging Estimator"

# 6. IAM Note for Secrets and DNS (in core-services-e01c)
SERVICE_ACCOUNT=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format 'value(status.address.url)' | xargs -n1 gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format 'value(spec.template.spec.serviceAccountName)')
# If using default compute SA:
if [ -z "$SERVICE_ACCOUNT" ]; then
    SERVICE_ACCOUNT=$(gcloud projects get-iam-policy "$PROJECT_ID" --format="value(bindings.role)" --filter="role:roles/editor" | grep compute | head -n 1) # Simplification
    # Better: just use the project number
    PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
    SERVICE_ACCOUNT="$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
fi

echo "---------------------------------------------------"
echo "Deployment Complete!"
echo "Service URL: $(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)')"
echo "---------------------------------------------------"
echo "Next Steps (IAM for core-services-e01c):"
echo "1. Grant the Cloud Run service account access to secrets in core-services-e01c:"
echo "   gcloud projects add-iam-policy-binding core-services-e01c \\"
echo "     --member=\"serviceAccount:$SERVICE_ACCOUNT\" \\"
echo "     --role=\"roles/secretmanager.secretAccessor\""
echo ""
echo "2. For DNS (managed in core-services-e01c):"
echo "   Use Cloud Run Custom Domains or a Global Load Balancer to map your domain"
echo "   to the service URL provided above."
echo "---------------------------------------------------"
