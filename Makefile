# Configuration
PROJECT_ID=florida-cloudrunn-apps
REGION=us-central1
REPO_NAME=cloud-run-source-deploy
SERVICE_NAME=scc-log-estimator
IMAGE_TAG=latest
IMAGE_URL=$(REGION)-docker.pkg.dev/$(PROJECT_ID)/$(REPO_NAME)/$(SERVICE_NAME):$(IMAGE_TAG)
GOOGLE_APPLICATION_CREDENTIALS=$(HOME)/.creds/terraform-admin-jwt.json

.PHONY: all build push deploy clean tf-init tf-plan tf-apply cloud-build

all: cloud-build tf-apply

# 1. Build and push using Cloud Build (cleanest for GCP env)
cloud-build:
	gcloud builds submit --tag $(IMAGE_URL) --project $(PROJECT_ID)

# 2. Terraform workflows
tf-init:
	export GOOGLE_APPLICATION_CREDENTIALS=$(GOOGLE_APPLICATION_CREDENTIALS) && \
	cd terraform && terraform init

tf-plan:
	export GOOGLE_APPLICATION_CREDENTIALS=$(GOOGLE_APPLICATION_CREDENTIALS) && \
	cd terraform && terraform plan

tf-apply:
	export GOOGLE_APPLICATION_CREDENTIALS=$(GOOGLE_APPLICATION_CREDENTIALS) && \
	cd terraform && terraform apply -auto-approve

# Local build/push if needed
local-build:
	docker build -t $(IMAGE_URL) .

local-push:
	docker push $(IMAGE_URL)
