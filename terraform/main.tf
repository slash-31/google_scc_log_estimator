provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Enable Required APIs
resource "google_project_service" "services" {
  for_each = toset([
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "monitoring.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com"
  ])
  service            = each.key
  disable_on_destroy = false
}

# 2. Artifact Registry for the container image
resource "google_artifact_registry_repository" "repo" {
  location      = var.region
  repository_id = var.artifact_repo_id
  description   = "Docker repository for Cloud Run services"
  format        = "DOCKER"

  depends_on = [google_project_service.services]
}

# 3. Service Account for Cloud Run
resource "google_service_account" "cloud_run_sa" {
  account_id   = "${var.service_name}-sa"
  display_name = "Service Account for SCC Log Estimator Cloud Run"
}

# 4. IAM Binding for Secrets Access (in core-services-e01c)
resource "google_project_iam_member" "secrets_accessor" {
  project = var.secrets_project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

# 5. IAM Binding for Monitoring/Resource Manager (needed by the app)
# Note: These are usually needed at the Org/Folder level for full functionality.
# This binding grants it on the deployment project itself for single-project scope.
resource "google_project_iam_member" "monitoring_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

# 6. Cloud Run Service
resource "google_cloud_run_v2_service" "default" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.cloud_run_sa.email
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.name}/${var.service_name}:${var.image_tag}"
      
      env {
        name  = "ORG_ID"
        value = var.org_id
      }

      env {
        name  = "SECRETS_PROJECT"
        value = var.secrets_project_id
      }

      env {
        name  = "GCP_SA_SECRET"
        value = var.sa_secret_id
      }

      env {
        name  = "OAUTH_CLIENT_ID"
        value = var.oauth_client_id
      }

      env {
        name  = "OAUTH_CLIENT_SECRET"
        value = var.oauth_client_secret
      }

      ports {
        container_port = 8080
      }
    }
  }

  depends_on = [google_project_service.services]
}

# 7. Make Cloud Run service publicly accessible (if desired)
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  location = google_cloud_run_v2_service.default.location
  name     = google_cloud_run_v2_service.default.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
