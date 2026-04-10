output "service_url" {
  value       = google_cloud_run_v2_service.default.uri
  description = "The URL of the deployed Cloud Run service"
}

output "artifact_registry_repo" {
  value       = google_artifact_registry_repository.repo.id
  description = "The ID of the Artifact Registry repository"
}

output "service_account_email" {
  value       = google_service_account.cloud_run_sa.email
  description = "The email of the service account used by Cloud Run"
}
