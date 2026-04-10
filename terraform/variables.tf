variable "project_id" {
  description = "The GCP project ID to deploy to"
  type        = string
}

variable "region" {
  description = "The GCP region to deploy to"
  type        = string
}

variable "service_name" {
  description = "The name of the Cloud Run service"
  type        = string
}

variable "secrets_project_id" {
  description = "The GCP project ID where secrets are stored"
  type        = string
}

variable "sa_secret_id" {
  description = "The ID of the secret containing the Service Account JSON key"
  type        = string
  default     = ""
}

variable "oauth_client_id" {
  description = "OAuth2 Client ID"
  type        = string
  default     = ""
}

variable "oauth_client_secret" {
  description = "OAuth2 Client Secret"
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "The container image tag to deploy"
  type        = string
}

variable "artifact_repo_id" {
  description = "The ID of the Artifact Registry repository"
  type        = string
}

variable "org_id" {
  description = "Optional GCP Organization ID to pre-fill in the UI"
  type        = string
}
