terraform {
  backend "gcs" {
    bucket = "florida-cloudrunn-apps-terraform-state"
    prefix = "scc-log-estimator"
  }
}
