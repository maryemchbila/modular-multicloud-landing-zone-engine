variable "gcp_project_id" {
  description = "Identifiant du projet Google Cloud"
  type        = string
}

variable "gcp_region" {
  description = "Region Google Cloud par defaut"
  type        = string
  default     = "europe-west1"
}

variable "gcp_zone" {
  description = "Zone Google Cloud par defaut"
  type        = string
  default     = "europe-west1-b"
}
