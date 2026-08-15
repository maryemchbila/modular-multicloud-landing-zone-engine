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

variable "vm_test_26_name" {
  description = "Nom de la VM GCP"
  type        = string
}


variable "vm_test_26_machine_type" {
  description = "Type de machine GCP"
  type        = string
}


variable "vm_test_26_zone" {
  description = "Zone GCP"
  type        = string
}


variable "vm_test_26_image" {
  description = "Image de démarrage GCP"
  type        = string
}


variable "vm_test_26_network" {
  description = "Réseau VPC GCP"
  type        = string
}


variable "vm_e2e_01_name" {
  description = "Nom de la VM GCP"
  type        = string
}


variable "vm_e2e_01_machine_type" {
  description = "Type de machine GCP"
  type        = string
}


variable "vm_e2e_01_zone" {
  description = "Zone GCP"
  type        = string
}


variable "vm_e2e_01_image" {
  description = "Image de démarrage GCP"
  type        = string
}


variable "vm_e2e_01_network" {
  description = "Réseau VPC GCP"
  type        = string
}


variable "vm_e2_01_name" {
  description = "Nom de la VM GCP"
  type        = string
}


variable "vm_e2_01_machine_type" {
  description = "Type de machine GCP"
  type        = string
}


variable "vm_e2_01_zone" {
  description = "Zone GCP"
  type        = string
}


variable "vm_e2_01_image" {
  description = "Image de démarrage GCP"
  type        = string
}


variable "vm_e2_01_network" {
  description = "Réseau VPC GCP"
  type        = string
}


variable "vpc_backend_01_name" {
  description = "Nom du VPC GCP"
  type        = string
}


variable "subnet_backend_01_name" {
  description = "Nom du subnet GCP"
  type        = string
}


variable "subnet_backend_01_cidr" {
  description = "Plage CIDR du subnet"
  type        = string
}


variable "subnet_backend_01_region" {
  description = "Région du subnet GCP"
  type        = string
}


variable "bucket_archive_01_name" {
  description = "Nom du bucket GCS"
  type        = string
}


variable "bucket_archive_01_location" {
  description = "Localisation du bucket GCS"
  type        = string
}


variable "bucket_archive_01_storage_class" {
  description = "Classe de stockage du bucket GCS"
  type        = string
}


variable "bucket_archive_01_uniform_bucket_level_access" {
  description = "Active Uniform Bucket Level Access"
  type        = bool
}


variable "bucket_logs_01_name" {
  description = "Nom du bucket GCS"
  type        = string
}


variable "bucket_logs_01_location" {
  description = "Localisation du bucket GCS"
  type        = string
}


variable "bucket_logs_01_storage_class" {
  description = "Classe de stockage du bucket GCS"
  type        = string
}


variable "bucket_logs_01_uniform_bucket_level_access" {
  description = "Active Uniform Bucket Level Access"
  type        = bool
}


variable "sa_logging_01_account_id" {
  description = "Identifiant du compte de service GCP"
  type        = string
}


variable "sa_logging_01_display_name" {
  description = "Nom affiché du compte de service GCP"
  type        = string
}


variable "sa_logging_01_description" {
  description = "Description du compte de service GCP"
  type        = string
}


variable "sa_logging_01_project_id" {
  description = "Identifiant du projet GCP"
  type        = string
}


variable "sa_logging_01_role" {
  description = "Rôle IAM attribué au compte de service"
  type        = string
}


variable "sa_monitoring_01_account_id" {
  description = "Identifiant du compte de service GCP"
  type        = string
}


variable "sa_monitoring_01_display_name" {
  description = "Nom affiché du compte de service GCP"
  type        = string
}


variable "sa_monitoring_01_description" {
  description = "Description du compte de service GCP"
  type        = string
}


variable "sa_monitoring_01_project_id" {
  description = "Identifiant du projet GCP"
  type        = string
}


variable "sa_monitoring_01_role" {
  description = "Rôle IAM attribué au compte de service"
  type        = string
}


variable "sa_storage_viewer_01_account_id" {
  description = "Identifiant du compte de service GCP"
  type        = string
}


variable "sa_storage_viewer_01_display_name" {
  description = "Nom affiché du compte de service GCP"
  type        = string
}


variable "sa_storage_viewer_01_description" {
  description = "Description du compte de service GCP"
  type        = string
}


variable "sa_storage_viewer_01_project_id" {
  description = "Identifiant du projet GCP"
  type        = string
}


variable "sa_storage_viewer_01_role" {
  description = "Rôle IAM attribué au compte de service"
  type        = string
}


variable "sa_compute_viewer_01_account_id" {
  description = "Identifiant du compte de service GCP"
  type        = string
}


variable "sa_compute_viewer_01_display_name" {
  description = "Nom affiché du compte de service GCP"
  type        = string
}


variable "sa_compute_viewer_01_description" {
  description = "Description du compte de service GCP"
  type        = string
}


variable "sa_compute_viewer_01_project_id" {
  description = "Identifiant du projet GCP"
  type        = string
}


variable "sa_compute_viewer_01_role" {
  description = "Rôle IAM attribué au compte de service"
  type        = string
}
