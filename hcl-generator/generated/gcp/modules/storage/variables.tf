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
