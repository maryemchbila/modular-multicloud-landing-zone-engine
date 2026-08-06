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
