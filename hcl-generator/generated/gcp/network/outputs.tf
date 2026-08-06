output "vpc_test_01_id" {
  description = "Identifiant du VPC GCP"
  value       = google_compute_network.vpc_test_01.id
}

output "subnet_test_01_id" {
  description = "Identifiant du subnet GCP"
  value       = google_compute_subnetwork.subnet_test_01.id
}

output "vpc_test_02_id" {
  description = "Identifiant du VPC GCP"
  value       = google_compute_network.vpc_test_02.id
}

output "subnet_test_02_id" {
  description = "Identifiant du subnet GCP"
  value       = google_compute_subnetwork.subnet_test_02.id
}

output "vpc_clean_test_01_id" {
  description = "Identifiant du VPC GCP"
  value       = google_compute_network.vpc_clean_test_01.id
}

output "subnet_clean_test_01_id" {
  description = "Identifiant du subnet GCP"
  value       = google_compute_subnetwork.subnet_clean_test_01.id
}

output "vpc_modular_test_01_id" {
  description = "Identifiant du VPC GCP"
  value       = google_compute_network.vpc_modular_test_01.id
}

output "subnet_modular_test_01_id" {
  description = "Identifiant du subnet GCP"
  value       = google_compute_subnetwork.subnet_modular_test_01.id
}
