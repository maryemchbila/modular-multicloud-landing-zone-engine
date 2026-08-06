output "vpc_backend_01_id" {
  description = "Identifiant du VPC GCP"
  value       = google_compute_network.vpc_backend_01.id
}

output "subnet_backend_01_id" {
  description = "Identifiant du subnet GCP"
  value       = google_compute_subnetwork.subnet_backend_01.id
}
