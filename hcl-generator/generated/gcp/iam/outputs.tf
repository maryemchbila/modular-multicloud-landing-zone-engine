output "sa_delete_b_01_email" {
  description = "Adresse email du compte de service GCP"
  value       = google_service_account.sa_delete_b_01.email
}

output "sa_delete_b_01_name" {
  description = "Nom complet du compte de service GCP"
  value       = google_service_account.sa_delete_b_01.name
}

output "sa_delete_b_01_unique_id" {
  description = "Identifiant unique du compte de service GCP"
  value       = google_service_account.sa_delete_b_01.unique_id
}
