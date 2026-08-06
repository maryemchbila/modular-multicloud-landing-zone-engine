output "bucket_archive_01_id" {
  description = "Identifiant du bucket GCS"
  value       = google_storage_bucket.bucket_archive_01.id
}

output "bucket_archive_01_url" {
  description = "URL du bucket GCS"
  value       = google_storage_bucket.bucket_archive_01.url
}

output "bucket_logs_01_id" {
  description = "Identifiant du bucket GCS"
  value       = google_storage_bucket.bucket_logs_01.id
}

output "bucket_logs_01_url" {
  description = "URL du bucket GCS"
  value       = google_storage_bucket.bucket_logs_01.url
}
