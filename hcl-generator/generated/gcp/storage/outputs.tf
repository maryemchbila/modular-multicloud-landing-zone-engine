output "bucket_test_01_id" {
  description = "Identifiant du bucket GCS"
  value       = google_storage_bucket.bucket_test_01.id
}

output "bucket_test_01_url" {
  description = "URL du bucket GCS"
  value       = google_storage_bucket.bucket_test_01.url
}
