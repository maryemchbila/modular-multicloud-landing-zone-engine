output "vpc_backend_01_id" {
  value = module.network.vpc_backend_01_id
}


output "subnet_backend_01_id" {
  value = module.network.subnet_backend_01_id
}


output "bucket_archive_01_id" {
  value = module.storage.bucket_archive_01_id
}


output "bucket_archive_01_url" {
  value = module.storage.bucket_archive_01_url
}


output "bucket_logs_01_id" {
  value = module.storage.bucket_logs_01_id
}


output "bucket_logs_01_url" {
  value = module.storage.bucket_logs_01_url
}


output "sa_logging_01_email" {
  value = module.iam.sa_logging_01_email
}


output "sa_logging_01_name" {
  value = module.iam.sa_logging_01_name
}


output "sa_logging_01_unique_id" {
  value = module.iam.sa_logging_01_unique_id
}


output "sa_monitoring_01_email" {
  value = module.iam.sa_monitoring_01_email
}


output "sa_monitoring_01_name" {
  value = module.iam.sa_monitoring_01_name
}


output "sa_monitoring_01_unique_id" {
  value = module.iam.sa_monitoring_01_unique_id
}


output "sa_storage_viewer_01_email" {
  value = module.iam.sa_storage_viewer_01_email
}


output "sa_storage_viewer_01_name" {
  value = module.iam.sa_storage_viewer_01_name
}


output "sa_storage_viewer_01_unique_id" {
  value = module.iam.sa_storage_viewer_01_unique_id
}


output "sa_compute_viewer_01_email" {
  value = module.iam.sa_compute_viewer_01_email
}


output "sa_compute_viewer_01_name" {
  value = module.iam.sa_compute_viewer_01_name
}


output "sa_compute_viewer_01_unique_id" {
  value = module.iam.sa_compute_viewer_01_unique_id
}
