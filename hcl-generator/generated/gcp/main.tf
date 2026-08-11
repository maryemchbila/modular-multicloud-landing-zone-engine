module "compute" {
  source                  = "./modules/compute"
  vm_test_26_image        = var.vm_test_26_image
  vm_test_26_machine_type = var.vm_test_26_machine_type
  vm_test_26_name         = var.vm_test_26_name
  vm_test_26_network      = var.vm_test_26_network
  vm_test_26_zone         = var.vm_test_26_zone
}


module "network" {
  source                   = "./modules/network"
  subnet_backend_01_cidr   = var.subnet_backend_01_cidr
  subnet_backend_01_name   = var.subnet_backend_01_name
  subnet_backend_01_region = var.subnet_backend_01_region
  vpc_backend_01_name      = var.vpc_backend_01_name
}


module "storage" {
  source                                        = "./modules/storage"
  bucket_archive_01_location                    = var.bucket_archive_01_location
  bucket_archive_01_name                        = var.bucket_archive_01_name
  bucket_archive_01_storage_class               = var.bucket_archive_01_storage_class
  bucket_archive_01_uniform_bucket_level_access = var.bucket_archive_01_uniform_bucket_level_access
  bucket_logs_01_location                       = var.bucket_logs_01_location
  bucket_logs_01_name                           = var.bucket_logs_01_name
  bucket_logs_01_storage_class                  = var.bucket_logs_01_storage_class
  bucket_logs_01_uniform_bucket_level_access    = var.bucket_logs_01_uniform_bucket_level_access
}


module "iam" {
  source                            = "./modules/iam"
  sa_compute_viewer_01_account_id   = var.sa_compute_viewer_01_account_id
  sa_compute_viewer_01_description  = var.sa_compute_viewer_01_description
  sa_compute_viewer_01_display_name = var.sa_compute_viewer_01_display_name
  sa_compute_viewer_01_project_id   = var.sa_compute_viewer_01_project_id
  sa_compute_viewer_01_role         = var.sa_compute_viewer_01_role
  sa_logging_01_account_id          = var.sa_logging_01_account_id
  sa_logging_01_description         = var.sa_logging_01_description
  sa_logging_01_display_name        = var.sa_logging_01_display_name
  sa_logging_01_project_id          = var.sa_logging_01_project_id
  sa_logging_01_role                = var.sa_logging_01_role
  sa_monitoring_01_account_id       = var.sa_monitoring_01_account_id
  sa_monitoring_01_description      = var.sa_monitoring_01_description
  sa_monitoring_01_display_name     = var.sa_monitoring_01_display_name
  sa_monitoring_01_project_id       = var.sa_monitoring_01_project_id
  sa_monitoring_01_role             = var.sa_monitoring_01_role
  sa_storage_viewer_01_account_id   = var.sa_storage_viewer_01_account_id
  sa_storage_viewer_01_description  = var.sa_storage_viewer_01_description
  sa_storage_viewer_01_display_name = var.sa_storage_viewer_01_display_name
  sa_storage_viewer_01_project_id   = var.sa_storage_viewer_01_project_id
  sa_storage_viewer_01_role         = var.sa_storage_viewer_01_role
}
