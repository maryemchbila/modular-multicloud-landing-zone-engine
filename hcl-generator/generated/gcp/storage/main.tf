resource "google_storage_bucket" "bucket_test_01" {
  name                        = var.bucket_test_01_name
  location                    = var.bucket_test_01_location
  storage_class               = var.bucket_test_01_storage_class
  uniform_bucket_level_access = var.bucket_test_01_uniform_bucket_level_access
}
