resource "google_service_account" "sa_logging_01" {
  account_id   = var.sa_logging_01_account_id
  display_name = var.sa_logging_01_display_name
  description  = var.sa_logging_01_description
  project      = var.sa_logging_01_project_id
}

resource "google_project_iam_member" "sa_logging_01_role" {
  project = var.sa_logging_01_project_id
  role    = var.sa_logging_01_role
  member  = "serviceAccount:${google_service_account.sa_logging_01.email}"
}

resource "google_service_account" "sa_monitoring_01" {
  account_id   = var.sa_monitoring_01_account_id
  display_name = var.sa_monitoring_01_display_name
  description  = var.sa_monitoring_01_description
  project      = var.sa_monitoring_01_project_id
}

resource "google_project_iam_member" "sa_monitoring_01_role" {
  project = var.sa_monitoring_01_project_id
  role    = var.sa_monitoring_01_role
  member  = "serviceAccount:${google_service_account.sa_monitoring_01.email}"
}

resource "google_service_account" "sa_storage_viewer_01" {
  account_id   = var.sa_storage_viewer_01_account_id
  display_name = var.sa_storage_viewer_01_display_name
  description  = var.sa_storage_viewer_01_description
  project      = var.sa_storage_viewer_01_project_id
}

resource "google_project_iam_member" "sa_storage_viewer_01_role" {
  project = var.sa_storage_viewer_01_project_id
  role    = var.sa_storage_viewer_01_role
  member  = "serviceAccount:${google_service_account.sa_storage_viewer_01.email}"
}

resource "google_service_account" "sa_compute_viewer_01" {
  account_id   = var.sa_compute_viewer_01_account_id
  display_name = var.sa_compute_viewer_01_display_name
  description  = var.sa_compute_viewer_01_description
  project      = var.sa_compute_viewer_01_project_id
}

resource "google_project_iam_member" "sa_compute_viewer_01_role" {
  project = var.sa_compute_viewer_01_project_id
  role    = var.sa_compute_viewer_01_role
  member  = "serviceAccount:${google_service_account.sa_compute_viewer_01.email}"
}
