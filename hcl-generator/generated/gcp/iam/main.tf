resource "google_service_account" "sa_delete_b_01" {
  account_id   = var.sa_delete_b_01_account_id
  display_name = var.sa_delete_b_01_display_name
  description  = var.sa_delete_b_01_description
  project      = var.sa_delete_b_01_project_id
}

resource "google_project_iam_member" "sa_delete_b_01_role" {
  project = var.sa_delete_b_01_project_id
  role    = var.sa_delete_b_01_role
  member  = "serviceAccount:${google_service_account.sa_delete_b_01.email}"
}
