resource "google_compute_network" "vpc_backend_01" {
  name                    = var.vpc_backend_01_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet_backend_01" {
  name          = var.subnet_backend_01_name
  ip_cidr_range = var.subnet_backend_01_cidr
  region        = var.subnet_backend_01_region
  network       = google_compute_network.vpc_backend_01.id
}
