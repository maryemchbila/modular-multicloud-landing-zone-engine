resource "google_compute_network" "vpc_test_01" {
  name                    = var.vpc_test_01_name
  auto_create_subnetworks = false
}


resource "google_compute_subnetwork" "subnet_test_01" {
  name          = var.subnet_test_01_name
  ip_cidr_range = var.subnet_test_01_cidr
  region        = var.subnet_test_01_region
  network       = google_compute_network.vpc_test_01.id
}


resource "google_compute_network" "vpc_test_02" {
  name                    = var.vpc_test_02_name
  auto_create_subnetworks = false
}


resource "google_compute_subnetwork" "subnet_test_02" {
  name          = var.subnet_test_02_name
  ip_cidr_range = var.subnet_test_02_cidr
  region        = var.subnet_test_02_region
  network       = google_compute_network.vpc_test_02.id
}


resource "google_compute_network" "vpc_clean_test_01" {
  name                    = var.vpc_clean_test_01_name
  auto_create_subnetworks = false
}


resource "google_compute_subnetwork" "subnet_clean_test_01" {
  name          = var.subnet_clean_test_01_name
  ip_cidr_range = var.subnet_clean_test_01_cidr
  region        = var.subnet_clean_test_01_region
  network       = google_compute_network.vpc_clean_test_01.id
}


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


resource "google_compute_network" "vpc_modular_test_01" {
  name                    = var.vpc_modular_test_01_name
  auto_create_subnetworks = false
}


resource "google_compute_subnetwork" "subnet_modular_test_01" {
  name          = var.subnet_modular_test_01_name
  ip_cidr_range = var.subnet_modular_test_01_cidr
  region        = var.subnet_modular_test_01_region
  network       = google_compute_network.vpc_modular_test_01.id
}

