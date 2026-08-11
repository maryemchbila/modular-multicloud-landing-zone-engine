resource "google_compute_instance" "vm_test_26" {
  name         = var.vm_test_26_name
  machine_type = var.vm_test_26_machine_type
  zone         = var.vm_test_26_zone

  boot_disk {
    initialize_params {
      image = var.vm_test_26_image
    }
  }

  network_interface {
    network = var.vm_test_26_network
  }
}
