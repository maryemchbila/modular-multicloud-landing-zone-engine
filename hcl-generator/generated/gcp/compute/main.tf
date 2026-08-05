resource "google_compute_instance" "vm_compute_test_02" {
  name         = var.vm_compute_test_02_name
  machine_type = var.vm_compute_test_02_machine_type
  zone         = var.vm_compute_test_02_zone

  boot_disk {
    initialize_params {
      image = var.vm_compute_test_02_image
    }
  }

  network_interface {
    network = var.vm_compute_test_02_network
  }
}

resource "google_compute_instance" "vm_clean_test_01" {
  name         = var.vm_clean_test_01_name
  machine_type = var.vm_clean_test_01_machine_type
  zone         = var.vm_clean_test_01_zone

  boot_disk {
    initialize_params {
      image = var.vm_clean_test_01_image
    }
  }

  network_interface {
    network = var.vm_clean_test_01_network
  }
}

resource "google_compute_instance" "vm_modular_test_01" {
  name         = var.vm_modular_test_01_name
  machine_type = var.vm_modular_test_01_machine_type
  zone         = var.vm_modular_test_01_zone

  boot_disk {
    initialize_params {
      image = var.vm_modular_test_01_image
    }
  }

  network_interface {
    network = var.vm_modular_test_01_network
  }
}

resource "google_compute_instance" "vm_migration_test_01" {
  name         = var.vm_migration_test_01_name
  machine_type = var.vm_migration_test_01_machine_type
  zone         = var.vm_migration_test_01_zone

  boot_disk {
    initialize_params {
      image = var.vm_migration_test_01_image
    }
  }

  network_interface {
    network = var.vm_migration_test_01_network
  }
}

resource "google_compute_instance" "vm_inexistante_999" {
  name         = var.vm_inexistante_999_name
  machine_type = var.vm_inexistante_999_machine_type
  zone         = var.vm_inexistante_999_zone

  boot_disk {
    initialize_params {
      image = var.vm_inexistante_999_image
    }
  }

  network_interface {
    network = var.vm_inexistante_999_network
  }
}
