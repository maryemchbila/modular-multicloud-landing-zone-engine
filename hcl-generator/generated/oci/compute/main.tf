resource "oci_core_instance" "oci_vm_test_01" {
  availability_domain = var.oci_vm_test_01_availability_domain
  compartment_id      = var.oci_vm_test_01_compartment_id
  display_name        = var.oci_vm_test_01_display_name
  shape               = var.oci_vm_test_01_shape

  create_vnic_details {
    subnet_id        = var.oci_vm_test_01_subnet_id
    assign_public_ip = var.oci_vm_test_01_assign_public_ip
  }

  source_details {
    source_type = "image"
    source_id   = var.oci_vm_test_01_image_id
  }
}
