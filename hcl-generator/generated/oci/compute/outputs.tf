output "oci_vm_test_01_id" {
  description = "OCID de l'instance OCI"
  value       = oci_core_instance.oci_vm_test_01.id
}

output "oci_vm_test_01_display_name" {
  description = "Nom affiché de l'instance OCI"
  value       = oci_core_instance.oci_vm_test_01.display_name
}

output "oci_vm_test_01_private_ip" {
  description = "Adresse IP privée de l'instance OCI"
  value       = oci_core_instance.oci_vm_test_01.private_ip
}

output "oci_vm_test_01_public_ip" {
  description = "Adresse IP publique de l'instance OCI"
  value       = oci_core_instance.oci_vm_test_01.public_ip
}
