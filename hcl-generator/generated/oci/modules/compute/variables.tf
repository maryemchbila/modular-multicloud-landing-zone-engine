variable "oci_vm_backend_01_display_name" {
  description = "Nom affiché de l'instance OCI"
  type        = string
}

variable "oci_vm_backend_01_availability_domain" {
  description = "Availability Domain OCI"
  type        = string
}

variable "oci_vm_backend_01_compartment_id" {
  description = "OCID du compartiment OCI"
  type        = string
}

variable "oci_vm_backend_01_shape" {
  description = "Shape de l'instance OCI"
  type        = string
}

variable "oci_vm_backend_01_subnet_id" {
  description = "OCID du subnet OCI"
  type        = string
}

variable "oci_vm_backend_01_image_id" {
  description = "OCID de l'image OCI"
  type        = string
}

variable "oci_vm_backend_01_assign_public_ip" {
  description = "Autorise une adresse IP publique sur le VNIC"
  type        = bool
}
