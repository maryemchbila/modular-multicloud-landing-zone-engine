module "compute" {
  source                                = "./modules/compute"
  oci_vm_backend_01_assign_public_ip    = var.oci_vm_backend_01_assign_public_ip
  oci_vm_backend_01_availability_domain = var.oci_vm_backend_01_availability_domain
  oci_vm_backend_01_compartment_id      = var.oci_vm_backend_01_compartment_id
  oci_vm_backend_01_display_name        = var.oci_vm_backend_01_display_name
  oci_vm_backend_01_image_id            = var.oci_vm_backend_01_image_id
  oci_vm_backend_01_shape               = var.oci_vm_backend_01_shape
  oci_vm_backend_01_subnet_id           = var.oci_vm_backend_01_subnet_id
}


module "network" {
  source                                           = "./modules/network"
  oci_igw_private_01_display_name                  = var.oci_igw_private_01_display_name
  oci_rt_private_01_display_name                   = var.oci_rt_private_01_display_name
  oci_subnet_private_01_availability_domain        = var.oci_subnet_private_01_availability_domain
  oci_subnet_private_01_cidr_block                 = var.oci_subnet_private_01_cidr_block
  oci_subnet_private_01_display_name               = var.oci_subnet_private_01_display_name
  oci_subnet_private_01_dns_label                  = var.oci_subnet_private_01_dns_label
  oci_subnet_private_01_prohibit_public_ip_on_vnic = var.oci_subnet_private_01_prohibit_public_ip_on_vnic
  oci_vcn_private_01_cidr_block                    = var.oci_vcn_private_01_cidr_block
  oci_vcn_private_01_compartment_id                = var.oci_vcn_private_01_compartment_id
  oci_vcn_private_01_display_name                  = var.oci_vcn_private_01_display_name
  oci_vcn_private_01_dns_label                     = var.oci_vcn_private_01_dns_label
}
