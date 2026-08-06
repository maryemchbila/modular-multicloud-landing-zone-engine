resource "oci_core_vcn" "oci_vcn_private_01" {
  compartment_id = var.oci_vcn_private_01_compartment_id
  cidr_block     = var.oci_vcn_private_01_cidr_block
  display_name   = var.oci_vcn_private_01_display_name
  dns_label      = var.oci_vcn_private_01_dns_label
}

resource "oci_core_internet_gateway" "oci_igw_private_01" {
  compartment_id = var.oci_vcn_private_01_compartment_id
  vcn_id         = oci_core_vcn.oci_vcn_private_01.id
  display_name   = var.oci_igw_private_01_display_name
  enabled        = true
}

resource "oci_core_route_table" "oci_rt_private_01" {
  compartment_id = var.oci_vcn_private_01_compartment_id
  vcn_id         = oci_core_vcn.oci_vcn_private_01.id
  display_name   = var.oci_rt_private_01_display_name

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.oci_igw_private_01.id
  }
}

resource "oci_core_subnet" "oci_subnet_private_01" {
  compartment_id             = var.oci_vcn_private_01_compartment_id
  vcn_id                     = oci_core_vcn.oci_vcn_private_01.id
  cidr_block                 = var.oci_subnet_private_01_cidr_block
  display_name               = var.oci_subnet_private_01_display_name
  dns_label                  = var.oci_subnet_private_01_dns_label
  availability_domain        = var.oci_subnet_private_01_availability_domain
  route_table_id             = oci_core_route_table.oci_rt_private_01.id
  prohibit_public_ip_on_vnic = var.oci_subnet_private_01_prohibit_public_ip_on_vnic
}
