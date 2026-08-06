output "oci_vcn_test_01_id" {
  description = "OCID du VCN OCI"
  value       = oci_core_vcn.oci_vcn_test_01.id
}

output "oci_subnet_test_01_id" {
  description = "OCID du subnet OCI"
  value       = oci_core_subnet.oci_subnet_test_01.id
}

output "oci_igw_test_01_id" {
  description = "OCID de l'Internet Gateway OCI"
  value       = oci_core_internet_gateway.oci_igw_test_01.id
}

output "oci_rt_test_01_id" {
  description = "OCID de la route table OCI"
  value       = oci_core_route_table.oci_rt_test_01.id
}
