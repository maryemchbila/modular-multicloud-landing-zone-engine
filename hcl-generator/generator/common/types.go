package common

import "github.com/hashicorp/hcl/v2/hclwrite"

type TerraformFiles struct {
	Main      *hclwrite.File
	Variables *hclwrite.File
	Tfvars    *hclwrite.File
	Outputs   *hclwrite.File
}

type TransactionFile struct {
	path        string
	tempPath    string
	backupPath  string
	hadOriginal bool
}
