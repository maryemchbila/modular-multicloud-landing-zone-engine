**# Modular Multi-Cloud Landing Zone Automation Engine**



**Moteur d'automatisation Terraform multi-cloud pour GCP et OCI.**



**## Architecture**



**- `hcl-generator/` : moteur Go avec hclwrite**

**- `python-engine/` : interface CLI temporaire et orchestration Python**



**## Providers supportés**



**- GCP**

**- OCI**



**## Modules supportés**



**- Compute**

**- Network**

**- Storage**

**- IAM**

**## Chemins de generation**

**- Production : `hcl-generator/generated/<provider>/modules/<module>`**

**- Fixtures statiques : `hcl-generator/testdata/`**

**Le nom d'une ressource ne determine jamais si elle est une fixture de test.**



**## Actions supportées**



**- Create**

**- Update**

**- Delete**



**## Sécurité**



**Le projet n'exécute pas automatiquement :**



**- terraform apply**

**- terraform destroy**

