# ACME Certificate Renewal — Azure Function

This project provides a fully automated, zero-touch certificate lifecycle management solution for Azure, built around the ACME protocol and Let's Encrypt. Rather than manually renewing TLS certificates or relying on expensive commercial solutions, this solution provisions a lightweight Python Azure Function that runs daily, checks certificate expiry across all configured domains, and automatically renews any certificate approaching its expiration threshold. Certificates are stored in a central Azure Key Vault and can be referenced by any consuming application (e.g. Application Gateway).

---

## How It Works

1. A timer-triggered Azure Function runs daily at 02:00 UTC
2. For each configured certificate, it checks the expiry date in Key Vault
3. If the certificate is within the renewal threshold (default: 30 days) or missing, it triggers renewal:
   - Generates a new RSA private key and CSR
   - Requests a new certificate order from Let's Encrypt via the ACME protocol
   - Completes the DNS-01 challenge by writing `_acme-challenge` TXT records to Azure DNS
   - Waits for DNS propagation, then notifies Let's Encrypt to validate
   - Bundles the issued certificate into PKCS#12 format
   - Stores it in Azure Key Vault
4. Consuming applications (App Gateway, etc.) reference the certificate from Key Vault via their own Terraform configs

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           rg-cert-management                │
│                                             │
│  ┌─────────────────┐   ┌─────────────────┐  │
│  │  Function App   │   │   Key Vault     │  │
│  │  (Flex FC1)     │──▶│  (central certs)│  │
│  └────────┬────────┘   └─────────────────┘  │
│           │                                 │
│  ┌────────▼────────┐                        │
│  │ Storage Account │                        │
│  │ (deployment)    │                        │
│  └─────────────────┘                        │
└─────────────────────────────────────────────┘
           │
           ▼ DNS-01 challenge
┌─────────────────────┐
│  Azure DNS Zone     │  (existing, separate RG)
│  yourdomain.com     │
└─────────────────────┘
           │
           ▼ validates
┌─────────────────────┐
│  Let's Encrypt      │
│  (ACME CA)          │
└─────────────────────┘
```

---

## File Structure

```
.
├── README.md                   ← this file
├── function_app.tf             ← all Azure infrastructure (Terraform)
├── terraform.tfvars            ← your configuration values
├── deploy_function.ps1         ← PowerShell script to deploy function code
└── function_code/              ← function source code (zipped and deployed by deploy_function.ps1)
    ├── host.json               ← Azure Functions runtime config
    ├── requirements.txt        ← Python dependencies
    └── function_app.py         ← main function code (v2 programming model)
```

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.3 | Infrastructure deployment |
| [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) | Function code deployment |
| [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) >= 5.1 | Running the deploy script |
| Python (any version) | Required locally by `az functionapp deployment` in `deploy_function.ps1` |

You must be logged in to Azure CLI before deploying:
```powershell
az login
az account set --subscription "YOUR_SUBSCRIPTION_ID"
```

---

## Infrastructure (Terraform)

All infrastructure is defined in `function_app.tf`. Running `terraform apply` creates:

| Resource | Name | Purpose |
|----------|------|---------|
| Resource Group | `rg-cert-management` | Container for all cert management resources |
| Key Vault | `{base_name}-kv-{suffix}` | Central store for all managed certificates |
| Storage Account | `{base_name}acmefuncst{suffix}` | Deployment package storage for the Function App |
| Storage Container | `{base_name}-acme-func-deployment` | Blob container for function zip packages |
| App Service Plan | `{base_name}-acme-renewal-asp` | Flex Consumption (FC1) plan |
| Function App | `{base_name}-acme-renewal-func` | The renewal function |
| Role Assignment | Key Vault Administrator | Allows function to read/write certificates in Key Vault and purge soft-deleted certificates |
| Role Assignment | DNS Zone Contributor | Allows function to write TXT records for DNS-01 |

> **Note:** A random 6-character suffix is appended to the Key Vault and Storage Account names to ensure global uniqueness.

### Terraform Outputs

After `terraform apply`, the following outputs are available:

| Output | Description |
|--------|-------------|
| `key_vault_id` | Resource ID of the Key Vault — use in consuming app configs |
| `key_vault_name` | Name of the Key Vault |
| `resource_group_name` | Resource group name |
| `function_app_name` | Name of the Function App |
| `managed_identity_principal_id` | Object ID of the Function App's managed identity |

---

## Configuration

Edit `terraform.tfvars` and fill in your values.

### Certificate Names

Key Vault certificate names must be alphanumeric with dashes only — **no dots**. Use dashes instead:

| Domain | Certificate Name |
|--------|-----------------|
| `yourdomain.com` | `yourdomain-com` |
| `subdomain.yourdomain.com` | `subdomain-yourdomain-com` |

### Domain Names

Each certificate entry's `domain_names` list should explicitly include both the apex and wildcard if needed. Let's Encrypt **does not support** wildcards more than one level deep — `*.subdomain.yourdomain.com` requires a separate certificate from `*.yourdomain.com`.

### DNS Requirements

For each domain in `domain_names`, the domain must:
1. Exist as an A or CNAME record in your Azure DNS zone
2. Be within the configured `dns_zone_name` — domains outside this zone will cause a validation error

---

## Deployment

### Step 1 — Deploy infrastructure

```powershell
terraform init
terraform plan -out="tfplan"
terraform apply "tfplan"
```

### Step 2 — Deploy function code

The Terraform provider for Azure (version 4.61.0 while creating this config) doesn't support deploying code to Flex Consumption plans yet. The PowerShell script is a workaround until they do.

```powershell
.\deploy_function.ps1
```

This script automatically reads the Function App name and resource group from Terraform outputs, zips `function_code/`, and deploys via the Azure CLI.

### Redeploying after code changes

Only `deploy_function.ps1` needs to be run — no `terraform apply` required unless infrastructure variables changed.

### Redeploying after infrastructure changes

Run both steps in order.

---

## Consuming Certificates in Other Terraform Configs

Reference the central Key Vault from other Terraform configurations using remote state or data sources:

```hcl
# Reference the Key Vault created by this module
data "azurerm_key_vault" "cert_mgmt" {
  name                = "YOUR_KEY_VAULT_NAME"   # from terraform output key_vault_name
  resource_group_name = "rg-cert-management"
}

# Grant your app's managed identity access to read the certificate
resource "azurerm_role_assignment" "cert_reader" {
  scope                = data.azurerm_key_vault.cert_mgmt.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_web_app.myapp.identity[0].principal_id
}

# Reference the certificate (e.g. in an Application Gateway)
data "azurerm_key_vault_certificate" "my_cert" {
  name         = "yourdomain-com"
  key_vault_id = data.azurerm_key_vault.cert_mgmt.id
}
```

---

## Monitoring

### View function execution logs

**Portal:** Function App → Functions → `main` → Test/Run

Click on `Run` to see the full log output including any errors.

### Enable Application Insights (optional)

Set `enable_application_insights = true` in `terraform.tfvars` and run `terraform apply`. This enables full telemetry, query-able logs, and smart anomaly detection. Note that Azure will automatically create an additional managed resource group for smart detection alerts.

---

## Security

- **No credentials stored anywhere** — the Function App authenticates to Key Vault and Azure DNS using its system-assigned managed identity
- **Least privilege RBAC** — the identity only has the minimum roles required
- **Key Vault RBAC** — access is controlled via Azure role assignments, not legacy access policies
- **No inbound exposure** — the Function App has a timer trigger only, no public HTTP endpoint
- **Certificates stay in Key Vault** — private keys never leave Key Vault

---

## Troubleshooting

### Function not appearing in portal
- Ensure `function_app.py` is at the root of the zip (not in a subfolder)
- Check that `host.json` is present at the root with the `extensionBundle` section
- Restart the Function App and check Log stream for import errors

### DNS-01 challenge failing with "Incorrect TXT record"
- A stale `_acme-challenge` TXT record from a previous failed run may still exist — delete it manually in the DNS zone and retry
- Increase the propagation wait time in `function_app.py` if failures persist

### DNS-01 challenge failing with "NXDOMAIN"
- The domain has no A or CNAME record in the DNS zone — add one before retrying

### Certificate name invalid
- Key Vault names allow only alphanumeric characters and dashes — replace dots with dashes in the `name` field

### Soft-deleted certificate conflict
- The function automatically purges soft-deleted certificates before reimporting
- If it still fails, purge manually: **Key Vault → Certificates → Manage deleted certificates → Purge**