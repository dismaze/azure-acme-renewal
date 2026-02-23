terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0" # Flex Consumption requires azurerm 4.x+
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# ============================================================================
# VARIABLES
# ============================================================================

variable "subscription_id" {
  description = "Azure subscription where all resources will be deployed"
  type        = string
}

variable "location" {
  description = "Azure region for all resources in this module"
  type        = string
  default     = "france central"
}

variable "rg_cert_resource_group" {
  description = "Resource group created for the Certificates Management"
  type        = string
  default     = "rg-cert-management"
}

variable "base_name" {
  description = "Base name used for the ressources"
  type        = string
  default     = "cert-mgmt"
}

variable "dns_zone_name" {
  description = "Azure DNS zone used for the ACME DNS-01 challenge"
  type        = string
  default     = "yourdomain.com"
}

variable "dns_zone_resource_group" {
  description = "Resource group containing the DNS zone"
  type        = string
  default     = "rg-hub-dns"
}

variable "certificates" {
  description = "List of certificates to manage. Each entry has a name (used in Key Vault) and a list of domain_names."
  type = list(object({
    name         = string
    domain_names = list(string)
  }))
  default = [
    {
      name         = "yourdomain-com"
      domain_names = ["yourdomain.com", "*.yourdomain.com"]
    },
        {
      name         = "subdomain-yourdomain-com"
      domain_names = ["subdomain.yourdomain.com", "*.subdomain.yourdomain.com"]
    }
  ]
}

variable "acme_email" {
  description = "Email address for ACME account registration — Let's Encrypt sends expiry warnings here"
  type        = string
}

variable "acme_server_url" {
  description = "ACME directory URL — controls which CA and environment is used"
  type        = string
  default     = "https://acme-v02.api.letsencrypt.org/directory"
  # Staging (untrusted, for testing): "https://acme-staging-v02.api.letsencrypt.org/directory"
}

variable "renewal_threshold_days" {
  description = "How many days before expiry the function triggers a renewal"
  type        = number
  default     = 30
}

variable "enable_application_insights" {
  description = "Enable Application Insights for logging and diagnostics (recommended for troubleshooting)"
  type        = bool
  default     = false
}

# ============================================================================
# RESOURCE GROUP — dedicated to certificate management
# ============================================================================

resource "azurerm_resource_group" "cert_mgmt" {
  name     = var.rg_cert_resource_group
  location = var.location
}

# ============================================================================
# KEY VAULT — central store for all managed certificates
# Consuming apps (e.g. App Gateway) reference certs here via their own
# Terraform configs using a data source and a Key Vault Secrets User role.
# ============================================================================

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_key_vault" "cert_mgmt" {
  name                       = "${var.base_name}-kv-${random_string.suffix.result}" # must be globally unique
  resource_group_name        = azurerm_resource_group.cert_mgmt.name
  location                   = var.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
}

# ============================================================================
# DATA SOURCES — reference existing DNS zone
# ============================================================================

data "azurerm_dns_zone" "main" {
  name                = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group
}

# ============================================================================
# STORAGE — Flex Consumption requires a dedicated blob container for deployment
# ============================================================================

resource "azurerm_storage_account" "func" {
  name                     = "${replace(var.base_name, "/[^a-z0-9]/", "")}acmefuncst${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.cert_mgmt.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Flex Consumption deploys function code from a blob container
resource "azurerm_storage_container" "deployment" {
  name                 = "${var.base_name}-acme-func-deployment"
  storage_account_id  = azurerm_storage_account.func.id
  container_access_type = "private"
}

# ============================================================================
# APPLICATION INSIGHTS (optional)
# ============================================================================

resource "azurerm_application_insights" "main" {
  count               = var.enable_application_insights ? 1 : 0
  name                = "${var.base_name}-acme-renewal-appi"
  resource_group_name = azurerm_resource_group.cert_mgmt.name
  location            = var.location
  application_type    = "other"
}

# ============================================================================
# FUNCTION APP — Flex Consumption plan (FC1)
# ============================================================================

resource "azurerm_service_plan" "func" {
  name                = "${var.base_name}-acme-renewal-asp"
  resource_group_name = azurerm_resource_group.cert_mgmt.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "FC1" # Flex Consumption
}

resource "azurerm_function_app_flex_consumption" "acme_renewal" {
  name                = "${var.base_name}-acme-renewal-func"
  resource_group_name = azurerm_resource_group.cert_mgmt.name
  location            = var.location
  service_plan_id     = azurerm_service_plan.func.id

  # Flex Consumption deploys code from a private blob container
  storage_container_type      = "blobContainer"
  storage_container_endpoint = "${azurerm_storage_account.func.primary_blob_endpoint}${azurerm_storage_container.deployment.name}"
  storage_authentication_type = "StorageAccountConnectionString"
  storage_access_key          = azurerm_storage_account.func.primary_access_key

  # Deploy function code directly from zip
  #zip_deploy_file = data.archive_file.function_zip.output_path

  # Runtime
  runtime_name    = "python"
  runtime_version = "3.12"

  site_config {
    cors {
      allowed_origins = ["https://portal.azure.com"]
    }
  }

  # Scale settings — minimal for a daily cert check
  instance_memory_in_mb  = 512
  maximum_instance_count = 1

  # System-assigned managed identity
  identity {
    type = "SystemAssigned"
  }

  # App settings — all configuration passed as environment variables
  # Certificates config is passed as a JSON string and parsed by the function
  app_settings = merge(
    {
      KEY_VAULT_NAME                     = azurerm_key_vault.cert_mgmt.name
      CERTIFICATES_CONFIG                = jsonencode(var.certificates)
      DNS_ZONE_NAME                      = var.dns_zone_name
      DNS_ZONE_RESOURCE_GROUP            = var.dns_zone_resource_group
      SUBSCRIPTION_ID                    = var.subscription_id
      ACME_EMAIL                         = var.acme_email
      ACME_SERVER_URL                    = var.acme_server_url
      RENEWAL_THRESHOLD_DAYS             = tostring(var.renewal_threshold_days)
      PYTHON_ISOLATE_WORKER_DEPENDENCIES = "1"
    },
    var.enable_application_insights ? {
      APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main[0].connection_string
    } : {}
  )
}


# ============================================================================
# ROLE ASSIGNMENTS — grant the Function's managed identity what it needs
# ============================================================================

# Key Vault permission to handle certificates and purge
resource "azurerm_role_assignment" "kv_cert_administrator" {
  scope                = azurerm_key_vault.cert_mgmt.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = azurerm_function_app_flex_consumption.acme_renewal.identity[0].principal_id
}

# Write TXT records during the ACME DNS-01 challenge
resource "azurerm_role_assignment" "dns_contributor" {
  scope                = data.azurerm_dns_zone.main.id
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_function_app_flex_consumption.acme_renewal.identity[0].principal_id
}

# ============================================================================
# OUTPUTS
# Consuming apps (App Gateway etc.) reference the Key Vault via these outputs,
# either through remote state or by passing them as inputs to other configs.
# They will also need a "Key Vault Secrets User" role on the Key Vault.
# ============================================================================

output "resource_group_name" {
  value       = azurerm_resource_group.cert_mgmt.name
  description = "Resource group containing the Function App"
}

output "key_vault_id" {
  value       = azurerm_key_vault.cert_mgmt.id
  description = "Resource ID of the central certificate Key Vault — reference this in consuming app configs"
}

output "key_vault_name" {
  value       = azurerm_key_vault.cert_mgmt.name
  description = "Name of the central certificate Key Vault"
}

output "function_app_name" {
  value       = azurerm_function_app_flex_consumption.acme_renewal.name
  description = "Name of the deployed Function App"
}

output "managed_identity_principal_id" {
  value       = azurerm_function_app_flex_consumption.acme_renewal.identity[0].principal_id
  description = "Object ID of the Function App's managed identity"
}

output "application_insights_name" {
  value       = var.enable_application_insights ? azurerm_application_insights.main[0].name : "Application Insights not enabled"
  description = "Application Insights resource name (if enabled)"
}
