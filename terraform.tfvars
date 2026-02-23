# Azure subscription where all resources will be deployed
subscription_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Resource group where the Function App and Storage Account will be created
rg_cert_resource_group = "rg-cert-management"

# Azure region for the Function App and Storage Account
location = "france central"

# Already existing Azure DNS zone that will be used for the ACME DNS-01 challenge
dns_zone_name = "yourdomain.com"

# Resource group containing the DNS zone "dns_zone_name"
dns_zone_resource_group = "rg-hub-dns"

# name:           Name of the certificate in the key store. Key Vault only allows alphanumeric characters and dashes in certificate names.
# domain_names:   Domain the certificate will be issued for. Wildcards can be used.
certificates = [
    {
        name         = "yourdomain-com"
        domain_names = ["yourdomain.com","*.yourdomain.com"]
    }
] 

# Email address for the ACME account — Let's Encrypt sends expiry warnings here
acme_email = "admin@yourdomain.com"

# How many days before expiry the function triggers a renewal
renewal_threshold_days = 30

# ACME directory URL — controls which CA and environment is used
# Staging (untrusted, for testing — no rate limits):   "https://acme-staging-v02.api.letsencrypt.org/directory"
# Production (real trusted certificates):              "https://acme-v02.api.letsencrypt.org/directory"
acme_server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"

# Enable Application Insights for logging and diagnostics (recommended for troubleshooting)
enable_application_insights = true