"""
Azure Function - Automatic ACME Certificate Renewal (multi-certificate, self-contained)
Runs on a daily timer, loops over all configured certificates, checks expiry in Key Vault,
and renews any that are within the threshold or missing.

Required environment variables (set as Application Settings on the Function App):
  KEY_VAULT_NAME          - e.g. cert-mgmt-kv-abc123
  CERTIFICATES_CONFIG     - JSON array: [{"name": "yourdomain-com", "domain_names": ["yourdomain.com","*.yourdomain.com"]}]
  DNS_ZONE_NAME           - e.g. yourdomain.com
  DNS_ZONE_RESOURCE_GROUP - e.g. rg-hub-dns
  SUBSCRIPTION_ID         - Azure subscription ID
  ACME_EMAIL              - e.g. admin@yourdomain.com
  ACME_SERVER_URL         - Let's Encrypt directory URL
  RENEWAL_THRESHOLD_DAYS  - default 30

Required managed identity roles:
  - DNS Zone Contributor            on the DNS zone
  - Key Vault Administrator         on the Key Vault
"""

import logging
import os
import time
import json
from datetime import datetime, timedelta

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord

import josepy as jose
import acme.challenges
import acme.client
import acme.messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import NoEncryption

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration — read at module load
# ============================================================================

try:
    KEY_VAULT_NAME         = os.environ["KEY_VAULT_NAME"]
    CERTIFICATES_CONFIG    = json.loads(os.environ["CERTIFICATES_CONFIG"])
    DNS_ZONE_NAME          = os.environ["DNS_ZONE_NAME"]
    DNS_ZONE_RG            = os.environ["DNS_ZONE_RESOURCE_GROUP"]
    SUBSCRIPTION_ID        = os.environ["SUBSCRIPTION_ID"]
    ACME_EMAIL             = os.environ["ACME_EMAIL"]
    ACME_SERVER_URL        = os.environ["ACME_SERVER_URL"]
    RENEWAL_THRESHOLD_DAYS = int(os.environ["RENEWAL_THRESHOLD_DAYS"])
    VAULT_URL              = f"https://{KEY_VAULT_NAME}.vault.azure.net/"
except KeyError as e:
    logger.error("Missing required environment variable: %s", e)
    raise


# ============================================================================
# Entry Point
# ============================================================================

app = func.FunctionApp()

@app.timer_trigger(schedule="0 0 2 * * *", arg_name="mytimer", run_on_startup=False)
def main(mytimer: func.TimerRequest) -> None:
    logger.info("Certificate renewal check started at %s", datetime.utcnow().isoformat())
    logger.info("Managing %d certificate(s)", len(CERTIFICATES_CONFIG))

    try:
        credential = DefaultAzureCredential()

        # Initialise clients once — reused across all certificates
        cert_client = CertificateClient(vault_url=VAULT_URL, credential=credential)
        dns_client  = DnsManagementClient(credential, SUBSCRIPTION_ID)

        # Initialise ACME client once — account key is reused for all renewals
        account_key = _generate_rsa_key(4096)
        acme_client = _get_acme_client(account_key)

        for cert_config in CERTIFICATES_CONFIG:
            cert_name    = cert_config["name"]
            domain_names = cert_config["domain_names"]
            logger.info("--- Checking certificate: %s (domains: %s)", cert_name, domain_names)

            try:
                expires_in = _get_days_until_expiry(cert_client, cert_name)
                logger.info("Certificate '%s' expires in %d day(s)", cert_name, expires_in)

                if expires_in <= 0:
                    logger.error("Certificate '%s' has EXPIRED!", cert_name)
                    send_alert(f"[CRITICAL] Certificate '{cert_name}' has expired!")
                    _do_renewal(acme_client, cert_client, dns_client, cert_name, domain_names)

                elif expires_in <= RENEWAL_THRESHOLD_DAYS:
                    logger.warning("Certificate '%s' renewal threshold reached — starting renewal", cert_name)
                    _do_renewal(acme_client, cert_client, dns_client, cert_name, domain_names)
                    logger.info("Certificate '%s' renewed successfully", cert_name)

                else:
                    logger.info("Certificate '%s' is valid — no action needed", cert_name)

            except Exception as exc:
                # Log and alert per certificate but continue with remaining ones
                logger.error("Failed to process certificate '%s': %s", cert_name, exc, exc_info=True)
                send_alert(f"Certificate renewal failed for '{cert_name}': {exc}")

    except Exception as exc:
        logger.error("Certificate renewal check failed: %s", exc, exc_info=True)
        send_alert(f"Certificate renewal check failed: {exc}")
        raise


# ============================================================================
# Expiry check
# ============================================================================

def _get_days_until_expiry(cert_client: CertificateClient, cert_name: str) -> int:
    try:
        cert       = cert_client.get_certificate(cert_name)
        expires_on = cert.properties.expires_on
        if expires_on.tzinfo is None:
            expires_on = expires_on.replace(tzinfo=None)
        return (expires_on - datetime.utcnow()).days
    except Exception:
        logger.warning("Certificate '%s' not found in Key Vault — will issue a new one", cert_name)
        return -1


# ============================================================================
# Full renewal flow
# ============================================================================

def _do_renewal(
    acme_client,
    cert_client: CertificateClient,
    dns_client: DnsManagementClient,
    cert_name: str,
    domain_names: list,
) -> None:
    """Issue/renew a single certificate via ACME DNS-01 and store it in Key Vault."""

    domains  = list(domain_names)
    cert_key = _generate_rsa_key(2048)
    csr_pem  = _generate_csr(cert_key, domains)

    order = acme_client.new_order(csr_pem)
    logger.info("ACME order created for: %s", domains)

    _complete_dns_challenges(acme_client, order, dns_client)

    order = acme_client.poll_and_finalize(order)
    logger.info("Certificate '%s' issued successfully", cert_name)

    p12_bytes = _bundle_pkcs12(cert_key, order.fullchain_pem)

    # Purge if soft-deleted so we can reimport cleanly
    try:
        cert_client.purge_deleted_certificate(cert_name)
        logger.info("Purged soft-deleted certificate '%s'", cert_name)
    except Exception:
        pass

    cert_client.import_certificate(
        certificate_name=cert_name,
        certificate_bytes=p12_bytes,
        password=b"",
    )
    logger.info("Certificate '%s' stored in Key Vault", cert_name)


# ============================================================================
# ACME helpers
# ============================================================================

def _generate_rsa_key(bits: int):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )


def _get_acme_client(account_key) -> acme.client.ClientV2:
    jwk       = jose.JWKRSA(key=jose.ComparableRSAKey(account_key))
    net       = acme.client.ClientNetwork(jwk, user_agent="azure-function-acme/1.0")
    directory = acme.messages.Directory.from_json(net.get(ACME_SERVER_URL).json())
    client    = acme.client.ClientV2(directory, net)

    client.new_account(
        acme.messages.NewRegistration.from_data(
            email=ACME_EMAIL,
            terms_of_service_agreed=True,
        )
    )
    return client


def _generate_csr(private_key, domains: list) -> bytes:
    """Return PEM-encoded CSR covering all domains (first = CN, all = SANs)."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ============================================================================
# DNS-01 challenge
# ============================================================================

def _complete_dns_challenges(
    acme_client: acme.client.ClientV2,
    order,
    dns_client: DnsManagementClient,
) -> None:
    """Write _acme-challenge TXT records, validate, then clean up."""
    created_records = []

    try:
        # --- Collect ALL challenges and group by record name ---
        challenges_to_answer = []
        records = {}  # record_name -> list of validation values

        for auth in order.authorizations:
            domain    = auth.body.identifier.value
            challenge = _get_dns_challenge(auth)
            response, validation = challenge.response_and_validation(acme_client.net.key)

            record_domain = domain.lstrip("*.")

            if record_domain == DNS_ZONE_NAME:
                record_name = "_acme-challenge"
            elif record_domain.endswith(f".{DNS_ZONE_NAME}"):
                relative    = record_domain[: -(len(DNS_ZONE_NAME) + 1)]
                record_name = f"_acme-challenge.{relative}"
            else:
                raise ValueError(
                    f"Domain '{record_domain}' is not within DNS zone '{DNS_ZONE_NAME}'. "
                    f"Add this domain's zone to DNS_ZONE_NAME or use a separate DNS zone."
                )

            if record_name not in records:
                records[record_name] = []
            records[record_name].append(validation)
            challenges_to_answer.append((challenge, response))

        # --- Write all TXT records at once (multiple values per record) ---
        for record_name, validations in records.items():
            logger.info("Creating TXT %s with %d value(s): %s", record_name, len(validations), validations)
            dns_client.record_sets.create_or_update(
                DNS_ZONE_RG, DNS_ZONE_NAME, record_name, "TXT",
                RecordSet(ttl=60, txt_records=[TxtRecord(value=[v]) for v in validations]),
            )
            created_records.append(record_name)

        # --- Wait for propagation, then notify CA ---
        logger.info("Waiting 30s for DNS propagation...")
        time.sleep(30)

        for challenge, response in challenges_to_answer:
            acme_client.answer_challenge(challenge, response)

        deadline = datetime.utcnow() + timedelta(seconds=300)
        acme_client.poll_authorizations(order, deadline)

    finally:
        for record_name in created_records:
            try:
                dns_client.record_sets.delete(
                    DNS_ZONE_RG, DNS_ZONE_NAME, record_name, "TXT"
                )
                logger.info("Deleted TXT record: %s", record_name)
            except Exception as exc:
                logger.warning("Failed to delete TXT record %s: %s", record_name, exc)


def _get_dns_challenge(auth):
    for challenge in auth.body.challenges:
        if isinstance(challenge.chall, acme.challenges.DNS01):
            return challenge
    raise ValueError(f"No DNS-01 challenge found for {auth.body.identifier.value}")


# ============================================================================
# PKCS#12 bundling
# ============================================================================

def _bundle_pkcs12(private_key, cert_chain_pem: str) -> bytes:
    pem_parts = cert_chain_pem.encode().split(b"-----END CERTIFICATE-----")
    pem_certs = [
        part + b"-----END CERTIFICATE-----"
        for part in pem_parts
        if b"-----BEGIN CERTIFICATE-----" in part
    ]

    leaf_cert = x509.load_pem_x509_certificate(pem_certs[0])
    ca_certs  = [x509.load_pem_x509_certificate(c) for c in pem_certs[1:]]

    return serialize_key_and_certificates(
        name=b"",
        key=private_key,
        cert=leaf_cert,
        cas=ca_certs,
        encryption_algorithm=NoEncryption(),
    )


# ============================================================================
# Alerting
# ============================================================================

def send_alert(message: str) -> None:
    logger.warning("ALERT: %s", message)

    # ── Option A: Slack webhook ──────────────────────────────────────────────
    # import requests
    # webhook = os.environ.get("SLACK_WEBHOOK_URL")
    # if webhook:
    #     requests.post(webhook, json={"text": message}, timeout=10)

    # ── Option B: SendGrid email ─────────────────────────────────────────────
    # from sendgrid import SendGridAPIClient
    # from sendgrid.helpers.mail import Mail
    # sg   = SendGridAPIClient(os.environ["SENDGRID_API_KEY"])
    # mail = Mail(
    #     from_email=os.environ["ALERT_FROM"],
    #     to_emails=os.environ["ALERT_TO"],
    #     subject="[Certificate Alert]",
    #     plain_text_content=message,
    # )
    # sg.send(mail)