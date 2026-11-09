import ssl
import socket
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.services.ssrf_guard import validate_target_host
from app.services.demo_data import is_synthetic_demo_host
from app.config import settings

def inspect_tls_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Connects to the target server via TLS, downloads and parses its X.509 certificate.
    Analyzes validity, expiration, SANs, issuer, signature algorithm, and key strength.
    """
    result = {
        "is_valid": False,
        "status_text": "Insufficient information",
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "subject": {},
        "issuer": {},
        "san_list": [],
        "signature_algorithm": "Unknown",
        "key_type": "Unknown",
        "key_size": None,
        "tls_version": "Unknown",
        "hostname_match": False,
        "connection_errors": [],
        "chain_info": [],
        "limitation_notes": (
            "A valid HTTPS certificate confirms aspects of encrypted connection and domain verification. "
            "It does not establish that a website, company, or business is trustworthy or free from fraud."
        )
    }

    # Handle synthetic demo domains
    if is_synthetic_demo_host(hostname):
        now = datetime.now(timezone.utc)
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=365)
        result.update({
            "is_valid": True,
            "status_text": "Valid for inspected hostname (Synthetic Benchmark)",
            "not_before": not_before,
            "not_after": not_after,
            "days_remaining": (not_after - now).days,
            "subject": {"commonName": hostname, "organization": "Internet Assigned Numbers Authority"},
            "issuer": {"commonName": "DigiCert Global Root G2", "organization": "DigiCert Inc"},
            "san_list": [hostname, f"*.{hostname}"],
            "signature_algorithm": "sha256WithRSAEncryption",
            "key_type": "RSA",
            "key_size": 2048,
            "tls_version": "TLSv1.3",
            "hostname_match": True,
            "connection_errors": []
        })
        return result

    # SSRF guard and port policy
    if port not in (80, 443):
        result["status_text"] = "Blocked by SSRF Policy"
        result["connection_errors"].append(
            f"Passive HTTPS inspection is limited to ports 80 and 443; port {port} is not allowed."
        )
        return result

    is_safe, error_msg, resolved_ips = validate_target_host(hostname)
    if not is_safe or not resolved_ips:
        result["status_text"] = "Blocked by SSRF Policy"
        result["connection_errors"].append(error_msg)
        return result

    # Standard SSL Context with default CA verification
    ctx = ssl.create_default_context()
    
    # First attempt: standard validation
    cert_der = None
    tls_version_str = "Unknown"
    ssl_error_detail = None
    
    try:
        with socket.create_connection((resolved_ips[0], port), timeout=settings.REQUEST_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                tls_version_str = ssock.version() or "TLSv1.2"
                result["is_valid"] = True
                result["hostname_match"] = True
                result["status_text"] = "Valid for inspected hostname"
    except ssl.SSLCertVerificationError as e:
        ssl_error_detail = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in ssl_error_detail:
            if "hostname" in ssl_error_detail.lower():
                result["status_text"] = "Hostname mismatch"
            elif "expired" in ssl_error_detail.lower():
                result["status_text"] = "Expired"
            else:
                result["status_text"] = "Untrusted issuer or chain validation failure"
        result["connection_errors"].append(f"TLS Verification Error: {ssl_error_detail}")
    except ssl.SSLError as e:
        ssl_error_detail = str(e)
        result["status_text"] = f"TLS Handshake Failure: {ssl_error_detail[:50]}"
        result["connection_errors"].append(f"SSL Error: {ssl_error_detail}")
    except socket.timeout:
        result["status_text"] = "Connection Timed Out"
        result["connection_errors"].append("Timeout during TLS handshake connection.")
        return result
    except Exception as e:
        result["status_text"] = "Connection Error"
        result["connection_errors"].append(f"Network error: {str(e)[:100]}")
        return result

    # If verification failed, attempt to fetch the unverified certificate to extract metadata for diagnosis
    if not cert_der:
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((resolved_ips[0], port), timeout=settings.REQUEST_TIMEOUT_SECONDS) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    tls_version_str = ssock.version() or "TLS"
        except Exception:
            pass

    result["tls_version"] = tls_version_str

    if not cert_der:
        return result

    # Parse X.509 using cryptography library
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Validity dates
        # Use not_valid_before_utc and not_valid_after_utc if available (cryptography >= 42)
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        result["not_before"] = not_before
        result["not_after"] = not_after
        
        now = datetime.now(timezone.utc)
        delta = not_after - now
        result["days_remaining"] = delta.days

        if now < not_before:
            result["status_text"] = "Not yet valid"
            result["is_valid"] = False
        elif now > not_after:
            result["status_text"] = "Expired"
            result["is_valid"] = False

        # Subject attributes
        subject_dict = {}
        for attr in cert.subject:
            oid_name = attr.oid._name
            subject_dict[oid_name] = attr.value
        result["subject"] = subject_dict

        # Issuer attributes
        issuer_dict = {}
        for attr in cert.issuer:
            oid_name = attr.oid._name
            issuer_dict[oid_name] = attr.value
        result["issuer"] = issuer_dict

        # Subject Alternative Names (SANs)
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            result["san_list"] = [str(name.value) for name in san_ext.value]
        except x509.ExtensionNotFound:
            result["san_list"] = []

        # Check hostname match against SANs and Subject CommonName with SAN precedence.
        lower_host = hostname.lower()
        matched = False
        san_candidates = list(result["san_list"])
        if san_candidates:
            candidates = san_candidates
        elif "commonName" in subject_dict:
            candidates = [subject_dict["commonName"]]
        else:
            candidates = []

        for cand in candidates:
            cand_lower = cand.lower()
            if cand_lower == lower_host:
                matched = True
                break
            # Wildcard matching *.domain.com matches exactly one hostname label.
            if cand_lower.startswith("*."):
                suffix = cand_lower[2:]
                if lower_host.endswith("." + suffix):
                    prefix = lower_host[:-(len(suffix) + 1)]
                    if prefix and "." not in prefix and prefix != "":
                        matched = True
                        break
                    
        result["hostname_match"] = matched
        if not matched and result["is_valid"]:
            result["is_valid"] = False
            result["status_text"] = "Hostname mismatch"

        # Signature algorithm
        result["signature_algorithm"] = cert.signature_algorithm_oid._name

        # Public key information
        pub_key = cert.public_key()
        pub_key_class = pub_key.__class__.__name__
        if "RSA" in pub_key_class:
            result["key_type"] = "RSA"
            result["key_size"] = pub_key.key_size
        elif "EllipticCurve" in pub_key_class:
            result["key_type"] = "ECC"
            result["key_size"] = pub_key.key_size
        elif "Ed25519" in pub_key_class:
            result["key_type"] = "Ed25519"
            result["key_size"] = 256
        else:
            result["key_type"] = pub_key_class
            result["key_size"] = getattr(pub_key, "key_size", None)

    except Exception as e:
        result["connection_errors"].append(f"Certificate parsing issue: {str(e)}")

    return result
