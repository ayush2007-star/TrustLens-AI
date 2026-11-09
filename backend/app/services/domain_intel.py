import socket
from typing import Dict, Any
from app.services.bounded_dns import DNS_RESOLUTION_TIMEOUT_SECONDS, bounded_dns_call
from app.services.demo_data import is_synthetic_demo_host

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def inspect_dns_records(hostname: str) -> Dict[str, Any]:
    """
    Queries real DNS records for the given hostname.
    Returns A, AAAA, MX, NS, TXT records and heuristic DNS flags.
    """
    records = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "nameservers": [],
        "txt_records": [],
        "suspicious_dns_flags": [],
        "error": None
    }

    # Handle synthetic test domains
    if is_synthetic_demo_host(hostname):
        records["a_records"] = ["93.184.215.14"]
        records["nameservers"] = ["a.iana-servers.net", "b.iana-servers.net"]
        records["suspicious_dns_flags"] = ["SYNTHETIC_DEMO: Reserved IANA test domain"]
        return records

    if not DNS_AVAILABLE:
        # Fallback to standard socket resolution if dnspython is unavailable
        try:
            ips = bounded_dns_call(
                socket.gethostbyname_ex,
                hostname,
                timeout=DNS_RESOLUTION_TIMEOUT_SECONDS,
            )[2]
            records["a_records"] = ips
        except TimeoutError:
            records["error"] = "DNS resolution timed out."
        except Exception as e:
            records["error"] = f"DNS resolution failed: {str(e)}"
        return records

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # Query A
    try:
        answers = resolver.resolve(hostname, "A")
        records["a_records"] = [str(rdata) for rdata in answers]
    except Exception:
        pass

    # Query AAAA
    try:
        answers = resolver.resolve(hostname, "AAAA")
        records["aaaa_records"] = [str(rdata) for rdata in answers]
    except Exception:
        pass

    # Query MX
    try:
        answers = resolver.resolve(hostname, "MX")
        records["mx_records"] = [f"{rdata.preference} {str(rdata.exchange).rstrip('.')}" for rdata in answers]
    except Exception:
        pass

    # Query NS (use a heuristic root zone when a public-suffix library is unavailable)
    try:
        parts = hostname.split('.')
        if len(parts) >= 3 and parts[-2].lower() in {"co", "com", "org", "net", "edu", "gov"} and len(parts[-1]) == 2:
            base_zone = ".".join(parts[-3:])
        else:
            base_zone = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        records["base_zone"] = base_zone
        records["base_zone_heuristic"] = True
        answers = resolver.resolve(base_zone, "NS")
        records["nameservers"] = [str(rdata).rstrip('.') for rdata in answers]
    except Exception:
        pass

    # Heuristic DNS Flags
    if len(records["a_records"]) == 0 and len(records["aaaa_records"]) == 0:
        records["suspicious_dns_flags"].append("NXDOMAIN_OR_NO_A_RECORDS: Hostname has no resolvable IP records.")
    
    if len(records["a_records"]) > 6:
        records["suspicious_dns_flags"].append("HIGH_IP_ROTATION: Multiple A-records detected (possible CDN or fast-flux hosting).")

    return records


def inspect_whois_data(domain: str) -> Dict[str, Any]:
    """
    Returns WHOIS registration intelligence only for synthetic demo domains.
    Real lookups are unavailable because their client cannot guarantee a timeout.
    """
    result = {
        "domain": domain,
        "registrar": "Not available",
        "creation_date": "Not available",
        "expiration_date": "Not available",
        "age_days": None,
        "status": "Not available",
        "raw_whois_available": False
    }

    # Synthetic demo handling
    if is_synthetic_demo_host(domain):
        result["registrar"] = "RESERVED - Internet Assigned Numbers Authority"
        result["creation_date"] = "1992-01-01"
        result["expiration_date"] = "Permanent / IANA Reserved"
        result["age_days"] = 12000
        result["status"] = "ACTIVE (SYNTHETIC BENCHMARK)"
        result["raw_whois_available"] = True
        return result

    result["status"] = (
        "WHOIS lookup unavailable: the client cannot guarantee a bounded lookup."
    )

    return result
