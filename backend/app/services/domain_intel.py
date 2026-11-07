import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


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
    if hostname.endswith("example.com") or hostname.endswith("example.org") or hostname.endswith("example.net"):
        records["a_records"] = ["93.184.215.14"]
        records["nameservers"] = ["a.iana-servers.net", "b.iana-servers.net"]
        records["suspicious_dns_flags"] = ["SYNTHETIC_DEMO: Reserved IANA test domain"]
        return records

    if not DNS_AVAILABLE:
        # Fallback to standard socket resolution if dnspython is unavailable
        try:
            ips = socket.gethostbyname_ex(hostname)[2]
            records["a_records"] = ips
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

    # Query NS (use domain root if hostname is deep)
    try:
        parts = hostname.split('.')
        base_zone = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
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
    Retrieves WHOIS registration intelligence for the domain.
    Gracefully handles network errors, timeouts, or unparseable TLDs.
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
    if domain.endswith("example.com") or domain.endswith("example.org") or domain.endswith("example.net"):
        result["registrar"] = "RESERVED - Internet Assigned Numbers Authority"
        result["creation_date"] = "1992-01-01"
        result["expiration_date"] = "Permanent / IANA Reserved"
        result["age_days"] = 12000
        result["status"] = "ACTIVE (SYNTHETIC BENCHMARK)"
        result["raw_whois_available"] = True
        return result

    if not WHOIS_AVAILABLE:
        result["status"] = "WHOIS lookup engine not installed on host"
        return result

    try:
        w = whois.whois(domain)
        if not w:
            return result

        result["raw_whois_available"] = True
        
        # Registrar
        if w.registrar:
            result["registrar"] = str(w.registrar)
            
        # Creation Date
        c_date = w.creation_date
        if isinstance(c_date, list) and len(c_date) > 0:
            c_date = c_date[0]
        if isinstance(c_date, datetime):
            result["creation_date"] = c_date.strftime("%Y-%m-%d")
            # Calculate age
            now = datetime.now(timezone.utc)
            if c_date.tzinfo is None:
                c_date = c_date.replace(tzinfo=timezone.utc)
            delta = now - c_date
            result["age_days"] = max(0, delta.days)
        elif c_date:
            result["creation_date"] = str(c_date)[:10]

        # Expiration Date
        e_date = w.expiration_date
        if isinstance(e_date, list) and len(e_date) > 0:
            e_date = e_date[0]
        if isinstance(e_date, datetime):
            result["expiration_date"] = e_date.strftime("%Y-%m-%d")
        elif e_date:
            result["expiration_date"] = str(e_date)[:10]

    except Exception:
        # WHOIS server down, blocked by rate limit, or unsupported TLD
        result["registrar"] = "Not available"
        result["creation_date"] = "Not available"
        result["expiration_date"] = "Not available"
        result["status"] = "Lookup failed or queried registrar blocked request"

    return result
