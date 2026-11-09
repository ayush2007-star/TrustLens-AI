import re
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Tuple

# Popular high-value brands frequently targeted by phishing
TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "citibank", "capitalone",
    "binance", "coinbase", "metamask", "blockchain", "kraken",
    "facebook", "instagram", "whatsapp", "telegram", "twitter",
    "dhl", "fedex", "usps", "ups", "irs", "gov", "microsoftonline",
    "office365", "outlook", "icloud", "dropbox", "docuSign"
]

# Suspicious keywords in path/subdomain
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "confirm", "wallet",
    "support", "password", "recovery", "suspend", "unlock", "alert",
    "invoice", "billing", "payment", "portal", "kyc", "session"
]

# Common top-level domains associated with disposable/free abuse
HIGH_RISK_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work",
    ".fit", ".cfd", ".sbs", ".icu", ".cam", ".monster", ".click"
]

def normalize_url(raw_url: str) -> Dict[str, Any]:
    """
    Normalizes a user-supplied URL or domain string.
    Returns parsed parts and normalized representation.
    """
    cleaned = raw_url.strip()
    
    # Handle leading protocols or lacks thereof
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
        cleaned = "https://" + cleaned

    parsed = urllib.parse.urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URI scheme: '{scheme}'. Only HTTP and HTTPS are permitted.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "URL contains embedded userinfo/credentials and is not allowed for passive inspection. "
            "Remove the username or password before submitting the target."
        )

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise ValueError("Could not extract a valid hostname from the submitted target.")

    # Remove default port
    port = parsed.port
    host_for_url = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_for_url
    if port:
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            netloc = f"{host_for_url}:{port}"

    # Normalize path
    path = parsed.path or "/"
    # Clean redundant slashes
    path = re.sub(r'/{2,}', '/', path)

    normalized = urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))

    # Extract base domain & subdomains (simple robust heuristic without external network dependency)
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    parts = hostname.split('.')
    if is_ip_address:
        base_domain = hostname
        subdomains = []
    elif len(parts) >= 2:
        # Check two-part TLDs like co.uk, com.au
        if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "net", "edu", "gov"] and len(parts[-1]) == 2:
            base_domain = ".".join(parts[-3:])
            subdomains = parts[:-3]
        else:
            base_domain = ".".join(parts[-2:])
            subdomains = parts[:-2]
    else:
        base_domain = hostname
        subdomains = []

    return {
        "raw_url": raw_url,
        "normalized_url": normalized,
        "scheme": scheme,
        "hostname": hostname,
        "base_domain": base_domain,
        "subdomains": subdomains,
        "port": port,
        "path": path,
        "query": parsed.query,
        "has_credentials": bool(parsed.username or parsed.password),
        "username": parsed.username
    }


def analyze_url_heuristics(parsed_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates static URL indicators, heuristics, and potential deceptive patterns.
    Returns a list of structured findings.
    """
    findings = []
    hostname = parsed_info["hostname"]
    base_domain = parsed_info["base_domain"]
    subdomains = parsed_info["subdomains"]
    raw_url = parsed_info["raw_url"]
    path = parsed_info["path"]
    query = parsed_info["query"]

    # 1. IP Address based URL
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        findings.append({
            "category": "HEURISTIC",
            "finding_title": "IP Address Used in Place of Hostname",
            "severity": "HIGH",
            "evidence": f"Hostname '{hostname}' is a raw IP address without registered domain identity.",
            "impact": "Attackers frequently host credential harvesters and phishing landing pages on raw IPs to evade domain reputation filters.",
            "remediation": "Do not enter passwords or financial information on websites addressed directly via IP."
        })
    except ValueError:
        pass

    # 2. Punycode and IDN Confusables
    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append({
            "category": "TYPOSQUAT",
            "finding_title": "Internationalized Punycode Domain (IDN)",
            "severity": "HIGH",
            "evidence": f"Hostname '{hostname}' uses Punycode encoding.",
            "impact": "Punycode is frequently leveraged in homograph attacks, where Cyrillic or Greek lookalike characters visually mimic legitimate brand domains.",
            "remediation": "Verify the decoded unicode representation to ensure no homoglyph deception is present."
        })

    # 3. Embedded user credentials (@ symbol)
    if parsed_info["has_credentials"]:
        findings.append({
            "category": "DECEPTIVE_PATTERN",
            "finding_title": "Embedded Userinfo / Deceptive @ Symbol",
            "severity": "CRITICAL",
            "evidence": f"URL contains user credentials or '@' symbol in authority string: {raw_url[:60]}...",
            "impact": "Browsers ignore strings before '@' in the authority, allowing attackers to disguise destination targets (e.g., http://google.com@evil-site.com).",
            "remediation": "Reject navigation to URLs containing unexpected '@' symbols in the host segment."
        })

    # 4. Brand Impersonation / Typosquatting in Domain or Subdomain
    matched_brands = []
    for brand in TARGETED_BRANDS:
        # Check if brand appears in subdomains or base domain
        if brand in hostname:
            matched_brands.append(brand)

    for brand in matched_brands:
        # If the brand is present, but the base_domain is NOT the brand's official domain
        # e.g. "paypal-security-update.com" or "login.paypal.attacker.com"
        official_domains = [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co.uk"]
        if base_domain not in official_domains:
            findings.append({
                "category": "TYPOSQUAT",
                "finding_title": f"Potential Brand Impersonation Detected: '{brand.upper()}'",
                "severity": "HIGH",
                "evidence": f"The high-value brand '{brand}' was detected in host '{hostname}', but the registered base domain is '{base_domain}'.",
                "impact": "High risk of phishing or credential harvesting mimicking {brand.title()}.",
                "remediation": "Check official service bookmarks. Do not provide credentials."
            })

    # 5. Suspicious Subdomain Depth
    if len(subdomains) >= 3:
        findings.append({
            "category": "HEURISTIC",
            "finding_title": "Unusual Subdomain Nesting Depth",
            "severity": "MEDIUM",
            "evidence": f"Domain contains {len(subdomains)} subdomain segments: {'.'.join(subdomains)}.",
            "impact": "Deep subdomain chaining is commonly used to construct spoofed URL prefixes resembling trusted brands.",
            "remediation": "Examine the rightmost root domain carefully."
        })

    # 6. Suspicious Keywords in Subdomains or Path
    full_path_str = f"{hostname}{path}?{query}".lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_path_str]
    if len(found_keywords) >= 2:
        findings.append({
            "category": "HEURISTIC",
            "finding_title": f"Multiple High-Sensitivity Action Keywords: {', '.join(found_keywords[:4])}",
            "severity": "MEDIUM",
            "evidence": f"URL path or query includes security/financial action keywords: {found_keywords[:4]}.",
            "impact": "Legitimate sites rarely cluster multiple login/verify/banking tokens in unauthenticated URL strings.",
            "remediation": "Verify whether you initiated an account action through an authenticated portal."
        })

    # 7. Unusual Port Number
    port = parsed_info["port"]
    if port and port not in (80, 443):
        findings.append({
            "category": "HEURISTIC",
            "finding_title": f"Non-Standard Service Port: :{port}",
            "severity": "MEDIUM",
            "evidence": f"Web traffic is routed over non-standard port {port}.",
            "impact": "Attackers often deploy temporary phishing panels on non-standard ports to bypass corporate perimeter firewalls.",
            "remediation": "Confirm service authenticity before transmitting sensitive information."
        })

    # 8. Excessive URL Length
    if len(raw_url) > 120:
        findings.append({
            "category": "HEURISTIC",
            "finding_title": "Excessive URL Length",
            "severity": "LOW",
            "evidence": f"URL string length is {len(raw_url)} characters (typical benign links are under 80 characters).",
            "impact": "Long obfuscated URLs are often used to push malicious domains out of view on mobile address bars.",
            "remediation": "Inspect the full address bar rather than truncated notification previews."
        })

    # 9. Excessive Hyphens in Hostname
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        findings.append({
            "category": "HEURISTIC",
            "finding_title": "Excessive Hyphenation in Domain Name",
            "severity": "LOW",
            "evidence": f"Hostname '{hostname}' contains {hyphen_count} hyphens.",
            "impact": "Phishing kits frequently generate domain variants like 'service-secure-login-account-update.com'.",
            "remediation": "Ensure this domain corresponds to an official organization."
        })

    # 10. High-abuse TLDs
    for tld in HIGH_RISK_TLDS:
        if hostname.endswith(tld):
            findings.append({
                "category": "HEURISTIC",
                "finding_title": f"High-Risk or Low-Cost TLD: {tld}",
                "severity": "MEDIUM",
                "evidence": f"Top-level domain '{tld}' exhibits historically elevated abuse rates in phishing campaigns.",
                "impact": "Free or deeply discounted TLDs are predominantly utilized for disposable disposable phishing campaigns.",
                "remediation": "Exercise heightened scrutiny before interacting with this domain."
            })
            break

    return findings
