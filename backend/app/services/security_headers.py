import http.client
import urllib.parse
from http.cookies import SimpleCookie
from typing import Dict, Any, List
from app.services.safe_http import safe_request
from app.services.demo_data import is_synthetic_demo_host
from app.services.ssrf_guard import SSRFSecurityError
from app.config import settings

def assess_website_security(target_url: str) -> Dict[str, Any]:
    """
    Performs strictly passive, non-intrusive security checks on HTTP headers,
    cookies, TLS availability, robots.txt, and security.txt.
    """
    parsed = urllib.parse.urlsplit(target_url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme or "https"

    result = {
        "https_available": False,
        "http_status": None,
        "security_headers": {},
        "cookies": [],
        "robots_txt_status": "Not found",
        "security_txt_status": "Not found",
        "passive_findings": [],
        "limitations": [
            "Assessment is strictly passive and based solely on publicly observable HTTP response headers.",
            "Absence of a security header does not guarantee vulnerability if upstream WAF or edge mitigations exist.",
            "No active probing, port scanning, or intrusive payloads were dispatched."
        ]
    }

    # Synthetic demo handling
    if is_synthetic_demo_host(hostname):
        result.update({
            "https_available": True,
            "http_status": 200,
            "security_headers": {
                "strict_transport_security": "max-age=31536000; includeSubDomains",
                "content_security_policy": "default-src 'self'",
                "x_frame_options": "DENY",
                "x_content_type_options": "nosniff",
                "referrer_policy": "strict-origin-when-cross-origin",
                "permissions_policy": "geolocation=()"
            },
            "cookies": [],
            "robots_txt_status": "Present (HTTP 200)",
            "security_txt_status": "Present (HTTP 200 / RFC 9116)",
            "passive_findings": [
                {
                    "title": "Strict-Transport-Security (HSTS) Configured",
                    "severity": "INFO",
                    "evidence": "Strict-Transport-Security: max-age=31536000",
                    "impact": "Enforces HTTPS encryption for future browser visits.",
                    "remediation": "Maintain current configuration."
                }
            ]
        })
        return result

    # SSRF guard
    headers_dict = {}
    cookies_list = []

    try:
        resp = safe_request(
            "GET",
            target_url,
            headers={"User-Agent": "TrustLens-AI-PassiveAuditor/1.0"},
            max_bytes=settings.MAX_RESPONSE_BYTES,
        )
        result["http_status"] = resp.status_code
        result["https_available"] = scheme == "https"
        for raw_cookie in resp.set_cookie_headers:
            parsed_cookie = SimpleCookie()
            parsed_cookie.load(raw_cookie)
            for name, cookie in parsed_cookie.items():
                cookies_list.append({
                    "name": name,
                    "domain": cookie["domain"],
                    "path": cookie["path"],
                    "secure": bool(cookie["secure"]),
                    "httponly": bool(cookie["httponly"]),
                })
        headers_dict = resp.headers
    except (SSRFSecurityError, OSError, http.client.HTTPException, ValueError) as e:
        result["limitations"].append(f"HTTP passive request failed: {str(e)[:100]}")
        return result

    result["cookies"] = cookies_list

    # Assess Headers
    findings: List[Dict[str, Any]] = []

    # 1. HSTS
    hsts = headers_dict.get("strict-transport-security")
    result["security_headers"]["strict_transport_security"] = hsts or "Missing"
    if not hsts:
        findings.append({
            "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
            "severity": "MEDIUM",
            "evidence": "Header 'Strict-Transport-Security' was not present in the HTTP response.",
            "impact": "Users connecting via HTTP may be susceptible to SSL-stripping and man-in-the-middle downgrade attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
        })
    else:
        findings.append({
            "title": "HSTS Enforced",
            "severity": "INFO",
            "evidence": f"Strict-Transport-Security: {hsts}",
            "impact": "Protects users against SSL stripping downgrades.",
            "remediation": "Ensure max-age is at least 1 year (31536000 seconds)."
        })

    # 2. CSP
    csp = headers_dict.get("content-security-policy")
    result["security_headers"]["content_security_policy"] = csp or "Missing"
    if not csp:
        findings.append({
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "MEDIUM",
            "evidence": "Header 'Content-Security-Policy' was not present in the HTTP response.",
            "impact": "Increases susceptibility to Cross-Site Scripting (XSS), data injection, and malicious script execution.",
            "remediation": "Define a restrictive CSP specifying permitted origins for scripts, styles, frames, and connect-src."
        })

    # 3. X-Frame-Options
    xfo = headers_dict.get("x-frame-options")
    result["security_headers"]["x_frame_options"] = xfo or "Missing"
    if not xfo and (not csp or "frame-ancestors" not in csp):
        findings.append({
            "title": "Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
            "severity": "MEDIUM",
            "evidence": "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' directive was detected.",
            "impact": "Adversaries can embed the target application inside a transparent iframe to trick users into unauthorized clicks.",
            "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors 'self''."
        })

    # 4. X-Content-Type-Options
    xcto = headers_dict.get("x-content-type-options")
    result["security_headers"]["x_content_type_options"] = xcto or "Missing"
    if not xcto or "nosniff" not in xcto.lower():
        findings.append({
            "title": "Missing or Weak X-Content-Type-Options Header",
            "severity": "LOW",
            "evidence": f"Header value: {xcto or 'Missing'}.",
            "impact": "Older browsers may execute non-executable MIME types by MIME-sniffing content, exposing users to cross-site script inclusion.",
            "remediation": "Add 'X-Content-Type-Options: nosniff'."
        })

    # 5. Referrer-Policy
    ref = headers_dict.get("referrer-policy")
    result["security_headers"]["referrer_policy"] = ref or "Missing"
    if not ref:
        findings.append({
            "title": "Missing Referrer-Policy Header",
            "severity": "LOW",
            "evidence": "Header 'Referrer-Policy' was not configured.",
            "impact": "Browser may leak sensitive path information or auth tokens in the Referer header to external third parties.",
            "remediation": "Implement 'Referrer-Policy: strict-origin-when-cross-origin'."
        })

    # 6. Permissions-Policy
    perm = headers_dict.get("permissions-policy")
    result["security_headers"]["permissions_policy"] = perm or "Missing"

    # 7. Server Banner Leakage
    server_hdr = headers_dict.get("server")
    if server_hdr:
        findings.append({
            "title": "Server Software Fingerprint Exposed",
            "severity": "INFO",
            "evidence": f"Server: {server_hdr}",
            "impact": "Revealing detailed web server versions aids adversaries in fingerprinting known software CVEs.",
            "remediation": "Suppress detailed server tokens in web server configuration (e.g. ServerTokens Prod in Apache)."
        })

    # 8. Check robots.txt & security.txt passively
    base_origin = f"{scheme}://{parsed.netloc}"
    try:
        r_robots = safe_request("HEAD", f"{base_origin}/robots.txt")
        if r_robots.status_code == 200:
            result["robots_txt_status"] = "Present (HTTP 200)"
        elif r_robots.status_code == 404:
            result["robots_txt_status"] = "Not Found (HTTP 404)"
        else:
            result["robots_txt_status"] = f"HTTP {r_robots.status_code}"

        r_sec = safe_request("HEAD", f"{base_origin}/.well-known/security.txt")
        if r_sec.status_code == 200:
            result["security_txt_status"] = "Present (HTTP 200 / RFC 9116)"
        else:
            result["security_txt_status"] = f"HTTP {r_sec.status_code}"
    except (SSRFSecurityError, OSError, http.client.HTTPException, ValueError) as exc:
        result["limitations"].append(f"robots.txt/security.txt checks failed: {str(exc)[:100]}")

    result["passive_findings"] = findings
    return result
