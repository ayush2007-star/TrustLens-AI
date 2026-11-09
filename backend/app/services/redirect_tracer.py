import http.client
import ssl
import urllib.parse
from typing import Any, Dict, List

from app.config import settings
from app.services.demo_data import is_synthetic_demo_host
from app.services.safe_http import safe_request
from app.services.ssrf_guard import SSRFSecurityError


def trace_redirects_safely(initial_url: str) -> Dict[str, Any]:
    """Trace redirects one hop at a time, pinning each validated public address."""
    chain: List[Dict[str, Any]] = []
    current_url = initial_url
    visited_urls = set()
    initial_host = urllib.parse.urlsplit(initial_url).hostname or ""
    final_url = initial_url
    suspicious_patterns: List[str] = []

    if is_synthetic_demo_host(initial_host):
        return {
            "initial_url": initial_url,
            "final_url": initial_url,
            "redirect_count": 0,
            "chain": [],
            "domain_changed": False,
            "suspicious_patterns": [],
        }

    for step in range(settings.MAX_REDIRECTS):
        if current_url in visited_urls:
            suspicious_patterns.append(f"Circular redirect loop detected targeting {current_url}.")
            break
        visited_urls.add(current_url)

        try:
            response = safe_request(
                "HEAD",
                current_url,
                headers={"User-Agent": "TrustLens-AI-SecurityScanner/1.0"},
            )
            if response.status_code in (405, 501):
                response = safe_request(
                    "GET",
                    current_url,
                    headers={"User-Agent": "TrustLens-AI-SecurityScanner/1.0"},
                    max_bytes=settings.MAX_RESPONSE_BYTES,
                )
        except (SSRFSecurityError, OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            suspicious_patterns.append(f"Redirect trace stopped: {str(exc)[:100]}")
            break

        location = response.headers.get("location")
        if response.status_code not in (301, 302, 303, 307, 308) or not location:
            final_url = current_url
            break

        next_url = urllib.parse.urljoin(current_url, location)
        next_parsed = urllib.parse.urlsplit(next_url)
        current_parsed = urllib.parse.urlsplit(current_url)
        next_host = next_parsed.hostname or ""
        if next_parsed.scheme not in ("http", "https") or not next_host:
            suspicious_patterns.append("Redirect destination used an unsupported scheme or had no hostname.")
            break

        next_port = next_parsed.port or (443 if next_parsed.scheme == "https" else 80)
        if next_port not in (80, 443):
            suspicious_patterns.append(
                f"Redirect target '{next_url}' uses non-standard port {next_port}. Passive inspection only allows HTTP/HTTPS ports 80 and 443."
            )
            break

        try:
            safe_request("HEAD", next_url)
        except Exception as exc:  # validation and network checks must be independent per redirect hop
            suspicious_patterns.append(f"Redirect target validation failed for '{next_url}': {exc}")
            break

        domain_changed = current_parsed.hostname != next_host
        chain.append({
            "hop": step + 1,
            "from_url": current_url,
            "to_url": next_url,
            "status_code": response.status_code,
            "domain_changed": domain_changed,
        })
        if domain_changed:
            suspicious_patterns.append(f"Cross-domain redirect from '{current_parsed.hostname}' to '{next_host}'.")
        current_url = next_url
        final_url = next_url
    else:
        suspicious_patterns.append(
            f"Redirect limit of {settings.MAX_REDIRECTS} hops reached."
        )

    final_host = urllib.parse.urlsplit(final_url).hostname or ""
    return {
        "initial_url": initial_url,
        "final_url": final_url,
        "redirect_count": len(chain),
        "chain": chain,
        "domain_changed": initial_host != final_host,
        "suspicious_patterns": suspicious_patterns,
    }
