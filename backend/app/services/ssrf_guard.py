import ipaddress
import socket
from typing import List, Tuple

from app.services.bounded_dns import DNS_RESOLUTION_TIMEOUT_SECONDS, bounded_dns_call


SAFE_HTTP_PORTS = {80, 443}


class SSRFSecurityError(Exception):
    """Raised when an SSRF attempt is detected."""


def is_safe_port(scheme: str, port: int | None) -> bool:
    """Passive inspection is limited to standard HTTP/HTTPS ports to avoid arbitrary service exposure."""
    if port is None:
        port = 443 if scheme.lower() == "https" else 80
    return port in SAFE_HTTP_PORTS


def is_ip_blocked(ip_str: str) -> bool:
    """Allow only globally routable addresses for outbound target connections."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return not ip.is_global
    except ValueError:
        return True


def validate_target_host(hostname_or_ip: str) -> Tuple[bool, str, List[str]]:
    """
    Resolve a target once and return only public addresses suitable for pinned use.
    Any blocked or unresolved address rejects the hostname to prevent mixed-answer
    DNS responses from bypassing the network policy.
    """
    clean_host = hostname_or_ip.strip().lower()
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]
    clean_host = clean_host.rstrip(".")
    if not clean_host:
        return False, "Target hostname is empty.", []

    local_names = ("localhost", "localdomain", "broadcasthost", "local", "internal", "lan", "home")
    if any(clean_host == name or clean_host.endswith(f".{name}") for name in local_names):
        return False, f"Target hostname '{clean_host}' is in a local/internal namespace.", []

    try:
        address = ipaddress.ip_address(clean_host)
    except ValueError:
        address = None

    if address is not None:
        if is_ip_blocked(str(address)):
            return False, f"IP address {clean_host} is blocked because it is not globally routable.", [str(address)]
        return True, "", [str(address)]

    try:
        address_info = bounded_dns_call(
            socket.getaddrinfo,
            clean_host,
            None,
            timeout=DNS_RESOLUTION_TIMEOUT_SECONDS,
            type=socket.SOCK_STREAM,
        )
    except TimeoutError:
        return False, f"DNS resolution timed out for '{clean_host}'.", []
    except (socket.gaierror, OSError) as exc:
        return False, f"DNS resolution failed for '{clean_host}': {exc}", []

    resolved_ips = list(dict.fromkeys(item[4][0] for item in address_info))
    if not resolved_ips:
        return False, f"DNS returned no addresses for '{clean_host}'.", []

    blocked_ips = [ip for ip in resolved_ips if is_ip_blocked(ip)]
    if blocked_ips:
        return False, f"Hostname '{clean_host}' resolves to a restricted address.", resolved_ips

    return True, "", resolved_ips
