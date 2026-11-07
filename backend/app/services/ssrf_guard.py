import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List

# Blocked IP networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001::/23"),          # IETF Protocol
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

class SSRFSecurityError(Exception):
    """Raised when an SSRF attempt is detected."""
    pass

def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP string falls into private, loopback, or reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
            
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return True

def validate_target_host(hostname_or_ip: str) -> Tuple[bool, str, List[str]]:
    """
    Validates that a hostname or IP is not pointing to private/internal infrastructure.
    Returns (is_safe, error_message, resolved_ips).
    """
    clean_host = hostname_or_ip.strip().lower()
    
    # Strip port if present
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = clean_host.split(":")[0]
    elif clean_host.startswith("[") and "]" in clean_host:
        clean_host = clean_host[1:clean_host.index("]")]
        
    # Check known local names
    local_keywords = ["localhost", "localdomain", "broadcasthost", ".local", ".internal", ".lan", ".home"]
    for kw in local_keywords:
        if clean_host == kw or clean_host.endswith(kw):
            return False, f"Target hostname '{clean_host}' resolves to local/internal network namespace.", []

    # Try parsing direct IP
    try:
        ip = ipaddress.ip_address(clean_host)
        if is_ip_blocked(str(ip)):
            return False, f"Direct IP address {clean_host} belongs to a blocked/private network range.", [str(ip)]
        return True, "", [str(ip)]
    except ValueError:
        pass # Not a raw IP, it's a hostname

    # Resolve via DNS and check every resolved address
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        for item in addr_info:
            ip_val = item[4][0]
            if ip_val not in resolved_ips:
                resolved_ips.append(ip_val)
                if is_ip_blocked(ip_val):
                    return False, f"Hostname '{clean_host}' resolves to private/internal address {ip_val}.", resolved_ips
    except socket.gaierror as e:
        # DNS could not resolve, which is safe from SSRF but means host is unreachable
        return True, f"DNS resolution failed: {str(e)}", []
    except Exception as e:
        return False, f"Resolution error: {str(e)}", []

    return True, "", resolved_ips
