def is_synthetic_demo_host(hostname: str) -> bool:
    """Return whether a hostname is within an RFC 2606 example domain."""
    host = hostname.lower().rstrip(".")
    return any(
        host == domain or host.endswith(f".{domain}")
        for domain in ("example.com", "example.org", "example.net")
    )
