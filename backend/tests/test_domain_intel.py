import threading

import app.services.domain_intel as domain_intel
from app.services.bounded_dns import bounded_dns_call


def test_whois_is_explicitly_unavailable_without_calling_library(monkeypatch):
    def unexpected_lookup(domain):
        raise AssertionError("WHOIS lookup must remain disabled.")

    class Whois:
        whois = staticmethod(unexpected_lookup)

    monkeypatch.setattr(domain_intel, "whois", Whois(), raising=False)

    result = domain_intel.inspect_whois_data("example.test")

    assert result["status"] == (
        "WHOIS lookup unavailable: the client cannot guarantee a bounded lookup."
    )
    assert result["raw_whois_available"] is False


def test_socket_dns_fallback_returns_timeout_status(monkeypatch):
    release_resolver = threading.Event()
    monkeypatch.setattr(domain_intel, "DNS_AVAILABLE", False)
    monkeypatch.setattr(domain_intel, "DNS_RESOLUTION_TIMEOUT_SECONDS", 0.01)

    def blocked_resolution(hostname):
        release_resolver.wait()
        return hostname, [], []

    monkeypatch.setattr(domain_intel.socket, "gethostbyname_ex", blocked_resolution)
    monkeypatch.setattr(
        domain_intel,
        "bounded_dns_call",
        lambda function, *args, **kwargs: bounded_dns_call(function, *args, **kwargs),
    )
    try:
        result = domain_intel.inspect_dns_records("slow.example")
    finally:
        release_resolver.set()

    assert result["error"] == "DNS resolution timed out."
    assert result["a_records"] == []
