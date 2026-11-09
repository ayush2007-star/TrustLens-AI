import socket
import threading

import pytest
import app.services.ssrf_guard as ssrf_guard
from app.services.bounded_dns import bounded_dns_call
from app.services.ssrf_guard import is_ip_blocked, validate_target_host
from app.services.demo_data import is_synthetic_demo_host

def test_blocked_private_ips():
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("172.16.0.5") is True
    assert is_ip_blocked("192.168.1.1") is True
    assert is_ip_blocked("169.254.169.254") is True
    assert is_ip_blocked("::1") is True

def test_allowed_public_ips():
    # Public DNS
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False
    assert is_ip_blocked("2001:4860:4860::8888") is False


def test_non_global_ranges_are_blocked():
    assert is_ip_blocked("192.0.2.1") is True
    assert is_ip_blocked("::ffff:127.0.0.1") is True

def test_validate_target_host():
    safe, msg, _ = validate_target_host("localhost")
    assert safe is False
    assert "local" in msg.lower()

    safe, msg, _ = validate_target_host("127.0.0.1")
    assert safe is False
    assert "blocked" in msg.lower()


def test_dns_failure_is_not_safe(monkeypatch):
    def fail_resolution(*args, **kwargs):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)
    safe, message, addresses = validate_target_host("unresolvable.invalid")
    assert safe is False
    assert "DNS resolution failed" in message
    assert addresses == []


def test_dns_timeout_is_not_safe_and_does_not_wait_for_resolver(monkeypatch):
    release_resolver = threading.Event()
    monkeypatch.setattr(ssrf_guard, "DNS_RESOLUTION_TIMEOUT_SECONDS", 0.01)

    def blocked_resolution(*args, **kwargs):
        release_resolver.wait()
        return []

    monkeypatch.setattr(socket, "getaddrinfo", blocked_resolution)
    monkeypatch.setattr(
        ssrf_guard,
        "bounded_dns_call",
        lambda function, *args, **kwargs: bounded_dns_call(function, *args, **kwargs),
    )
    try:
        safe, message, addresses = validate_target_host("slow.example")
    finally:
        release_resolver.set()

    assert safe is False
    assert "timed out" in message.lower()
    assert addresses == []


def test_mixed_public_and_private_dns_answers_are_blocked(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ],
    )
    safe, message, addresses = validate_target_host("mixed.example")
    assert safe is False
    assert "restricted address" in message
    assert addresses == ["8.8.8.8", "127.0.0.1"]


def test_demo_domain_matching_uses_label_boundaries():
    assert is_synthetic_demo_host("sub.example.com") is True
    assert is_synthetic_demo_host("example.com.attacker.test") is False
    assert is_synthetic_demo_host("notexample.com") is False
