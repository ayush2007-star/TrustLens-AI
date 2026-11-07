import pytest
from app.services.ssrf_guard import is_ip_blocked, validate_target_host

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

def test_validate_target_host():
    safe, msg, _ = validate_target_host("localhost")
    assert safe is False
    assert "local" in msg.lower()

    safe, msg, _ = validate_target_host("127.0.0.1")
    assert safe is False
    assert "blocked" in msg.lower()
