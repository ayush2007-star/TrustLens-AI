import pytest
from app.services.url_normalizer import normalize_url, analyze_url_heuristics


def test_url_rejects_embedded_userinfo_before_network_checks():
    for bad_url in [
        "https://user:password@example.com/",
        "https://paypal.com@attacker.example/",
        "https://user@example.com/",
        "https://:password@example.com/",
    ]:
        with pytest.raises(ValueError, match="userinfo|credentials|username|password"):
            normalize_url(bad_url)

def test_url_normalization_basic():
    res = normalize_url("github.com/torvalds")
    assert res["scheme"] == "https"
    assert res["hostname"] == "github.com"
    assert res["base_domain"] == "github.com"

def test_url_heuristics_ip_address():
    res = normalize_url("http://192.0.2.1/login")
    findings = analyze_url_heuristics(res)
    assert any(f["finding_title"] == "IP Address Used in Place of Hostname" for f in findings)

def test_url_heuristics_brand_impersonation():
    res = normalize_url("https://paypal-security-update.example.com/login")
    findings = analyze_url_heuristics(res)
    assert any("Brand Impersonation Detected" in f["finding_title"] for f in findings)

def test_url_heuristics_credentials():
    with pytest.raises(ValueError, match="userinfo|credentials|username|password"):
        normalize_url("https://user:password@malicious-site.com/steal")


def test_at_symbol_in_path_is_not_mistaken_for_authority_userinfo():
    parsed = normalize_url("https://example.test/account@help")
    findings = analyze_url_heuristics(parsed)
    assert not any("Embedded Userinfo" in f["finding_title"] for f in findings)


def test_ipv6_url_normalization_preserves_brackets_and_domain():
    parsed = normalize_url("https://[2001:4860:4860::8888]:8443/path")
    assert parsed["normalized_url"] == "https://[2001:4860:4860::8888]:8443/path"
    assert parsed["base_domain"] == "2001:4860:4860::8888"
