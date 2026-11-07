import pytest
from app.services.url_normalizer import normalize_url, analyze_url_heuristics

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
    res = normalize_url("https://user:password@malicious-site.com/steal")
    findings = analyze_url_heuristics(res)
    assert any("Embedded Userinfo" in f["finding_title"] for f in findings)
