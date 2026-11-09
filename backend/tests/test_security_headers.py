from app.services.security_headers import assess_website_security


def test_blocked_https_target_is_not_reported_as_available():
    result = assess_website_security("https://127.0.0.1/")
    assert result["https_available"] is False
    assert result["http_status"] is None
    assert any("failed" in item.lower() for item in result["limitations"])
