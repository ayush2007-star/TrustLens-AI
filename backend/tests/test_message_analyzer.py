import pytest
from app.services.message_analyzer import analyze_scam_message_deterministic

def test_banking_otp_scam_detection():
    msg = "URGENT: Your Chase bank account is suspended. Reply with your one-time password OTP immediately to restore access."
    res = analyze_scam_message_deterministic(msg)
    assert res["risk_level"] in ("HIGH RISK", "CONFIRMED MALICIOUS")
    assert any(i["category"] == "CREDENTIAL_HARVESTING" for i in res["indicators"])
    assert any(i["category"] == "URGENCY" for i in res["indicators"])

def test_benign_message():
    msg = "Hi Mom, please remember to buy milk and bread on your way home today. Thanks!"
    res = analyze_scam_message_deterministic(msg)
    assert res["risk_level"] == "LOW RISK"
    assert len(res["indicators"]) == 0
