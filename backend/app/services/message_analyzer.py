import re
from typing import Dict, Any, List

# Regex patterns for social engineering indicators
URGENCY_PATTERNS = [
    (r"(?i)\b(urgent|immediately|within\s+(?:24|12|48)\s*hours?|act\s+now|action\s+required|critical\s+alert|final\s+notice)\b",
     "High-pressure artificial deadline", "URGENCY", "HIGH"),
    (r"(?i)\b(suspend(?:ed)?|block(?:ed)?|terminat(?:ed)?|freez(?:e|ing|en))\s+(?:your\s+)?(?:account|card|access|wallet)\b",
     "Threat of punitive service termination", "URGENCY", "HIGH"),
    (r"(?i)\b(limited\s+time|expires?\s+today|last\s+chance)\b",
     "Scarcity pressure tactic", "URGENCY", "MEDIUM"),
]

CREDENTIAL_PATTERNS = [
    (r"(?i)\b(one[\s-]?time\s+password|otp|verification\s+code|2fa\s+code|auth\s+token)\b",
     "Solicitation of One-Time Password / Security Code", "CREDENTIAL_HARVESTING", "CRITICAL"),
    (r"(?i)\b(password|pin|security\s+question|seed\s+phrase|private\s+key)\b",
     "Request for confidential authentication credentials", "CREDENTIAL_HARVESTING", "CRITICAL"),
]

PAYMENT_PATTERNS = [
    (r"(?i)\b(gift\s*card|crypto(?:currency)?|bitcoin|usdt|wire\s+transfer|western\s+union|zelle|cash\s*app|venmo)\b",
     "Irreversible or untraceable payment method solicited", "SUSPICIOUS_PAYMENT", "HIGH"),
    (r"(?i)\b(pay\s+(?:fee|customs|tax|release\s+charge|deposit))\b",
     "Advance-fee payment demand", "SUSPICIOUS_PAYMENT", "HIGH"),
]

REWARD_PATTERNS = [
    (r"(?i)\b(you(?:'ve|\s+have)\s+won|lottery|jackpot|prize|claim\s+your\s+(?:reward|bonus|gift|free\s+crypto))\b",
     "Unsolicited prize or windfall lure", "FAKE_REWARD", "HIGH"),
    (r"(?i)\b(guaranteed\s+(?:returns?|profit)|100%\s+daily\s+profit|no\s+risk\s+investment)\b",
     "High-yield investment fraud / Ponzi bait", "FAKE_REWARD", "HIGH"),
]

REMOTE_ACCESS_PATTERNS = [
    (r"(?i)\b(anydesk|teamviewer|ultraviewer|quicksupport|rustdesk|remote\s+desktop|install\s+(?:apk|app))\b",
     "Demand to install remote-administration or screen-sharing software", "REMOTE_ACCESS", "CRITICAL"),
]

IMPERSONATION_PATTERNS = [
    (r"(?i)\b(irs|hmrc|customs|police|fbi|interpol|court\s+summons|arrest\s+warrant)\b",
     "Impersonation of law enforcement or government tax authority", "IMPERSONATION", "CRITICAL"),
    (r"(?i)\b(fraud\s+department|security\s+team|compliance\s+officer|anti-fraud\s+unit)\b",
     "Impersonation of banking/security fraud staff", "IMPERSONATION", "HIGH"),
    (r"(?i)\b(fedex|dhl|usps|ups|royal\s+mail|amazon\s+delivery)\b",
     "Impersonation of postal courier regarding pending parcel", "IMPERSONATION", "MEDIUM"),
]

LINK_PATTERNS = [
    (r"https?://[^\s<>\"']+", "Suspicious or unverified external web link", "MALICIOUS_LINK", "MEDIUM"),
    (r"\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy)/\w+", "Obfuscated URL shortener disguising destination", "MALICIOUS_LINK", "HIGH"),
]

def analyze_scam_message_deterministic(message_text: str) -> Dict[str, Any]:
    """
    Deterministic rule-based analyzer for phishing, smishing, and social engineering messages.
    Operates locally with 0 network latency, 0 external API dependencies, and high consistency.
    """
    indicators = []
    text = message_text.strip()
    
    # Check Urgency
    for pattern, title, category, sev in URGENCY_PATTERNS:
        match = re.search(pattern, text)
        if match:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": match.group(0),
                "reasoning": "Fraudsters create artificial deadlines and fear of consequence to bypass logical evaluation."
            })

    # Check Credential harvesting
    for pattern, title, category, sev in CREDENTIAL_PATTERNS:
        match = re.search(pattern, text)
        if match:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": match.group(0),
                "reasoning": "Legitimate banking, tech, and security institutions will NEVER request passwords, PINs, or OTPs via SMS/email."
            })

    # Check Suspicious payments
    for pattern, title, category, sev in PAYMENT_PATTERNS:
        match = re.search(pattern, text)
        if match:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": match.group(0),
                "reasoning": "Requests for untraceable gift cards, wire transfers, or direct crypto transfers are primary signatures of advance-fee fraud."
            })

    # Check Fake rewards / investments
    for pattern, title, category, sev in REWARD_PATTERNS:
        match = re.search(pattern, text)
        if match:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": match.group(0),
                "reasoning": "Unsolicited prizes, lottery claims, or 'guaranteed risk-free' investment offers are classic social engineering hooks."
            })

    # Check Remote access
    for pattern, title, category, sev in REMOTE_ACCESS_PATTERNS:
        match = re.search(pattern, text)
        if match:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": match.group(0),
                "reasoning": "Instructing a victim to install remote desktop tools gives adversaries direct device compromise and banking session takeover."
            })

    # Check Impersonation
    for pattern, title, category, sev in IMPERSONATION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": match.group(0),
                "reasoning": "Impersonating authoritative bodies (banks, law enforcement, couriers) establishes false trust or intimidation."
            })

    # Check Links
    for pattern, title, category, sev in LINK_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            indicators.append({
                "category": category,
                "title": title,
                "severity": sev,
                "evidence_snippet": str(matches[0])[:60],
                "reasoning": "Embedded links in unsolicited communications commonly route to credential-stealing replica portals."
            })
            break

    # Calculate Score & Severity
    critical_count = sum(1 for i in indicators if i["severity"] == "CRITICAL")
    high_count = sum(1 for i in indicators if i["severity"] == "HIGH")
    medium_count = sum(1 for i in indicators if i["severity"] == "MEDIUM")

    score = (critical_count * 35) + (high_count * 20) + (medium_count * 10)
    score = min(score, 100)

    recommended_precautions = []
    if critical_count > 0 or high_count > 0:
        recommended_precautions.extend([
            "Never disclose One-Time Passwords (OTPs), PINs, or account passwords to anyone.",
            "Do not click links inside this message. Navigate independently to the service's official website or app.",
            "If this claims to be from your bank or a government agency, contact their official phone number directly."
        ])
    if any(i["category"] == "REMOTE_ACCESS" for i in indicators):
        recommended_precautions.append("Do NOT install any remote desktop applications (AnyDesk, TeamViewer) requested by third parties.")
    if not recommended_precautions:
        recommended_precautions.append("Verify the sender's identity using known, verified contact channels before taking action.")

    if critical_count >= 1 or score >= 70:
        risk_level = "HIGH RISK"
        confidence = "HIGH"
        summary = f"High probability of social engineering or phishing scam ({score}/100). Found {critical_count} critical indicator(s)."
        explanation = (
            "This communication exhibits hallmark techniques of cyber fraud, including pressure tactics "
            "and direct attempts to extract credentials, money, or device control. Do not interact."
        )
    elif high_count >= 1 or score >= 35:
        risk_level = "SUSPICIOUS"
        confidence = "MEDIUM"
        summary = f"Suspicious communication pattern detected ({score}/100)."
        explanation = (
            "The message contains manipulative social engineering patterns or unverified links. "
            "Proceed with extreme skepticism."
        )
    else:
        risk_level = "LOW RISK"
        confidence = "LOW"
        summary = f"No immediate high-severity threat markers identified ({score}/100)."
        explanation = (
            "Standard conversational or benign patterns observed. However, always exercise caution "
            "with unexpected requests or attachments."
        )

    limitations = [
        "Rule-based analysis evaluates lexical and contextual threat signatures.",
        "Persuasive phrasing alone does not guarantee fraud, but warrants high caution.",
        "Zero sensitive data (passwords, OTPs) is retained."
    ]

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "confidence": confidence,
        "analyzed_via": "deterministic",
        "summary": summary,
        "indicators": indicators,
        "explanation": explanation,
        "recommended_precautions": recommended_precautions,
        "limitations": limitations
    }


def analyze_scam_message(message_text: str) -> Dict[str, Any]:
    """Run the local deterministic analyzer; no submitted text is sent to an LLM."""
    return analyze_scam_message_deterministic(message_text)
