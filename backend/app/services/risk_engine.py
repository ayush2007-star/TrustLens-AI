from typing import Dict, Any, List, Tuple

def calculate_risk_classification(
    findings: List[Dict[str, Any]],
    threat_intel_matches: List[Dict[str, Any]],
    tls_report: Dict[str, Any],
    domain_info: Dict[str, Any],
    redirect_info: Dict[str, Any]
) -> Tuple[str, int, str, str, List[str]]:
    """
    Evaluates all collected evidence across heuristics, domain intel, TLS,
    redirects, and external feeds to produce a deterministic, explainable classification.

    Returns:
        overall_risk: LOW RISK | SUSPICIOUS | HIGH RISK | CONFIRMED MALICIOUS | INCONCLUSIVE
        risk_score: 0 to 100
        confidence: LOW | MEDIUM | HIGH
        summary: Clear English explanation
        limitations: List of limitations
    """
    limitations = [
        "Risk classification is evidence-driven based on publicly observable indicators.",
        "The absence of an active threat intelligence record does not prove a website is safe.",
        "HTTPS certificate validity establishes encryption and identity binding, but never organizational legitimacy."
    ]

    # Check for INCONCLUSIVE conditions (e.g. host completely unreachable, no DNS, no data)
    has_a_records = bool(domain_info.get("a_records")) or bool(domain_info.get("aaaa_records"))
    has_tls = bool(tls_report.get("is_valid")) or bool(tls_report.get("status_text") and tls_report["status_text"] != "Insufficient information")
    dns_nxdomain = any("NXDOMAIN" in str(flag) for flag in domain_info.get("suspicious_dns_flags", []))

    if not has_a_records and not has_tls and not threat_intel_matches:
        return (
            "INCONCLUSIVE",
            10,
            "LOW",
            "Insufficient diagnostic information available. Target host could not be resolved or reached for analysis.",
            limitations
        )

    # Check for CONFIRMED MALICIOUS via authoritative threat intelligence
    confirmed_sources = []
    for match in threat_intel_matches:
        if match.get("is_match") and match.get("verdict") == "MALICIOUS":
            confirmed_sources.append(match.get("source", "Threat Intel"))

    if confirmed_sources:
        return (
            "CONFIRMED MALICIOUS",
            95,
            "HIGH",
            f"Target URL has been confirmed as malicious by authoritative threat intelligence feeds: {', '.join(confirmed_sources)}.",
            limitations
        )

    # Calculate deterministic heuristic score
    score = 0
    high_count = 0
    medium_count = 0
    critical_count = 0

    # 1. URL Findings Evaluation
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev == "CRITICAL":
            critical_count += 1
            score += 40
        elif sev == "HIGH":
            high_count += 1
            score += 25
        elif sev == "MEDIUM":
            medium_count += 1
            score += 12
        elif sev == "LOW":
            score += 4

    # 2. Redirect evaluation
    if redirect_info.get("domain_changed"):
        score += 15
        medium_count += 1
    if len(redirect_info.get("suspicious_patterns", [])) > 0:
        score += 15
        medium_count += 1

    # 3. TLS Evaluation
    if tls_report.get("status_text") == "Hostname mismatch":
        score += 30
        high_count += 1
    elif tls_report.get("status_text") == "Expired":
        score += 20
        medium_count += 1
    elif tls_report.get("status_text") == "Untrusted issuer or chain validation failure":
        score += 25
        high_count += 1

    # 4. Domain Age Evaluation
    age_days = domain_info.get("age_days")
    if age_days is not None:
        if age_days < 14:
            score += 30
            high_count += 1
        elif age_days < 60:
            score += 15
            medium_count += 1

    # Clamp score between 0 and 100
    score = min(score, 100)

    # Determine classification
    if critical_count > 0 or high_count >= 2 or score >= 65:
        overall_risk = "HIGH RISK"
        confidence = "HIGH"
        summary = (
            f"Multiple significant security anomalies detected (Score: {score}/100). "
            f"Observed {critical_count} critical and {high_count} high-severity indicators including suspicious structural patterns or identity mismatches."
        )
    elif high_count == 1 or medium_count >= 2 or score >= 35:
        overall_risk = "SUSPICIOUS"
        confidence = "MEDIUM"
        summary = (
            f"Suspicious characteristics observed (Score: {score}/100). "
            f"Observed {medium_count} moderate-severity indicator(s). Exercise caution before entering credentials."
        )
    else:
        overall_risk = "LOW RISK"
        confidence = "MEDIUM"
        summary = (
            f"No prominent malicious indicators detected across available checks (Score: {score}/100). "
            "However, absence of evidence is not proof of safety. Always verify sender identity independently."
        )

    return overall_risk, score, confidence, summary, limitations
