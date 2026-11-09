import httpx
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.config import settings
from app.services.demo_data import is_synthetic_demo_host

def query_threat_intelligence(url: str, hostname: str) -> List[Dict[str, Any]]:
    """
    Query implemented providers and clearly label unavailable or synthetic results.
    Never converts an unavailable service into a clean verdict.
    """
    results: List[Dict[str, Any]] = []
    
    # Check synthetic demo
    is_synthetic = is_synthetic_demo_host(hostname)

    # 1. URLhaus Adapter (abuse.ch)
    urlhaus_result = {
        "source": "URLhaus (abuse.ch)",
        "is_available": False,
        "is_match": False,
        "verdict": "UNAVAILABLE",
        "confidence": "LOW",
        "details": {"query_type": "exact_url"},
        "checked_at": datetime.now(timezone.utc)
    }

    if is_synthetic:
        urlhaus_result["verdict"] = "SIMULATED_NO_MATCH"
        urlhaus_result["details"] = {"synthetic_simulation": True, "provider_queried": False}
        if "malware" in url or "phish" in url or "security-update" in url or "login" in url:
            urlhaus_result["is_match"] = True
            urlhaus_result["verdict"] = "SIMULATED_MALICIOUS"
            urlhaus_result["details"] = {
                "synthetic_simulation": True,
                "threat_type": "credential_stealer",
                "reporter": "TrustLens Benchmark Suite"
            }
        results.append(urlhaus_result)
    elif settings.URLHAUS_API_ENABLED:
        try:
            # Query URLhaus public lookup API
            with httpx.Client(timeout=4.0) as client:
                resp = client.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": url},
                    headers={"User-Agent": "TrustLens-AI-ThreatScanner/1.0"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if not isinstance(data, dict):
                        raise ValueError("Invalid URLhaus response format")
                    query_status = data.get("query_status")
                    urlhaus_result["is_available"] = True
                    if query_status == "ok":
                        urlhaus_result["is_match"] = True
                        urlhaus_result["verdict"] = "MALICIOUS"
                        urlhaus_result["confidence"] = "CONFIRMED"
                        urlhaus_result["details"] = {
                            "urlhaus_reference": data.get("urlhaus_reference"),
                            "threat": data.get("threat"),
                            "status": data.get("url_status"),
                            "tags": data.get("tags")
                        }
                    elif query_status == "no_results":
                        urlhaus_result["is_match"] = False
                        urlhaus_result["verdict"] = "NO_RECORD_FOUND"
                    else:
                        urlhaus_result["is_available"] = False
                        urlhaus_result["verdict"] = "UNAVAILABLE"
                        urlhaus_result["details"]["provider_status"] = query_status
                else:
                    urlhaus_result["is_available"] = False
                    urlhaus_result["verdict"] = "UNAVAILABLE"
                    urlhaus_result["details"]["error"] = f"HTTP {resp.status_code}"
        except (httpx.HTTPError, ValueError) as e:
            urlhaus_result["is_available"] = False
            urlhaus_result["verdict"] = "UNAVAILABLE"
            urlhaus_result["details"]["error"] = f"Provider request failed ({type(e).__name__})"
        results.append(urlhaus_result)
    else:
        urlhaus_result["is_available"] = False
        urlhaus_result["verdict"] = "DISABLED"
        results.append(urlhaus_result)

    # 2. PhishTank Adapter
    phishtank_result = {
        "source": "PhishTank",
        "is_available": False,
        "is_match": False,
        "verdict": "UNAVAILABLE",
        "confidence": "LOW",
        "details": {"status": "No live PhishTank lookup is implemented."},
        "checked_at": datetime.now(timezone.utc)
    }
    if is_synthetic:
        phishtank_result["verdict"] = "SIMULATED_NO_MATCH"
        if "paypal" in hostname or "bank" in hostname or "chase" in hostname:
            phishtank_result["is_match"] = True
            phishtank_result["verdict"] = "SIMULATED_MALICIOUS"
            phishtank_result["details"] = {
                "synthetic_simulation": True,
                "provider_queried": False,
                "target": "Financial Institution Impersonation"
            }
        else:
            phishtank_result["details"] = {"synthetic_simulation": True, "provider_queried": False}
        results.append(phishtank_result)
    else:
        results.append(phishtank_result)

    # 3. OpenPhish Adapter
    openphish_result = {
        "source": "OpenPhish Community Feed",
        "is_available": False,
        "is_match": False,
        "verdict": "UNAVAILABLE",
        "confidence": "LOW",
        "details": {"status": "No live OpenPhish lookup is implemented."},
        "checked_at": datetime.now(timezone.utc)
    }
    if is_synthetic:
        openphish_result["verdict"] = "SIMULATED_NO_MATCH"
        if "kyc" in url or "verify" in url:
            openphish_result["is_match"] = True
            openphish_result["verdict"] = "SIMULATED_MALICIOUS"
            openphish_result["details"] = {"synthetic_simulation": True, "provider_queried": False, "sector": "Banking / Telecommunications"}
        else:
            openphish_result["details"] = {"synthetic_simulation": True, "provider_queried": False}
    results.append(openphish_result)

    # 4. VirusTotal Adapter (Optional, requires API key)
    vt_result = {
        "source": "VirusTotal API",
        "is_available": False,
        "is_match": False,
        "verdict": "UNAVAILABLE",
        "confidence": "LOW",
        "details": {"status": "No API key configured (Optional integration)"},
        "checked_at": datetime.now(timezone.utc)
    }
    if is_synthetic:
        vt_result["verdict"] = "SIMULATED_NO_MATCH"
        vt_result["details"] = {"synthetic_simulation": True, "provider_queried": False}
    elif settings.VIRUSTOTAL_API_KEY:
        try:
            # Query VirusTotal v3 URL report
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}
                )
                if resp.status_code == 200:
                    vt_result["is_available"] = True
                    payload = resp.json()
                    if not isinstance(payload, dict):
                        raise ValueError("Invalid VirusTotal response format")
                    data = payload.get("data")
                    attributes = data.get("attributes") if isinstance(data, dict) else None
                    stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
                    if not isinstance(stats, dict):
                        raise ValueError("VirusTotal response omitted analysis statistics")
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    if not isinstance(malicious_count, int) or not isinstance(suspicious_count, int):
                        raise ValueError("VirusTotal response contained invalid analysis statistics")
                    
                    vt_result["details"] = stats
                    if malicious_count > 0:
                        vt_result["is_match"] = True
                        vt_result["verdict"] = "MALICIOUS"
                        vt_result["confidence"] = "HIGH"
                    elif suspicious_count > 0:
                        vt_result["is_match"] = True
                        vt_result["verdict"] = "SUSPICIOUS"
                        vt_result["confidence"] = "MEDIUM"
                    else:
                        vt_result["verdict"] = "NO_MALICIOUS_DETECTIONS"
                elif resp.status_code == 404:
                    vt_result["is_available"] = True
                    vt_result["verdict"] = "NO_RECORD_FOUND"
                else:
                    vt_result["is_available"] = False
                    vt_result["verdict"] = "UNAVAILABLE"
                    vt_result["details"] = {"status": f"HTTP {resp.status_code}"}
        except (httpx.HTTPError, ValueError) as e:
            vt_result["is_available"] = False
            vt_result["verdict"] = "UNAVAILABLE"
            vt_result["details"] = {"error": f"Provider request failed ({type(e).__name__})"}
    
    results.append(vt_result)
    return results
