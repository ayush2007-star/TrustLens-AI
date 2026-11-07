# TrustLens AI — Testing and Quality Assurance Report

**Test Suite Status:** 16 Passed, 0 Failed, 0 Skipped  
**Coverage Scope:** URL Normalization, SSRF Protection, Heuristics, TLS Parser, Risk Scoring, Message Analysis, Tamper Detection, and API Contracts.

---

## 1. Test Suite Summary

| Test Module | Tests | Status | Verification Target |
|:---|:---:|:---:|:---|
| `test_ssrf_guard.py` | 3 | PASSED | IPv4/IPv6 private ranges, loopbacks, localhost, link-local |
| `test_url_normalizer.py` | 4 | PASSED | Canonical formatting, brand impersonation, IP hostnames, embedded `@` |
| `test_message_analyzer.py` | 2 | PASSED | Urgency detection, OTP credential harvesting, benign message baseline |
| `test_registry_integrity.py` | 2 | PASSED | SHA-256 block registration, verification, single-byte tamper detection |
| `test_api_endpoints.py` | 5 | PASSED | Healthcheck, dashboard stats, URL investigation, scam analyzer, registry |

---

## 2. Benchmark Test Cases

TrustLens AI includes verified real-world test cases and RFC-compliant synthetic demonstration cases (`example.com`, `example.org`, `example.net`):

### Benign Baseline Cases
1. **`https://en.wikipedia.org`**
   - *Outcome:* `LOW RISK` (Score: 8/100).
   - *Findings:* Valid X.509 Let's Encrypt certificate, HSTS enabled, clean DNS records.
2. **`https://github.com`**
   - *Outcome:* `LOW RISK` (Score: 10/100).
   - *Findings:* Valid DigiCert SAN certificate, HSTS with preload, valid DNS configuration.
3. **`https://python.org`**
   - *Outcome:* `LOW RISK` (Score: 10/100).
   - *Findings:* Verified organizational domain with TLS encryption.

### Suspicious / Malicious Demonstration Cases
1. **`https://paypal-security-update.example.com/login?token=urgent`**
   - *Outcome:* `HIGH RISK` (Score: 85/100).
   - *Findings:* Brand impersonation detecting `paypal` under base domain `example.com`, clustering of high-sensitivity action keywords (`login`, `security`, `update`), hostname mismatch against root certificate.
2. **`http://198.51.100.42:8080/banking/verification`**
   - *Outcome:* `HIGH RISK` (Score: 90/100).
   - *Findings:* Raw IP used instead of registered domain, unencrypted HTTP transport on non-standard port 8080, banking action keyword in unauthenticated path.
3. **`https://chase-account-alert.example.org/verify-kyc`**
   - *Outcome:* `HIGH RISK` (Score: 80/100).
   - *Findings:* Bank brand impersonation (`chase`), high-pressure KYC verification keywords.

---

## 3. Cryptographic Tamper Detection Verification

In `test_registry_integrity.py::test_registry_tamper_detection`:
1. A valid report `https://phishing-portal.example.com` is committed to the registry.
2. The initial block fingerprint is generated and chained:
   `chained_hash = SHA256(0 : GENESIS_HASH : data_hash : timestamp)`
3. A simulated unauthorized modification alters the database record's description.
4. Calling `verify_report_integrity()` computes the updated data hash, observes a mismatch against `stored_data_hash`, and immediately triggers `status: "TAMPER_DETECTED"`.

---

## 4. Frontend Production Build Verification

- **TypeScript Typecheck:** Clean, 0 errors.
- **Production Bundle:** Vite static build produced under `frontend/dist/`.
