# TrustLens AI — Security Methodology & Threat Model

## 1. Core Security Axioms

1. **HTTPS Confirms Encryption, Not Legitimacy:**
   A valid TLS certificate issued by a trusted Certificate Authority (e.g., Let's Encrypt, DigiCert) only verifies that communication with that specific domain is encrypted and that the domain registrant verified control of the DNS/host at issue time. Over 80% of modern phishing websites operate over valid HTTPS certificates. TrustLens AI treats HTTPS strictly as a transport security parameter, not proof of organizational trustworthiness.

2. **Absence of Evidence is Not Evidence of Safety:**
   Cyber adversaries deploy disposable domains and targeted lure infrastructure that may remain unindexed by global threat feeds for the first 24–72 hours of a campaign. TrustLens AI never marks a domain "Safe" solely because external threat intelligence APIs returned zero matching records.

3. **Strictly Passive, Non-Intrusive Assessment:**
   TrustLens AI adheres strictly to non-intrusive observation:
   - Evaluates HTTP response headers and cookies provided in standard GET/HEAD responses.
   - Inspects public DNS resource records (A, AAAA, MX, NS, TXT).
   - Retrieves public X.509 TLS certificates.
   - Probes RFC 9116 security endpoints (`/.well-known/security.txt`, `robots.txt`).
   - **Never attempts:** SQL injection, XSS exploitation, port scanning, authentication brute-forcing, credential stuffing, or remote code execution.

---

## 2. Server-Side Request Forgery (SSRF) Defenses

When inspecting arbitrary external URLs provided by untrusted users, backend scanners are prime targets for SSRF attacks aimed at accessing cloud metadata endpoints (e.g., `169.254.169.254`), container interfaces, or internal microservices.

TrustLens AI implements a defense-in-depth SSRF protection pipeline in `app/services/ssrf_guard.py`:

```
User URL -> Hostname Parsing -> DNS Resolution -> IP Range Validation -> Network Socket Dispatch
```

- **Blocked IP Networks:**
  - Loopback (`127.0.0.0/8`, `::1`)
  - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-Local Unicast (`169.254.0.0/16`, `fe80::/10`)
  - Documentation Networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
  - Multicast & Reserved (`224.0.0.0/4`, `240.0.0.0/4`, `ff00::/8`)
  - IPv6 Unique Local (`fc00::/7`) & IPv4-mapped IPv6 (`::ffff:0:0/96`)
- **DNS Pinning & Hop-by-Hop Re-validation:**
  - Before establishing any TLS socket or HTTP client session, DNS resolution maps the target to all candidate IPs. If any IP resolves to a restricted subnet, the connection is instantly rejected.
  - Redirect chains are executed hop-by-hop with `follow_redirects=False`. The destination header of each redirect is subjected to the exact same SSRF filter before following.

---

## 3. Scam Message Analysis & Prompt Injection Defense

The AI Scam Message Analyzer handles untrusted, potentially adversarial text from SMS, WhatsApp, and email lures.

### Adversarial Input Hardening
- **Passive Data Isolation:** User-submitted text is treated strictly as opaque linguistic data. System prompts encapsulate inputs inside rigid delimiter tags and explicit instructions instructing the AI to ignore any imperative commands embedded within the message.
- **Deterministic Baseline Fallback:** The analyzer does not rely exclusively on generative AI. An extensive deterministic regex-based rule engine (`app/services/message_analyzer.py`) identifies behavioral patterns independently:
  - Urgency and artificial deadlines.
  - Demands for One-Time Passwords (OTPs) or PINs.
  - Untraceable payment methods (crypto, gift cards, wire transfer).
  - Unsolicited lottery wins and prize notifications.
  - Unauthorized remote administration tool requests (AnyDesk, TeamViewer).
- **Zero Sensitive Data Ingestion:**
  - The system explicitly advises users never to submit real passwords, OTPs, or private keys.
  - Volatile sensitive tokens are masked before storage.

---

## 4. Tamper-Evident Digital Trust Ledger

To guarantee the historical integrity of collaborative threat reports, TrustLens AI implements an immutable SHA-256 hash-chained registry (`app/services/registry_service.py`):

1. **Canonicalization:** A standardized JSON string with sorted keys and normalized UTC timestamps is constructed from the report's immutable fields.
2. **Data Hash:** `data_hash = SHA256(canonical_payload)`
3. **Chaining:** `chained_hash = SHA256(block_index : previous_hash : data_hash : timestamp)`
4. **Verification:**
   - Any client or auditor can invoke `GET /api/registry/verify/{report_id}`.
   - The engine reconstructs the canonical payload from the current database state, computes its SHA-256 hash, and compares it to `stored_data_hash`.
   - It re-computes `chained_hash` and checks linkage to `previous_hash`.
   - If a malicious database administrator modifies even one byte of a report's description or severity, the computed data hash fails immediately and triggers `TAMPER_DETECTED`.

> [!NOTE]
> The cryptographic registry proves the *immutability and tamper-resistance* of the recorded report. It does not prove that an unverified reporter's initial claim was inherently accurate.
