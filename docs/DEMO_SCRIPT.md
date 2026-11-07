# TrustLens AI — 3-Minute Live Demonstration Script

> **Theme:** Real Cyber Engineering Over Mockups.  
> **Target Audience:** Hackathon Judges, Security Researchers, and Tech Leads.

---

### **[0:00 – 0:15] The Problem**
- **Speaker:**  
  "Every day, millions of users fall victim to online scams because of a dangerous myth: *'The lock icon means it's safe.'* Over 80% of active phishing websites now run on valid HTTPS certificates. At the same time, newly minted scam domains stay unlisted by major blocklists for days.  
  Meet **TrustLens AI** — an AI-powered web threat detection and digital trust platform built on four core pillars: *Investigate. Understand. Verify. Protect.*"

---

### **[0:15 – 0:55] Live URL Investigation**
- **Action:**  
  Navigate to the **Investigate URL** tab.  
  Paste: `https://paypal-security-update.example.com/login?token=urgent` and click **Investigate**.
- **Speaker:**  
  "Let's investigate this link. In under 2 seconds, TrustLens runs a multi-stage passive pipeline:
  1. **URL Normalization & Deception Detection:** It identifies that 'paypal' appears in the hostname, but the registered base domain is `example.com` — a clear typosquatting impersonation attack. It also flags clustered authentication keywords.
  2. **DNS & WHOIS Intelligence:** It resolves A-records and authoritative nameservers without leaking internal queries.
  3. **SSRF-Protected Redirect Tracing:** Each hop is checked against private IP blocklists before following, strictly without executing untrusted JavaScript.
  4. **The Verdict:** The explainable risk engine flags it as **HIGH RISK (Score: 85/100)** with line-by-line evidence."

---

### **[0:55 – 1:20] TLS & Passive Security Assessment**
- **Action:**  
  Switch to the **TLS & Digital Trust** and **Security Assessment** tabs for this investigation.
- **Speaker:**  
  "Notice the TLS inspector. The site has an encrypted connection, but TrustLens highlights the critical distinction: **HTTPS confirms encryption, not business legitimacy.** It also reveals a hostname mismatch.  
  Under passive security assessment, we see missing HSTS and lack of Content-Security-Policy headers — all evaluated without intrusive or aggressive exploits."

---

### **[1:45 – 2:20] Collaborative Threat Intelligence & Correlation**
- **Action:**  
  Open **Threat Intelligence** and submit a report for `https://secure-chase-online.example.org/verify`.  
  Then switch to the **Threat Correlation** network view.
- **Speaker:**  
  "When researchers uncover a threat, they submit collaborative reports. Unlike naive databases, TrustLens analyzes shared infrastructure: co-hosted IPs, shared nameservers, and brand-targeting patterns. Our graph visualizes relationships backed by deterministic DNS evidence, not AI hallucinations."

---

### **[2:20 – 2:45] Tamper-Evident Digital Trust Ledger**
- **Action:**  
  Navigate to the **Trust Registry** tab.  
  Click **Verify Fingerprint** on Report Block #0. Observe `status: VERIFIED_AUTHENTIC`.  
  Point to the hash chaining breakdown.
- **Speaker:**  
  "How do we prove collaborative reports haven't been retroactively tampered with?  
  TrustLens features an append-only, SHA-256 cryptographic hash-chained registry. Each block records a canonical representation, data hash, and previous block link. When verified, the ledger confirms mathematical integrity. We also provide a Solidity smart contract demonstrator in `contracts/TrustLensRegistry.sol` for EVM testnets."

---

### **[2:45 – 3:00] Conclusion**
- **Speaker:**  
  "TrustLens AI requires no paid API keys to run out-of-the-box. It brings transparency to link security, combines passive heuristics with explainable AI, and provides mathematical integrity for threat intelligence.  
  Thank you — Investigate, Understand, Verify, and Protect with TrustLens AI."
