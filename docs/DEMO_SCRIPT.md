# TrustLens AI — Three-Minute Demo Plan

Use the reserved `.example` synthetic fixture and a synthetic message. Do not enter a real URL with private query values; live enabled providers may receive submitted URLs. The UI shows synthetic results as fixtures, not as live observations.

## Timed walkthrough and narration

**0:00–0:20 — Problem and solution**
“Phishing uses deceptive domains and incomplete threat feeds. HTTPS alone does not prove a site is safe. TrustLens combines bounded passive checks and explainable rules, while showing the evidence and limitations.”

**0:20–1:10 — URL investigation**
Open **Investigate URL** and submit `https://paypal-security-update.example.com/login`. Point out the synthetic-fixture label, URL-pattern findings, risk rationale, and provider availability. Explain that this reserved-domain result is synthetic and that the score is not a definitive verdict.

**1:10–1:40 — Scam-message analyzer**
Open **Message Analyzer** and submit a synthetic message containing an urgent request and a reserved example URL. Show the indicators and precautions. State that analysis uses deterministic rules, not a trained ML model or LLM, and that stored content is redacted.

**1:40–2:10 — Trust and infrastructure**
Show **TLS Trust**, **Security Assessment**, and **Threat Correlation**. Explain that TLS-only and header-only checks do not create an investigation record. Clarify that graph edges represent observed report/domain, shared-IP, or shared-nameserver relationships—not proof of a shared operator.

**2:10–2:35 — Registry**
Verify a seeded report in **Trust Registry**. Explain that the local SHA-256 chain detects record or chain inconsistencies but is not externally anchored and cannot prevent a full database rewrite.

**2:35–3:00 — Limitations and close**
“Threat feeds can be incomplete, provider checks may share submitted URLs, and heuristic results are not confirmed proof. TrustLens is a transparent triage demonstrator; a trained and independently evaluated ML model is not implemented.”

## Strongest features to show

- SSRF-aware URL and redirect inspection with bounded requests.
- Explainable, deterministic URL and message findings.
- Clear distinction between synthetic fixtures, local heuristics, and external provider results.
- Non-persisting TLS and passive-header actions.
- Local report-chain verification with explicit integrity limitations.

## Genuine screenshots to capture

1. Dashboard with seeded data and visible labels.
2. Synthetic URL investigation with the fixture disclosure visible.
3. Message analyzer results with no real personal message.
4. Threat-correlation graph with its relationship limitations visible.
5. Registry verification result.
6. Mobile navigation showing all available sections.

Capture these from the running application; do not mock, edit, or imply they are production/deployment screenshots.

## Final judging checklist

- Replace no result with a stronger claim than the evidence supports.
- Say “deterministic rules/heuristics,” not “trained AI/ML.”
- Identify synthetic examples as synthetic.
- Mention provider sharing and avoid sensitive URLs.
- Explain the local-only nature of the registry.
- Keep the recording within three minutes; do not imply public deployment unless the live URLs have been verified.

No recording has been made or uploaded. Add a video URL to the README only after the actual recording exists.
