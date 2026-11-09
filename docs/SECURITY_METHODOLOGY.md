# TrustLens AI — Security Methodology & Limitations

## What the application does

- Normalizes submitted HTTP(S) URLs and applies deterministic URL heuristics.
- Looks up DNS and WHOIS metadata and performs bounded HTTP/TLS checks.
- Follows redirects one hop at a time, checking each destination.
- Analyzes messages locally with deterministic rules.
- Stores community reports in a local SHA-256 hash chain.

These are indicators for investigation, not a guarantee of safety or maliciousness. A valid TLS certificate does not establish that a site or organization is trustworthy.

## Outbound request policy

Before a target HTTP or TLS connection, the backend resolves the hostname and rejects the target if resolution fails, returns no addresses, or includes any non-globally-routable address. Target HTTP requests use a standard-library connection pinned to one of the validated IPs while retaining the original hostname for the HTTP `Host` header and TLS SNI/certificate verification. Redirects are handled manually and each hop is independently resolved, validated, and pinned.

Target HTTP requests have a configured timeout and response-body limit. TLS validation uses the system trust store. The scanner makes ordinary GET/HEAD requests; it does not execute JavaScript, perform port scans, submit credentials, or send exploit payloads. DNS and WHOIS lookups are separate metadata queries.

The API binds to loopback by default. When `APP_ACCESS_TOKEN` is set, all `/api/*` data endpoints other than health require a bearer token; production startup rejects a missing or shorter-than-32-character token. This shared token is a coarse gate, not per-user identity or record-level authorization, and every token holder can access the same stored data. General API rate limiting is not built in. Do not expose the service publicly without HTTPS, deployment-level abuse controls, and a database configured for persistent storage and backups.

## Threat intelligence

- URLhaus is queried only when `URLHAUS_API_ENABLED` is true.
- VirusTotal is queried only when `VIRUSTOTAL_API_KEY` is configured.
- PhishTank and OpenPhish have no live lookup implementation and are reported unavailable.
- A provider's no-record result is not a clean verdict. Unavailable providers are not treated as evidence of safety.
- RFC 2606 `example.com`, `example.org`, and `example.net` targets use synthetic demo data. Simulated matches are marked as such and cannot produce a `CONFIRMED MALICIOUS` classification.

Investigation URLs are stored in the local database. When a live provider is enabled, the submitted URL is also sent to that provider. Do not scan URLs containing passwords, session IDs, or other sensitive query parameters.

## Message analysis and retention

Scam-message analysis uses local deterministic rules; no message is sent to a generative AI service. The submitted message text is not stored. Stored records contain risk/indicator metadata, use a fixed withheld-content preview, and redact indicator excerpts. The immediate analysis response can include short evidence excerpts from the submitted text.

## Local report registry

The registry canonicalizes report data, hashes it with SHA-256, and links entries using the prior hash. Verification checks the report payload and the full stored chain. This provides tamper evidence for ordinary record changes, but does not prevent an administrator who can rewrite the database from replacing the chain. It is not a public blockchain, an external timestamp authority, or proof that a submitted report is true. The Solidity file is a standalone demonstrator and is not deployed or called by the application.

## Synthetic data and verification

Seeded examples use reserved example domains and are labeled synthetic. They are illustrative fixtures, not verified observations of real services. Current test and build results are recorded in [TESTING_REPORT.md](./TESTING_REPORT.md); results may change as code changes.
