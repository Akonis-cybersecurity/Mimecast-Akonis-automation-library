# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-10

### Added
- Initial release of the Mimecast SIEM connector for SEKOIA.IO.
- **API 2.0 (OAuth2)** support: automatic token acquisition and renewal (5 min before expiry).
- **API 1.0 (HMAC-SHA1)** support: per-request signature with `x-mc-date`, `x-mc-req-id`, `x-mc-app-id` headers.
- **Dual auth mode**: routes to API 2.0 or API 1.0 automatically based on endpoint.
- **15 independent fetchers**, each with its own persistent cursor/checkpoint:
  - `siem_stream` — SIEM Stream API 2.0, real-time email security events with `isCaughtUp` support.
  - `siem_logs` — SIEM MTA/receipt/process/jrnl/delivery compressed logs (API 1.0).
  - `ttp_url_logs` — TTP URL Protection click logs.
  - `ttp_attachment_logs` — TTP Attachment scan results.
  - `ttp_impersonation_logs` — TTP Impersonation Protection detections.
  - `dlp_logs` — DLP policy violation logs.
  - `audit_events` — Admin Audit Events.
  - `rejection_logs` — Email Rejection logs.
  - `message_release_logs` — Quarantine Release logs.
  - `threat_events` — Threat Events API 2.0.
  - `threat_intel_feed` — IOC feeds (`malware_customer` + `malware_grid`).
  - `threat_incidents` — Threat Remediation Incidents.
  - `awareness_training` — SAFE scores, phishing campaigns, watchlists (daily, opt-in).
  - `web_security_logs` — DNS and Proxy ESS logs (opt-in, requires licence).
  - `archive_logs` — Archive search and message view logs (opt-in, requires licence).
- Per-source **feature flags** (`enable_*`) to toggle individual fetchers independently.
- **Retry with exponential backoff** on HTTP 429: 60 s → 120 s → 240 s (max 3 retries).
- **Prometheus metrics** per source: collected events, forwarded events, duration, and lag.
- **Gzip decompression** for binary SIEM log responses.
