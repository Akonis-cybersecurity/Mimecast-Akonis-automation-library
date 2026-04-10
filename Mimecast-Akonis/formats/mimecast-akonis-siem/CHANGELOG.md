# Changelog

All notable changes to this intake will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-10

### Added
- Initial release of the Mimecast SIEM intake.
- Parser for SIEM Stream events (url protect, av, attachment protect, impersonation protect, receipt, delivery, process, spam, journal).
- Parser for TTP URL Protection click logs.
- Parser for TTP Attachment scan results.
- Parser for TTP Impersonation Protection detections.
- Parser for DLP policy violation logs.
- Parser for Admin Audit Events.
- Parser for Email Rejection logs.
- Parser for Threat Events (API 2.0).
- ECS field mapping for all event types.
- Smart descriptions for all major event patterns.

[1.0.0]: https://github.com/Akonis-cybersecurity/Mimecast-Akonis-automation-library/releases/tag/intake-v1.0.0
