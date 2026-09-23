# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 2026-09-17 - 1.0.0

### Added

- Initial release of the VMRay module.
- Module configuration: `base_url`, `api_key` (secret), `verify_ssl` (for on-prem appliances with a self-signed certificate).
- `SearchSample` — look up a sample by SHA256/SHA1/MD5, no quota spent.
- `SubmitUrl` / `SubmitFile` — submit a URL or file for detonation without waiting.
- `SubmitAndWait` — submit and block until the analysis finishes, returning identifiers and verdict only.
- `GetAnalysisDetails` — fetch VTIs, IOCs and MITRE ATT&CK for a sample, concurrently, with per-section partial-failure reporting.
- `SubmitAndEnrich` — `SubmitAndWait` + `GetAnalysisDetails` composed in one node.
- `GetSample` — download a sample as an encrypted ZIP.
- `GetReportPdf` — download the VMRay PDF report.
- `GetQuota` — check the API key's quota limit and usage.
- `RenderSummary` — pure transform: an `AnalysisDetails` object to a markdown comment.
- `IocsToIndicators` — pure transform: VMRay's IOC set to Sekoia's flat, typed indicator list.
