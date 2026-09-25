# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 2026-09-25 - 2.0.0

### Added

- `GetSamplesByHash` — look up a list of SHA256/SHA1/MD5 hashes and return every matching sample, no quota spent.
- `SubmitUrlSample` — submit a URL and wait until every resulting submission finishes.
- `BuildReport` — build the full report for samples or submissions: analyses of the latest submission, VTIs, IOCs, MITRE ATT&CK, classifications, threat names and child samples.
- `RenderReport` — pure transform: a report to a markdown comment.
- `ReportToIndicators` — pure transform: a report to Sekoia's flat, typed indicator list, from malicious samples only by default.
- Submission options `max_recursive_samples` and `analysis_timeout`.
- Playbook `VMRay_Manual_Report` — manual trigger, hash and URL branches in parallel.

### Removed

- `SearchSample`, `SubmitUrl`, `SubmitFile`, `SubmitAndWait`, `GetAnalysisDetails`, `SubmitAndEnrich`, `RenderSummary` and `IocsToIndicators` — replaced by the actions above.
- `GetSample`, `GetReportPdf` and `GetScreenshots` — Sekoia cannot attach files to an alert or case.
- Playbooks `VMRay_Automatic_Enrichment`, `VMRay_Manual_Enrichment` and `VMRay_Manual_Detonation`.

### Fixed

- MITRE ATT&CK techniques and VTI classifications and scores are read from the field names the VMRay API actually returns.

## 2026-09-24 - 1.1.0

### Removed

- `GetQuota` action (and the client's `GET /api_key/quota` call) — not needed by any playbook.

### Added

- `GetScreenshots` — download an analysis run's screenshots as a ZIP (`GET /analysis/{id}/archive/screenshots`), written to `data_path` for a downstream handoff (e.g. TheHive's `upload_logs`), same pattern as `GetSample`/`GetReportPdf`.
- `GetAnalysisDetails` / `SubmitAndEnrich`: `include_analyses` toggle — fetches per-VM-profile analysis runs (`GET /analysis/sample/{id}`) into `sample_analyses`, each with its own verdict/severity/VTI score distinct from the sample-level aggregate. Default `false` — costs one extra call.
- `RenderSummary`: itemized IOC breakdown (domains, IPs, URLs, dropped files, filenames, mutexes, registry keys, emails, email addresses — capped at 10 per type) and a per-analysis-run verdict section, both previously visible only via the full VMRay report link.
- `GetAnalysisDetails` / `SubmitAndEnrich`: `ioc_severity_filter` — restricts fetched IOCs server-side to a single severity (VMRay's `ioc_severity` query param on `GET /sample/{id}/iocs`). Empty (default) fetches all severities.
- `SubmitUrl` / `SubmitFile` / `SubmitAndWait` / `SubmitAndEnrich`: submission-time VMRay options — `enable_reputation`, `enable_whois`, `analyzer_mode`, `known_malicious`, `known_benign`, `max_jobs`, `archive_action`, `archive_password`, `shareable`, `net_scheme_name` (sent inside `user_config`). Unset options are omitted so the VMRay user's analyzer settings apply; `shareable` is the exception — always sent, default `false`, so a sample's hash never reaches VirusTotal unless explicitly enabled.
- `GetAnalysisDetails` / `SubmitAndEnrich`: `analysis_verdict_filter` — keeps only `sample_analyses` runs (requires `include_analyses`) whose `analysis_verdict` matches one of the given values. Filtered client-side after fetch (VMRay's analysis-list endpoint has no server-side verdict filter). Empty (default) keeps every run.

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
