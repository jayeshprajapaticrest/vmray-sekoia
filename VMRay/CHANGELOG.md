# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-10-09 - 4.1.1

### Fixed

- `RenderReport` / `ExtractIocs` — failed in Sekoia with "resolve is unsupported on S3 service": the check keeping `report_path` inside the data path resolved the path, which S3 storage does not support. `report_path` is now checked as text (no absolute path, no `..`).

## 2026-10-09 - 4.1.0

### Added

- `SubmitUrlSample` — `failed_submission_ids` result: submissions VMRay finished with an error, or that could not be followed.
- End-to-end tests running every action as Sekoia does (`Action.execute()`) against a fake VMRay, chained as in the playbooks.

### Changed

- `RenderReport` — each section is written on one line of HTML, so no extra space appears between or inside sections.
- `RenderReport` — the empty-report message reads "No matches found for this sample."
- `GetSamplesByHash` — fails when VMRay could not answer for any hash (wrong API key, VMRay down) instead of taking `not_found`; a single hash and empty entries are accepted.
- `SubmitUrlSample` — a submission refused with an HTTP error, or finished with an error, takes `submission_failed`; one failed status check no longer ends the wait (a submission is given up after 3 in a row).
- `ExtractIocs` — values are normalised and checked before they reach an IOC collection: IPs with a port or CIDR range, URLs without a scheme and invalid hashes are dropped; domains and hashes are lowercased; an email address is taken from "Name <address>".
- `ExtractIocs` — an `ioc_severity_filter` with no valid value (e.g. a typo) is an error instead of extracting every IOC.
- Inputs are bounded: `max_recursive_samples` and `max_recursion_depth` 0–10, `max_comment_kb` at least 16, `query_retry_wait` above 0, `timeout` 0 or more.
- Client — every request has a timeout; a submission is no longer retried after a server error (it could be submitted and billed twice); `Retry-After` and backoff waits are capped; `analysis_caching` is no longer sent; a `base_url` ending in `/rest` works.

### Fixed

- `BuildReport` — odd VMRay data no longer fails the whole report: malformed screenshot summaries, very thin or huge images, null threat names or classifications, sections of an unexpected type, network or non-JSON errors on one sample, and children pointing back up the tree (which could cost thousands of requests).
- `BuildReport` — a submission VMRay returns no sample for is reported in `errors`.
- `RenderReport` / `ExtractIocs` — unexpected data shapes render or extract instead of failing.
- `RenderReport` — screenshot comments are measured as Sekoia receives them and never exceed the limit; a screenshot too large for any comment is replaced by a note.
- `RenderReport` / `ExtractIocs` — a missing, unreadable or malformed report file gives a clear error.

### Security

- `RenderReport` — a line break in a value from the sample (e.g. a dropped file's name) could end the comment's HTML and inject a link or remote image; line breaks and control characters are now removed from every value.
- `RenderReport` / `ExtractIocs` — `report_path` can only read files inside the playbook run's data directory.
- `RenderReport` — only `http(s)` VMRay URLs become links; warning lines are escaped as markdown; screenshot data must be valid base64.
- `GetSamplesByHash` — a value that is not a hex hash is refused before it reaches the request URL.

## 2026-10-09 - 4.0.1

### Fixed

- `RenderReport` / `ExtractIocs` — the report file was ignored when the playbook editor sent an empty inline `report`, so the comment said "No matches found" and no IOC was extracted. `report_path` now takes priority, and an empty `report` counts as not given.

## 2026-10-09 - 4.0.0

### Added

- `BuildReport` — `include_screenshots` argument: on (default) or off; screenshots of the submitted URL or looked-up hash only, never of their child samples.
- `ExtractIocs` — `ioc_severity_filter` (default `malicious`) and `include_child_iocs` (default `true`) arguments.

### Changed

- `ReportToIndicators` renamed `ExtractIocs` ("Extract IOCs"). Sekoia derives an action's UUID from its name, so playbook nodes using the old action must be replaced.
- `ExtractIocs` — each IOC is now judged on its own severity, no longer on the verdict of the sample it came from.
- `SubmitUrlSample` — argument descriptions, types and defaults follow the Cortex-Analyzers VMRay analyzer's configuration; `max_recursive_samples` defaults to 10 and is always sent.
- `BuildReport` — `ioc_severity_filter` is a list: exactly one of `malicious` / `suspicious` filters, none or both fetch everything; `analysis_verdict_filter` ignores values other than `malicious` / `suspicious` / `clean`; `max_recursion_depth` defaults to 10, as in the analyzer.
- `RenderReport` — tables are HTML: labels, types, verdicts and dates no longer wrap, long hashes and URLs wrap inside their own cell, and every cell is aligned to the top left.
- `RenderReport` — `max_comment_kb` defaults to 512.
- `RenderReport` — Overview no longer shows the VTI score.
- Every action — inputs show a clear title and description in the playbook editor; optional inputs no longer appear without a title.

### Removed

- `ReportToIndicators` — `verdicts` and `include_child_samples` arguments, replaced by `ioc_severity_filter` and `include_child_iocs` on `ExtractIocs`.
- `BuildReport` — `screenshot_mode` argument, replaced by `include_screenshots`; child samples' screenshots can no longer be included.
- `SubmitUrlSample` — `archive_action` and `archive_password` arguments: they only apply to submitted files.

## 2026-10-07 - 3.2.2

### Changed

- README — rewritten: how the actions fit together, each action's arguments and results, the alert comment layout, which IOC types reach an IOC collection, the playbooks, and the development and release steps.
- `RenderReport` — the Screenshots section's line uses a plain hyphen instead of an em dash.

### Removed

- Known limitation "No screenshots" from the README — screenshots have been embedded in the comment since 2.2.0.

## 2026-10-06 - 3.2.1

### Changed

- `RenderReport` — Detections back as a section of its own, after Overview.

### Fixed

- `RenderReport` — short table columns (labels, types, verdicts, dates) wrapping when a long value shared the table: multi-word labels and dates no longer break, and those columns keep a minimum width.

## 2026-10-06 - 3.2.0

### Changed

- `RenderReport` — headings on one size scale (comment title, sample, then bold section toggles) and in title case.
- `RenderReport` — Overview and Detections merged into one Property | Value table, styled like the other sections.
- `RenderReport` — a spacer line after every section.
- `RenderReport` — child samples shown as a collapsible tree like the VMRay TheHive report: one row per sample, children indented under their parent.
- `RenderReport` — MITRE ATT&CK technique IDs linked as plain text; an ID not shaped like a technique ID is never turned into a link.
- `RenderReport` — analysis dates shown as plain text, and an analysis's screenshot entries listed without gaps.

### Fixed

- `ReportToIndicators` — file IOC hashes were never extracted: they are now read from VMRay's `hashes` list (`sha256_hash`, else `sha1_hash`, else `md5_hash`), so dropped files reach the IOC collection.

## 2026-10-06 - 3.1.0

### Changed

- `RenderReport` — each section heading is its own toggle (open by default), replacing the separate Toggle button under it.
- `RenderReport` — screenshots listed one per line instead of in a table, each opening at the comment's full width.
- `BuildReport` — every screenshot is embedded; `RenderReport` spreads them over as many comments as needed.

### Removed

- `BuildReport` — `screenshot_budget_kb` argument and the sample's `screenshots_truncated` field.
- `RenderReport` — the "some screenshots have been excluded" notice.

## 2026-10-05 - 3.0.0

### Added

- `ReportToIndicators` — `indicator_groups` result: indicators grouped by type, one entry per non-empty type, so a Foreach pushes every type with one Add IOC to IOC Collection node.
- `SubmitUrlSample` — `submission_ids` result: IDs of the finished submissions.

### Changed

- `BuildReport` — takes `sample_ids` or `submission_ids` instead of sample and submission objects; each submission ID is resolved to its sample, and one that cannot be is recorded in `errors`.
- `RenderReport` — screenshots shown in list mode, like the VMRay TheHive report: a Name | Action table per analysis, each image behind a View toggle.

### Removed

- `BuildReport` — `samples` and `submissions` arguments, replaced by `sample_ids` and `submission_ids`.

## 2026-09-30 - 2.3.0

### Added

- `RenderReport` — `screenshot_comments` result: screenshots split into separate comments, each under `max_comment_kb`.

### Changed

- `RenderReport` — the main comment lists how many screenshots there are instead of embedding them.

### Fixed

- Comment Alert node failing with "Arguments given to the action are too big" (SYM216) when the comment held many screenshots.

## 2026-09-30 - 2.2.1

### Changed

- `BuildReport` — writes the report to a file and returns `report_path` instead of the report itself.

### Fixed

- Playbook nodes after `BuildReport` failing with "Arguments given to the action are too big" (SYM216) when the report included screenshots.

## 2026-09-30 - 2.2.0

### Added

- `BuildReport` — analysis screenshots, embedded in the report as compressed JPEG.
- `BuildReport` — `screenshot_mode` and `screenshot_budget_kb` arguments.
- `RenderReport` — screenshots section, with a notice when some were left out.

### Changed

- `RenderReport` — comment styled like the VMRay TheHive report: coloured badges, collapsible sections and MITRE ATT&CK links.

### Security

- `RenderReport` — values from the analysed sample are escaped, so it cannot inject links or images into the comment.

## 2026-09-28 - 2.1.1

### Changed

- `RenderReport` — child samples are listed in a table only; their detail sections are no longer rendered in the comment.

## 2026-09-28 - 2.1.0

### Changed

- `RenderReport` — comment laid out like the VMRay TheHive report: overview, detections, IOC summary, threat identifiers, MITRE ATT&CK, IOCs, analyses and child samples, as markdown tables.

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
