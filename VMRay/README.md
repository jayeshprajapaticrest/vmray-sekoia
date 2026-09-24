# VMRay

VMRay Platform — agentless hypervisor-based sandbox for malware detonation, VTI scoring and IOC extraction.

## Configuration

| Field | Required | Notes |
|---|---|---|
| `base_url` | yes | e.g. `https://eu.cloud.vmray.com`, or an on-prem appliance URL |
| `api_key` | yes | stored as a secret |
| `verify_ssl` | no (default `true`) | set `false` only for an on-prem appliance with a self-signed certificate |

Requires VMRay Platform **2026.2 or later** (recursive threat-name/classification data is silently absent on older versions). Submission actions (`SubmitUrl`, `SubmitFile`, `SubmitAndWait`, `SubmitAndEnrich`) are not available on the DeepResponse product plan — VMRay's own API rejects submission there regardless of this module.

## Actions

| Action | Purpose |
|---|---|
| `SearchSample` | Look up a sample by hash. Zero quota, sub-second — run this before submitting anything. |
| `SubmitUrl` / `SubmitFile` | Submit for detonation, fire-and-forget. All submitting actions accept VMRay's submission options (`analyzer_mode`, `max_jobs`, `archive_action`, `net_scheme_name`, …); unset ones fall back to the VMRay user's analyzer settings. `shareable` (hash → VirusTotal) is always sent and defaults to `false`. |
| `SubmitAndWait` | Submit and block until finished. Returns identifiers and verdict only. |
| `GetAnalysisDetails` | VTIs, IOCs and MITRE ATT&CK for an existing sample, fetched concurrently. `ioc_severity_filter` narrows IOCs server-side; `analysis_verdict_filter` narrows `sample_analyses` (with `include_analyses`) client-side. |
| `SubmitAndEnrich` | `SubmitAndWait` + `GetAnalysisDetails` in one node — what most playbooks should use. |
| `GetSample` | Download the sample as an encrypted ZIP (default password `infected` unless overridden). |
| `GetReportPdf` | Download the VMRay PDF report. |
| `GetScreenshots` | Download an analysis run's screenshots as a ZIP. |
| `RenderSummary` | Pure transform — an analysis into one markdown comment, with an itemized IOC breakdown and per-analysis-run verdicts. |
| `IocsToIndicators` | Pure transform — VMRay's IOC set into Sekoia's flat, typed indicator list. |

## Known limitations

**No file attachment on a Sekoia alert or case.** Confirmed against Sekoia's own SIC OpenAPI spec — no such endpoint exists anywhere in it. `GetSample`'s ZIP, `GetReportPdf`'s PDF and `GetScreenshots`'s ZIP can only be surfaced as a deep link in a comment, or handed to a downstream node (TheHive, email, object storage). This is a platform gap, not something this module can work around.

**`GetScreenshots` takes `analysis_id`, not `sample_id`.** A sample can carry several analysis runs (different VM profiles); each has its own screenshots. `sample_analyses[].analysis_id` (from `GetAnalysisDetails` with `include_analyses: true`) is the source for this argument.

**`SubmitFile` needs an upstream node to supply the file.** Sekoia alerts do not carry sample bytes by default — this action reads from the playbook's shared storage, so something earlier in the playbook must have fetched and written the file there first.

**No indicator-revocation action.** If a `reanalyze` flips a sample's verdict away from `malicious` after its IOCs were already pushed to a Sekoia IOC collection, this module has no way to retract them — `DELETE /v2/inthreat/ioc-collections/{uuid}/indicators/{id}` is a **Sekoia** endpoint, and this module only holds VMRay credentials. That action belongs in the `Sekoia.io` module.

**No STIX bundle output.** Scoped in, then dropped: VMRay's own `iocs/stix` endpoint only emits STIX 2.0, and Sekoia Intelligence's accepted bundle version was never confirmed against a real submission. Child-sample lineage, sample relations and MITRE ATT&CK render as prose in `RenderSummary`'s output and nowhere else — not queryable, not structured.

**Verdict is data, not a decision.** `sample_verdict` comes back on every enrichment action, but nothing in this module writes it to Sekoia's `verdict_uuid`/`custom_status` fields — that's `Sekoia.io`'s `PatchAlert` action, driven by a playbook Condition node. Deliberate: auto-closing an alert on a `clean` verdict can bury a true positive the sandbox simply didn't trigger.

## Development

```
uv sync
mise run lint   # ruff check, ruff format --check, mypy
mise run test   # pytest — fast suite only, ~50 tests, well under 1s
```

Three tests are marked `slow` (`pytest -m slow`, ~35s) — they exercise the retry adapter over a real local socket, not `requests_mock`. That's deliberate, not an oversight: `requests_mock` patches the transport at a level that bypasses any `HTTPAdapter` mounted on the session, so it cannot verify retry or `Retry-After` behaviour at all. Run the slow suite before any change to `client.py`'s retry configuration.
