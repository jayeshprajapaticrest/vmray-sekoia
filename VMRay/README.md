# VMRay

VMRay Platform — agentless hypervisor-based sandbox for malware detonation, VTI scoring and IOC extraction.

## Configuration

| Field | Required | Notes |
|---|---|---|
| `base_url` | yes | e.g. `https://eu.cloud.vmray.com`, or an on-prem appliance URL |
| `api_key` | yes | stored as a secret |
| `verify_ssl` | no (default `true`) | set `false` only for an on-prem appliance with a self-signed certificate |

Requires VMRay Platform **2026.2 or later** (recursive threat-name/classification data is silently absent on older versions). `SubmitUrlSample` is not available on the DeepResponse product plan — VMRay's own API rejects submission there regardless of this module.

## Actions

The report flow mirrors the Cortex-Analyzers VMRay analyzer: find or create samples, build the full report, then render it and extract indicators.

| Action | Purpose |
|---|---|
| `GetSamplesByHash` | Look up SHA256/SHA1/MD5 hashes (a list; duplicates ignored) in VMRay's existing analyses and return every matching sample. Zero quota. `found` / `not_found` outputs. |
| `SubmitUrlSample` | Submit a URL and wait until every resulting submission finishes (`timeout`, default 30 min). Accepts VMRay's submission options (`analyzer_mode`, `max_jobs`, `net_scheme_name`, `analysis_timeout`, …); unset ones fall back to the VMRay user's analyzer settings, and `shareable` (hash → VirusTotal) is always sent, default `false`. `completed` / `timed_out` / `submission_failed` outputs. |
| `BuildReport` | The heavy lifting. Takes `samples` (from `GetSamplesByHash`) or `submissions` (from `SubmitUrlSample`) and, per sample, fetches analyses of the latest submission, VTIs, MITRE ATT&CK, IOCs, classifications and threat names — then the same for child samples down to `max_recursion_depth` (default 1). A failing section lands in that sample's `errors`; the rest is still filled. |
| `RenderReport` | Pure transform — a report into one markdown alert comment: every sample, its VTIs (strongest first, with scores), IOCs, MITRE ATT&CK, analyses and a line per child sample. |
| `ReportToIndicators` | Pure transform — a report into Sekoia's flat, typed indicator list for `add_ioc_to_ioc_collection`. Only `malicious` samples contribute by default, each child judged on its own verdict; child samples also add their own SHA256. |

## Known limitations

**No screenshots, no file downloads.** Sekoia has no alert/case attachment API (confirmed against its SIC OpenAPI spec), so screenshots and sample files could never be shown on the alert. The module deliberately fetches neither; the `[Full VMRay report]` link in the comment is where an analyst sees them.

**URL and hash only — no file submission.** Sekoia alerts don't carry sample bytes, so there is no file-submission action. A hash is looked up; a URL is detonated.

**No indicator-revocation action.** If a `reanalyze` flips a sample's verdict away from `malicious` after its IOCs were already pushed to a Sekoia IOC collection, this module has no way to retract them — `DELETE /v2/inthreat/ioc-collections/{uuid}/indicators/{id}` is a **Sekoia** endpoint, and this module only holds VMRay credentials. That action belongs in the `Sekoia.io` module.

**No STIX bundle output.** Scoped in, then dropped: VMRay's own `iocs/stix` endpoint only emits STIX 2.0, and Sekoia Intelligence's accepted bundle version was never confirmed against a real submission. Child-sample lineage and MITRE ATT&CK render as prose in `RenderReport`'s comment and nowhere else — not queryable, not structured.

**Verdict is data, not a decision.** `sample_verdict` comes back in every report, but nothing in this module writes it to Sekoia's `verdict_uuid`/`custom_status` fields — that's `Sekoia.io`'s `PatchAlert` action, driven by a playbook Condition node. Deliberate: auto-closing an alert on a `clean` verdict can bury a true positive the sandbox simply didn't trigger.

## Playbooks

`playbooks/VMRay_Manual_Report.json` (Manual Trigger). It gets the alert and its events, extracts hashes and URLs, and runs a hash branch (`GetSamplesByHash` → `BuildReport` → `RenderReport` → comment → `ReportToIndicators` → IOC collection) and a URL branch (`SubmitUrlSample` → the same chain) in parallel. When an alert has both a hash and a URL, both branches run and each posts its own comment. Replace `ioc_collection_id` on both "Add hashes to IOC Collection" nodes before use.

## Development

```
uv sync
mise run lint   # ruff check, ruff format --check, mypy
mise run test   # pytest — fast suite only, well under 1s
```

Three tests are marked `slow` (`pytest -m slow`, ~35s) — they exercise the retry adapter over a real local socket, not `requests_mock`. That's deliberate, not an oversight: `requests_mock` patches the transport at a level that bypasses any `HTTPAdapter` mounted on the session, so it cannot verify retry or `Retry-After` behaviour at all. Run the slow suite before any change to `client.py`'s retry configuration.
