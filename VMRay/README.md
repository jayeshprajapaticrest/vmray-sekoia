# VMRay

VMRay Platform — agentless hypervisor-based sandbox for malware detonation, VTI scoring and IOC extraction.

This module lets a Sekoia.io playbook look up file hashes in VMRay or detonate URLs, build the full VMRay report, post it on the alert as a comment (with screenshots), and push the indicators it found to a Sekoia IOC collection. The report flow mirrors the Cortex-Analyzers VMRay analyzer and its TheHive template (`VMRay_4_1/long.html`).

## Configuration

| Field | Required | Notes |
|---|---|---|
| `base_url` | yes | e.g. `https://eu.cloud.vmray.com`, or an on-prem appliance URL |
| `api_key` | yes | stored as a secret |
| `verify_ssl` | no (default `true`) | set `false` only for an on-prem appliance with a self-signed certificate |

Requires VMRay Platform **2026.2 or later** (recursive threat-name/classification data is silently absent on older versions). `SubmitUrlSample` is not available on the DeepResponse product plan — VMRay's own API rejects submission there regardless of this module.

## How it works

```
hashes ──► GetSamplesByHash ──► sample_ids ─────┐
                                                ├─► BuildReport ──► report_path ─┬─► RenderReport ──► comment + screenshot comments
URL ─────► SubmitUrlSample ───► submission_ids ─┘   (file on data_path)          └─► ExtractIocs ──────► IOC collection
```

1. **Find or create samples.** `GetSamplesByHash` looks hashes up in VMRay's existing analyses (no quota). `SubmitUrlSample` detonates a URL and waits for the result (consumes quota).
2. **Build the report.** `BuildReport` fetches everything VMRay knows about each sample and writes the report to a JSON file on the playbook's data path. Only the file's path travels between nodes: a report with screenshots is far larger than Sekoia accepts as an action argument (SYM216).
3. **Use the report.** `RenderReport` turns it into the alert comment; `ExtractIocs` turns it into indicators for an IOC collection. Neither calls VMRay or Sekoia.

## Actions

### `GetSamplesByHash` — Get samples by hash

Looks up SHA256, SHA1 or MD5 hashes in VMRay's existing analyses and returns every matching sample. Costs no quota.

| Argument | Default | Notes |
|---|---|---|
| `hashes` (File hashes) | required | list of SHA256, SHA1 or MD5 hashes to look up; duplicates ignored, no quota used |

**Outputs:** `found` (at least one sample) / `not_found` (none). **Results:** `sample_ids`, `samples`, `not_found` (hashes VMRay has never analysed), `errors` (per hash: invalid value or lookup failure).

### `SubmitUrlSample` — Submit URL sample

Submits a URL and polls every resulting submission until it finishes.

| Argument | Default | Notes |
|---|---|---|
| `sample_url` | required | the URL to detonate |
| `reanalyze` | `true` | re-analyze known samples on submission |
| `tags` | `["sekoia"]` | tags to attach to the sample |
| `shareable` | `false` | share the sample's hash with VirusTotal |
| `max_recursive_samples` | `10` | maximum amount of recursive samples analyzed; `0` disables recursion |
| `query_retry_wait` | `10` | seconds to wait before trying to fetch the results |
| `timeout` | `1800` | seconds to wait for every submission to finish, then the `timed_out` branch |
| `analyzer_mode`, `max_jobs`, `enable_reputation`, `enable_whois`, `known_malicious`, `known_benign`, `analysis_timeout`, `net_scheme_name` | empty | VMRay submission options; empty ones are not sent, so the VMRay user's analyzer settings apply |

Names, descriptions, types and defaults follow the Cortex-Analyzers VMRay analyzer's configuration (`VMRay.json`), without its archive settings (`archive_password`, `archive_compound_sample`) — they only apply to submitted files, and this module submits URLs only. Where the names differ: its `recursive_sample_limit` is `max_recursive_samples` here and its `timeout` (analysis timeout) is `analysis_timeout`, since `timeout` here is how long the action waits.

**Outputs:** `completed` / `timed_out` / `submission_failed`. **Results:** `submission_ids`, `sample_ids`, `submissions`, `pending_submission_ids` (still running at the timeout), `errors` (VMRay's reasons for a rejected submission).

### `BuildReport` — Build report

The heavy lifting. Takes `sample_ids` (from `GetSamplesByHash`) or `submission_ids` (from `SubmitUrlSample`, each resolved to its sample); `sample_ids` wins when both are given. Per sample it fetches, concurrently: the analyses of the latest submission, VTIs, MITRE ATT&CK techniques, IOCs, classifications and threat names — then the screenshots of each analysis, then the same for child samples.

| Argument | Default | Notes |
|---|---|---|
| `sample_ids` / `submission_ids` | one required | |
| `max_recursion_depth` | `10` | maximum depth of child samples analyzed in the report; `0` disables recursion |
| `include_screenshots` | `true` | include the screenshots of the submitted URL or looked-up hash — the top-level samples only, never their child samples |
| `ioc_severity_filter` | empty | list of `malicious` / `suspicious`: exactly one filters server-side; empty or both fetch both severities |
| `analysis_verdict_filter` | empty | list of `malicious` / `suspicious` / `clean` to include; empty includes all analyses, even those with an unknown verdict (adding all three does not) |

These follow the Cortex-Analyzers VMRay analyzer's configuration (`VMRay.json`), except `include_screenshots`: there it is `none` / `parent_only` / `all`, here it is on or off and covers the top-level samples only — child samples' screenshots would multiply the comments for little value. Its `recursive_sample_limit` — which the analyzer uses both for the submission and as the report's depth — is `max_recursion_depth` here (and `max_recursive_samples` on `SubmitUrlSample`). Values outside the allowed ones are ignored, as in the analyzer.

Screenshots are read from each analysis archive (`logs/summary.json`), scaled to at most 800 px wide and re-encoded as JPEG, then embedded as base64 — Sekoia has no attachment API, so this is the only way they reach the alert. Every screenshot is kept.

A failing section lands in that sample's `errors` and every other section is still filled; a sample or submission that cannot be fetched at all lands in the report's `errors`.

**Results:** `report_path` (give it to `RenderReport` and `ExtractIocs`), `sample_ids`, `errors`.

### `RenderReport` — Render report

Turns a report into the alert comment, laid out like the VMRay TheHive report.

| Argument | Default | Notes |
|---|---|---|
| `report_path` (or `report`) | required | Build report's `report_path` |
| `max_comment_kb` | `512` | maximum size of each screenshot comment |

**Results:**

- `content` — the main comment, for Comment Alert. Per sample, each section is a collapsible block, open by default, whose heading is the toggle:

  | Section | Contents |
  |---|---|
  | Overview | verdict, reason, URL or filename, type, created, MD5/SHA1/SHA256, link to the VMRay report |
  | Detections | threat names and classifications |
  | IOC Summary | count per IOC type |
  | VMRay Threat Identifiers | VTIs, strongest first, with a coloured 1–5 score |
  | MITRE ATT&CK | technique links, plus a collapsed Details table (technique, tactics) |
  | Indicators of Compromise | every IOC with its type and verdict |
  | Analyses | each VM run, newest first, with its verdict |
  | Screenshots | how many screenshots were posted in the screenshot comments |
  | Child Samples | a collapsible tree: one row per child sample (verdict, name, type, children, link), children indented under their parent |

  Tables are capped at 20 rows ("…and N more"); the VMRay report link has the rest. When several samples are reported, each starts with "Sample i of N". A section that failed to load is named in a "Partial data" note.

- `screenshot_comments` — the screenshots, grouped per analysis, each behind its own toggle that opens the image at the comment's full width. Split into as many comments as needed, each at most `max_comment_kb` and titled "VMRay Screenshots (i/N)"; post them with a Foreach. Sekoia rejects a playbook action argument above an undocumented size (SYM216), and Comment Alert only takes inline text, so one comment cannot hold them all.

Every value that comes from the analysed sample (filenames, URLs, IOC values, rule text) is escaped, so a crafted sample cannot inject links, remote images or markup into the comment.

### `ExtractIocs` — Extract IOCs

Extracts a report's IOCs as indicators for Sekoia's "Add IOC to IOC Collection" action.

| Argument | Default | Notes |
|---|---|---|
| `report_path` (or `report`) | required | Build report's `report_path` |
| `ioc_severity_filter` | `["malicious"]` | IOC severities to extract: `malicious`, `suspicious`. Each IOC is judged on its own severity; a child sample's own SHA256 on its verdict. Empty = every IOC; other values are ignored |
| `include_child_iocs` | `true` | also extract the child samples' IOCs and each child sample's own SHA256; `false` = root sample only |

**Results:** `indicators` (`[{value, type}]`, deduplicated) and `indicator_groups` — the same values grouped by type, one entry per non-empty type (`[{type, indicators}]`). "Add IOC to IOC Collection" takes one `indicator_type` per call, so a Foreach over `indicator_groups` pushes every type with one node.

| VMRay IOC | Pushed as |
|---|---|
| IPs | `IP address` |
| domains | `domain` |
| URLs | `url` |
| emails, email addresses | `email` |
| files | `hash` — the strongest of `sha256_hash`, `sha1_hash`, `md5_hash` per file |
| processes, mutexes, registry keys, filenames | not pushed — Sekoia's IOC collection has no matching type. They still appear in the comment |

## Playbooks

### `playbooks/VMRay_Manual_Report.json` — VMRay: Report on demand

Manual Trigger, run by an analyst on one alert.

1. Gets the alert and up to 100 of its events.
2. From the **first event**, extracts the file hashes (`file.hash.*` and `process.hash.*`: sha256, sha1, md5) and the http(s) `url.original`.
3. Runs two branches in parallel:
   - **Hash branch:** `GetSamplesByHash` → `BuildReport` → `RenderReport` → Comment Alert, then the screenshot comments and the IOC push. When VMRay knows none of the hashes, a comment lists them instead (no quota spent).
   - **URL branch:** `SubmitUrlSample` → the same chain. When the detonation times out or is rejected, a comment says so and lists any submissions still running.
4. When the event has neither a hash nor a URL, a comment says which fields were checked.

Each Foreach (screenshot comments, IOC types) sits behind a condition that skips it when its list is empty — Sekoia rejects a Foreach over an empty list ("Foreach input is not a list").

**Before use:** replace `ioc_collection_id` on both "Add IOCs to IOC Collection" nodes.

### `playbooks/VMRay_Report_Per_Event.json` — experimental

Loops over the alert's events and runs the same workflow per event. **Not usable yet:** Sekoia does not resolve a node inside a Foreach loop from a Foreach nested in it, so the screenshot comments and the IOC push inside the event loop fail or are skipped. See the limitation below.

## Known limitations

**Comments are styled with HTML Sekoia allows, not CSS.** Sekoia renders comments as GitHub-flavoured markdown and strips `style` attributes and `<style>` blocks. Colours use `<font color>`, collapsible sections use `<details>`, and short table columns keep their width through an invisible spacer image in the header.

**Screenshots are embedded, not attached.** Sekoia has no alert or case attachment API, so screenshots are compressed and embedded as base64 images in their own comments. A sample with many screenshots posts many comments.

**No nested loops inside a loop.** A Foreach inside another Foreach cannot iterate a list produced inside the outer loop — its input arrives empty. This is why the per-event playbook cannot post screenshots or push IOCs.

**URL and hash only — no file submission.** Sekoia alerts don't carry sample bytes, so there is no file-submission action. A hash is looked up; a URL is detonated.

**No indicator-revocation action.** If a `reanalyze` flips a sample's verdict away from `malicious` after its IOCs were already pushed to a Sekoia IOC collection, this module has no way to retract them — `DELETE /v2/inthreat/ioc-collections/{uuid}/indicators/{id}` is a **Sekoia** endpoint, and this module only holds VMRay credentials. That action belongs in the `Sekoia.io` module.

**No STIX bundle output.** Scoped in, then dropped: VMRay's own `iocs/stix` endpoint only emits STIX 2.0, and Sekoia Intelligence's accepted bundle version was never confirmed against a real submission.

**Verdict is data, not a decision.** `sample_verdict` comes back in every report, but nothing in this module writes it to Sekoia's `verdict_uuid`/`custom_status` fields — that's `Sekoia.io`'s `PatchAlert` action, driven by a playbook Condition node. Deliberate: auto-closing an alert on a `clean` verdict can bury a true positive the sandbox simply didn't trigger.

## Development

```
uv sync
mise run lint     # ruff check, ruff format --check, mypy
mise run test     # pytest — fast suite only
mise run format   # ruff fix + format
```

Action manifests (`action_*.json`) and `main.py` are generated from the code — never edit them by hand:

```
uv run sekoia-automation generate-files-from-code .
```

The generator reorders `main.py`'s imports; revert that file if nothing else in it changed.

Every release adds a dated entry to `CHANGELOG.md` and bumps the version in `manifest.json`, `pyproject.toml` and the project's entry in `uv.lock`.

Three tests are marked `slow` (`pytest -m slow`, ~35s) — they exercise the retry adapter over a real local socket, not `requests_mock`. That's deliberate, not an oversight: `requests_mock` patches the transport at a level that bypasses any `HTTPAdapter` mounted on the session, so it cannot verify retry or `Retry-After` behaviour at all. Run the slow suite before any change to `client.py`'s retry configuration.
