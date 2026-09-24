# VMRay for Sekoia

**Status:** Design, pre-build
**Prepared:** 2026-08-27
**Revised:** 2026-09-16 — standalone connector dropped; design re-grounded on the official integration docs (`docs.sekoia.com/integration/`) and on shipped module source in `SEKOIA-IO/automation-library`.
**Revised:** 2026-09-23 — three gaps found against the earlier TheHive/VMRay Cortex analyzer closed: `GetScreenshots` action (analysis-archive screenshots ZIP, `data_path` handoff), `sample_analyses`/`include_analyses` (per-VM-profile verdicts, `GET /analysis/sample/{id}`), and an itemized IOC breakdown in `RenderSummary` (previously counts-only via VTIs). Per-VTI severity scoring and all-type IOC push (vs. today's hash-only) remain open, tracked as v1.1 candidates.

A working brief on Sekoia's platform and the shape of a VMRay sandbox integration into its alert lifecycle.

---

## What Sekoia is

Sekoia is an agentic SecOps platform bundling extended detection and response (XDR), cyber threat intelligence (CTI), and SOAR-style automation into one product line.

## What it offers

| Product | Role |
|---|---|
| **Sekoia Defend (XDR)** | Log ingestion, 900+ MITRE ATT&CK-aligned detection rules, alert correlation, incident workspace. Core SOC engine. |
| **Sekoia Intelligence (CTI)** | STIX 2.1 threat intel — 150+ proprietary trackers + curated OSINT (URLhaus, ThreatFox), ~6M objects, built by a TDR team (ex-ANSSI, Kaspersky). |
| **Automation (Playbooks)** | SOAR layer inside Defend — trigger → conditions → actions. |
| **Integrations Hub** | Catalog of 300+ connectors. A VMRay module ships here as an **automation module**. |

---

## Decision: native automation module

The standalone-daemon option (the shape of [`vmray/crowdstrike-falcon`](https://github.com/vmray/crowdstrike-falcon)) is **dropped**. Build follows the official path documented at [Develop Integration → Automation](https://docs.sekoia.com/integration/develop_integration/automation/overview/): a Python module in the `sekoia-automation` SDK, contributed to `SEKOIA-IO/automation-library`, listed in the Integrations Hub.

Sekoia's docs define three integration types. Only one applies:

| Type | Applies to VMRay? |
|---|---|
| **Data ingestion** (format + intake + optional connector) | No — VMRay is not a log source for Sekoia. |
| **Intake modification** (extend an existing parser) | No. |
| **Automation** (module of triggers + actions) | **Yes** — this is the build. |

---

## Three corrections to the original brief

Source research against the docs and the automation-library repo invalidated three premises the earlier draft was built on.

### 1. There is no "sandbox gap" in the catalog — but VMRay is genuinely absent

`automation-library` already ships malware-analysis modules whose shape maps directly onto VMRay:

| Module | Vendor | Relevance |
|---|---|---|
| `Glimps` (v1.15.0) | GLIMPS Detect | Closest analog. Submit-file, submit-and-wait, retrieve-by-UUID, search-by-SHA256, export report. |
| `Virustotal` | VirusTotal | scan file / hash / url / domain / ip, with detection-threshold branching. |
| `Triage` | Hatching Triage | CTI-feed trigger + `triage_to_observables` action (config → STIX observables). |
| `MWDB` | CERT.pl MWDB | Same config-to-observables shape. |

VMRay is still not in the catalog. The differentiator is VMRay's depth (VTI rules, full behavior reports, ATT&CK mapping), not the category.

**Consequence:** `Glimps` is the reference implementation to copy, not `Triage`.

### 2. The 10s/60s limits are advice about *third-party* timeouts, not a platform-enforced kill

[Best practices](https://docs.sekoia.com/getting_started/best_practices/) says verbatim:

> "Ensure the duration of each Action within playbooks is less than 10 seconds to reduce the chance of a timeout with most third-party tools you interact with."
> "Track the overall duration of playbook executions for each playbook to complete its execution in less than 1 minute."

The stated reason is third-party timeouts — not a runtime limit. Shipped modules blow straight through it:

- `Glimps/glimps/models.py` — `WaitForResultArgument.timeout` defaults to **180 s**, with `pull_time` (poll interval) and `push_timeout` as separate knobs. The action is named "Analyse a file and wait for result".
- `Virustotal/virustotal/action_virustotal_scanfile.py` — blocking `while return_code == -2` loop with `time.sleep((2**count_error) * 30)`, tolerating five backoff rounds before giving up (≈ 8 min of wall clock).

**Consequence:** the two-playbook split, and the whole alert_id-through-a-VMRay-tag handoff it required, is unnecessary. A single **submit-and-wait action** is the sanctioned pattern for exactly this problem.

### 3. Files can flow through a playbook

Actions receive a shared data volume. Glimps reads its input as:

```python
with self.data_path.joinpath(arguments.file_name).open("rb") as reader:
    uuid = self.gdetect_client.push_reader(filename=arguments.file_name, reader=reader, ...)
```

and the SDK's `Action.json_argument()` resolves any `<name>_path` argument off `self.data_path`. Sekoia's own `SecurityAlertsTrigger` writes `alert.json` into `_data_path` and passes a relative `file_path` downstream — the same channel.

**Consequence:** the module should expose a file-submission action regardless. What remains genuinely open is whether a given tenant's *alerts* carry sample bytes (they usually will not — Sekoia aggregates events, not files). Hash/URL is the realistic default path; file submission is there for the case where an upstream action fetched the sample.

#### Corroboration (2026-09-21): Sekoia has no file-retrieval capability of its own, at any layer

Prompted by a comparison to CrowdStrike Falcon — which exposes real file retrieval (RTR `get` pulls a file off a live host; the Sample Uploads API fetches/submits binaries) because CrowdStrike *is* the EDR and holds file custody. Checked whether Sekoia has an equivalent, at any of four layers:

| Layer | Checked | Result |
|---|---|---|
| SIC Alert API | OpenAPI spec, 103 paths (already machine-checked above) | No attach/file/upload/download paths |
| Native remediation actions | [`docs.sekoia.com/xdr/features/modules/reveal_security_controls/`](https://docs.sekoia.com/xdr/features/modules/reveal_security_controls/) | Only host isolation and patch-scan trigger — no file pull |
| `Sekoia.io` playbook action library | `main.py` + [action library docs](https://docs.sekoia.com/xdr/features/automate/library/sekoia-io/) | Zero file-retrieval/download actions |
| Sekoia Endpoint Agent | [product docs](https://docs.sekoia.com/integration/categories/endpoint/sekoiaio/) + vendor blog | Telemetry/log shipper (auth, file monitoring, AV events) — not an EDR with file custody |

**Why:** Sekoia isn't itself an EDR vendor. It ingests events from third-party EDRs (CrowdStrike, HarfangLab, Cortex XDR, TEHTRIS) via connector modules and orchestrates their response actions (isolate host, etc.) — it does not hold or serve file bytes itself, at the alert layer or the endpoint layer.

**Consequence:** if file retrieval is ever wanted in a VMRay playbook, it has to come from an **upstream EDR-vendor module calling that vendor's own API** (e.g. a CrowdStrike module pulling the file from Falcon), handed to the VMRay module via `data_path` — never from Sekoia's own alert or agent surface. This is consistent with, and further corroborates, decision 3 and the correction above: hash/URL is the only path reachable through Sekoia natively; file submission stays gated on an upstream fetch the VMRay module has no visibility into.

---

## Webhook ingress: resolved, and not needed

`"webhook": true` exists as a **manifest flag**, not an SDK feature:

- `Sekoia.io/trigger_sekoiaio_alert_webhook.json` and `trigger_sekoiaio_case_webhook.json` are the only two files in the entire library carrying it.
- Neither has Python behind it. Neither is registered in `Sekoia.io/main.py`. `grep -rn webhook` across `sekoia-automation-sdk` returns **nothing**.

So the flag marks a platform-hosted entrypoint (surfaced in the UI as "Manual Trigger" — "starts a playbook automatically once an analyst has reviewed an alert"). It is Sekoia pushing *into* a playbook, not a generic public ingress a third-party module can claim. A VMRay analysis-complete callback therefore has no landing pad in a custom module.

*(A `/hooks/{uuid}` entrypoint path appears in search-surfaced doc text but was not confirmed on any doc page read directly — treat as unverified, and irrelevant either way given the design below.)*

**Consequence:** VMRay webhooks are out of scope for v1. Correction 2 removes the need for them — the action polls VMRay internally, exactly as Glimps and VirusTotal do.

---

## Module design

Scaffold: `sekoia-automation new-module .` → module slug `vmray`, category `Threat Intelligence`.

### Module configuration (`manifest.json` → `configuration`)

Per the [development guidelines](https://docs.sekoia.com/integration/develop_integration/automation/development_guideline/), credentials belong at module level, never duplicated into action arguments:

```json
{
  "uuid": "<generated>",
  "name": "VMRay",
  "slug": "vmray",
  "description": "VMRay Platform — agentless hypervisor-based sandbox for malware detonation, VTI scoring and IOC extraction",
  "version": "1.0.0",
  "configuration": {
    "title": "VMRayConfiguration",
    "type": "object",
    "properties": {
      "base_url": { "title": "Base Url", "description": "VMRay Platform URL", "format": "uri", "type": "string" },
      "api_key":  { "title": "Api Key",  "description": "VMRay API key", "type": "string" }
    },
    "required": ["base_url", "api_key"],
    "secrets": ["api_key"]
  },
  "categories": ["Threat Intelligence"]
}
```

A `VMRayAction` base class holds the cached API client, mirroring `Glimps/glimps/base.py`:

```python
class VMRayAction(Action):
    module: VMRayModule

    @cached_property
    def client(self):
        return VMRayClient(self.module.configuration.base_url,
                           self.module.configuration.api_key)
```

### What VMRay returns, and where each piece lands in Sekoia

A VMRay analysis yields far more than a verdict. Sekoia's receiving surfaces are narrower than the payload, so the mapping drives the action breakdown.

| VMRay output | Sekoia landing surface | Mechanism |
|---|---|---|
| **IOCs** (domains, IPs, URLs, files, registry, mutexes) | IOC Collection | `add_ioc_to_ioc_collection`, flat typed set (enum: IP address / domain / url / email / hash). No richer sink in v1 — STIX bundle path dropped, see below |
| **VTIs** (VMRay Threat Identifiers — rule name, category, score) | Alert comment; verdict branching | No native structured home. Rendered as a markdown table in the comment; the aggregate score drives `set_output` |
| **Threat names** | Alert comment + STIX `malware` SDO | Bundle to Intelligence Center gives it a real object; comment gives the analyst it inline |
| **Classifications** | Alert comment; STIX labels | Same channel as threat names |
| **Analysis info** (job id, duration, VM profile, submission metadata) | Action result fields + comment footer | Provenance — lets an analyst jump to the exact VMRay job |
| **Screenshots** | ⚠️ **No attachment API** — deep link only | See below |
| **Child samples** (dropped / extracted) | IOC collection (hashes) + STIX `file` SDOs; optional re-submission | Each child's hash is an indicator; `relationship` SDOs tie them to the parent |
| **Relations** (sample↔sample, sample↔domain, sample↔process) | ⚠️ **Not preserved in v1** | STIX bundle path dropped (2026-09-17). Relations render as prose in the alert comment via `RenderSummary` and are discarded otherwise — no durable, queryable home |
| **MITRE ATT&CK details** | STIX `attack-pattern` refs in bundle; comment | Sekoia's detection rules are already ATT&CK-aligned, so technique IDs read natively to the analyst |
| **Sample retrieval** (download the sample itself) | `data_path` → downstream actions | Writes bytes to the shared volume; any later node (VirusTotal, Glimps, TheHive, an email action) consumes it |
| **Full PDF report** | ⚠️ No alert/case attachment. Two fallbacks | See below |

**The attachment gap — confirmed against the spec, not inferred.** Sekoia publishes its SIC OpenAPI spec unauthenticated at `https://app.sekoia.io/api/v1/sic/openapi.json` (OpenAPI 3.1, "SIC Alert API", 103 paths). Machine-checked:

- paths matching `attach` / `file` / `upload` / `document` / `blob` / `artifact` → **none**
- request bodies using `multipart/form-data` or `application/octet-stream` → **none**
- `formData` parameters → **none**

So this is not an undocumented endpoint we might discover on a tenant. **There is no way to attach a file to a Sekoia alert or case.** Screenshots and the PDF report cannot be pinned to the alert the way an analyst would expect. Three workarounds, in order of preference:

1. **Deep link in the alert comment** — VMRay report URL and screenshot URLs, authenticated on VMRay's side. Simplest, and the analyst is already licensed for VMRay.
2. **`post-reports/pdf`** ("Create Content Proposal from PDF", `post-reports/pdf`) — pushes the VMRay PDF into the Intelligence Center as a content proposal awaiting analyst merge. Works, but it lands on the CTI surface, not the alert, and it is semantically intended for threat-intel reports rather than per-sample detonation output. Offer it as an opt-in action, not a default.
3. **`data_path` handoff** — write the PDF to the shared volume and let a downstream node (TheHive `upload_logs`, an email action, object storage) take custody. Only worth wiring where the customer already runs that downstream tool.

This gap is worth raising with Sekoia during homologation — it limits every sandbox vendor equally, not just VMRay.

### Two endpoints the spec exposes that the automation library does not

Reading the OpenAPI spec turned up two SIC endpoints with no corresponding action in `Sekoia.io/main.py`. Both are relevant enough to change the design.

**`GET /v1/sic/alerts/{uuid}/objects`** — "List the objects of the alert". Returns STIX-typed objects attached to the alert, with `match[type]`, `match[kind]`, `exclude[type]`, `limit` (max 1000) and `offset`. Requires only the *View alerts* permission.

This is a **cleaner observable-extraction path than the event search**. The shipped `Enrich_alerts_with_VirusTotal_Hash` template goes alert → `short_id` → event-search job → poll → page results → dig a hash out of raw event fields. Against this endpoint the same job is one call with `match[type]=file,url`, returning already-typed objects rather than whatever field names the intake happened to use. Spike 0.1 now probes both paths and compares.

**`PATCH /v1/sic/alerts/{alert_uuid}/custom-fields`** — up to 25 custom fields per alert, each `{uuid, value}` where the value may be boolean, number, string or array.

This is a **structured home for the VMRay verdict**, which the design currently lacks — right now the verdict exists only as prose inside a markdown comment. Written to a custom field instead, it becomes filterable and sortable in the alert list, and usable in triage views. Same shape of prerequisite as the IOC collection: the custom field must be pre-created in the tenant and is addressed by UUID, so it is customer-configured, not a module default.

**Caveat on both:** neither is exposed as an action in the `Sekoia.io` module today, so a playbook cannot call them out of the box. Three ways forward, to be decided after the spikes:

1. Use the generic **Request URL** playbook block — works immediately, ugly, and hand-rolls auth in the playbook
2. **Contribute the two actions to the `Sekoia.io` module** as a separate PR — the clean fix, benefits every integration, but it is Sekoia's module and adds a second review
3. Leave them alone for v1 — extract via the event-search path, write the verdict to a comment only

Recommendation: ship v1 on the documented path (option 3), and raise option 2 with Sekoia during homologation. Do not have the VMRay module call the Sekoia API directly — a vendor module should talk to its own vendor.

### VMRay API surface — resolved (spike 0.3 closed)

Settled against the **VMRay Platform REST API OpenAPI spec, v2026.2.1** (OpenAPI 3.1, 159 paths, server `https://<host>/rest`, auth `Authorization: api_key <key>`), committed at `spikes/specs/vmray-openapi-2026.2.1.json`. No longer inferred.

| Design output | Endpoint | Notes |
|---|---|---|
| Verdict, score, severity | `GET /sample/{id}` | `sample_verdict`, `sample_verdict_reason_code/_description`, `sample_score`, `sample_severity`, `sample_vti_score`, `sample_highest_vti_score` |
| **Threat names** | `GET /sample/{id}` | `sample_threat_names` is on the base object. Dedicated `GET /sample/{id}/threat_names` returns `{sample_threat_names, children_threat_names}` — needed **only** for recursive-submission names |
| **Classifications** | `GET /sample/{id}` | `sample_classifications` on the base object; `GET /sample/{id}/classifications` splits `sample_` vs `children_` |
| **Child samples** | `GET /sample/{id}` | `sample_child_sample_ids`, `sample_child_relations`, `sample_parent_*` — **no separate call needed** |
| **Relations** | `GET /sample/{id}` | Same. Fall back to `GET /sample_relation/sample/{id}` **only** when `sample_child_relations_truncated` is true |
| VTIs (detailed rules) | `GET /sample/{id}/vtis` | Returns `{status, threat_indicators}`. The base object carries only the aggregate score |
| IOCs | `GET /sample/{id}/iocs` | Filterable by `ioc_type`, `ioc_severity`, `ioc_verdict`, `all_artifacts`. Types: files, filenames, mutexes, registry, urls, domains, ips, emails, email_addresses, processes |
| MITRE ATT&CK | `GET /sample/{id}/mitre_attack` | `{status, mitre_attack_techniques}` |
| PDF report | `GET /sample/{id}/report` | `application/octet-stream`, PDF |
| Sample bytes | `GET /sample/{id}/file` | ⚠️ **encrypted ZIP**, not raw bytes — `encryption_password` query param |
| Hash lookup | `GET /sample/sha256\|sha1\|md5/{hash}` | Returns the **full** sample object, array-wrapped |
| Submit | `POST /sample/submit` | multipart; **one endpoint for both** `sample_file` and `sample_url` |
| Poll | `GET /submission/{id}` | `submission_finished`, `submission_has_errors`, `submission_has_recursive_errors`, `submission_consumed_quota` |
| Quota | `GET /api_key/quota` | `{quota_limit, used_quota}` |
| Version | `GET /system_info` | `version`, `version_major/minor/revision`, `api_items_per_request`, `max_api_items` |
| Force reanalysis | `POST /analysis/{id}/reanalyze` | Also `reanalyze` and `analysis_caching` params on submit |
| Screenshots | `GET /analysis/{id}/archive/{filename}` | ⚠️ No dedicated endpoint — screenshots live inside the analysis archive |

#### Five corrections this forces

**1. The fan-out is roughly half the size assumed.** `GET /sample/{id}` already carries verdict, threat names, classifications, child sample ids and relations. Only three sub-resources genuinely need their own call:

```
GET /sample/{id}            → verdict, threat names, classifications, children, relations
GET /sample/{id}/vtis       → detailed VTI rules
GET /sample/{id}/iocs       → the IOC set
GET /sample/{id}/mitre_attack
```

Four calls, not six to eight. Two conditional extras: `/sample_relation/sample/{id}` when `sample_child_relations_truncated`, and `/threat_names` + `/classifications` only when recursive-child data is wanted. The aggregating-action argument still holds — four container starts is still three too many — but the latency budget is smaller than feared.

**2. The fan-out is sample-centric, not analysis-centric.** Almost everything hangs off `sample_id`. `SubmitAndWait` must therefore return `sample_id` as its primary identifier; `analysis_id` and `submission_id` are secondary. The results model changes accordingly.

**3. ~~`AnalysisToBundle` cannot be a pass-through.~~** *(Historical — the STIX bundle / CTI-tier feature was dropped from v1 entirely, 2026-09-17. Keeping this finding on record: `GET /sample/{id}/iocs/stix` exists, but its own description states "the STIX endpoint designed for accessing sample-related data for STIX 2.0. Currently the retrieval of sample IOCs in STIX 2.1 format is not supported" — Sekoia Intelligence is documented as STIX 2.1. If this feature is reconsidered later, that version gap is still the first thing to resolve, and is still worth raising with VMRay as a product request.)*

**4. `SearchSample` is far more valuable than designed.** `GET /sample/sha256/{hash}` returns the complete sample object — verdict, threat names, classifications, VTI score, child sample ids, relations, `sample_webif_url`. A cache hit therefore answers most of the enrichment in **one call, zero quota, sub-second**. Given that Sekoia alerts carry hashes far more often than URLs, this is probably the module's most-exercised path. It should be the first node in both playbook templates, not a quiet optimisation.

**5. Dedup is a native parameter, not something to hand-roll.** `POST /sample/submit` accepts `analysis_caching` and `reanalyze` directly. Expose both rather than reimplementing cache logic in the module.

#### Other constraints the spec surfaces

- **Licensing:** submission *"is not available in the DeepResponse product. DR users cannot submit samples via API."* The module must fail with a clear message on a DR key rather than a raw 4xx, and the README must state the requirement.
- **Pagination via continuation:** large results return a continuation id fetched from `GET /continuation/{id}`, and *"the Continuation ID will not be available anymore after this call."* Single-shot, so the aggregator must drain it immediately and cannot retry the same id. `system_info` exposes `api_items_per_request` / `max_api_items`. Large IOC sets will hit this.
- **Quota is observable:** `GET /api_key/quota` gives `{quota_limit, used_quota}`, and each submission reports `submission_consumed_quota` *including recursively triggered submissions*. Surface both — recursive child detonation can consume quota well beyond one unit per alert, which is exactly the risk flagged when child-sample re-detonation was defaulted off.
- **Submit response is not a single id.** It returns `{samples, submissions, jobs, errors, reputation_jobs, vt_jobs, static_jobs, md_jobs, whois_jobs}`. The `errors` array must be checked explicitly — a 200 does not mean the submission succeeded.
- **Minimum supported version: 2026.2.** Recursive threat names and classifications are *"only available for analyses completed after the 2026.2 release."* Below that, children data is silently absent rather than an error. Gate on `system_info.version_major/minor` and degrade with a logged warning.

### The alert has a native verdict field — this upgrades decision #5

Reading the full `AlertDetailSchema` (from `GET /v1/sic/alerts/{uuid}`, and confirmed against a real response body pasted in-session) settles what "wire the verdict, don't wire it" actually means mechanically.

**Three fields are system-populated and confirmed READ-ONLY** — not writable by any PATCH body, this module or any other:

- `stix` — *"Full STIX 2 bundle describing the alert and its related objects. Only populated when `?stix=true` is passed."* Read-only convenience for consumers; not a write target.
- `ttps` — MITRE ATT&CK techniques, *"as minimal STIX SCO objects"* — populated by Sekoia's own CTI correlation, not settable per-alert.
- `adversaries` — same shape, same story, for threat-actor attribution.

This closes the earlier open speculation cleanly: **there is no way to push VMRay's ATT&CK mapping or threat-actor names onto the alert object directly.** With the STIX-bundle/`post_bundle` path dropped from v1 (2026-09-17), there is now **no durable destination for this data at all** — it renders as prose in the alert comment and nothing else. Not a gap this module tries to close; a stated limitation.

**One field is genuinely useful and changes decision #5.** `PATCH /v1/sic/alerts/{uuid}` accepts:

```json
{
  "verdict_uuid": "<uuid of a pre-created custom_verdict>",
  "verdict_analysis": "free text — analysis of the alert verdict",
  "status_uuid": "<one of 5 fixed workflow-status uuids, from GET /alerts/statuses>",
  "details": "free text — additional analyst context",
  "comment": "reason the alert was updated"
}
```

`verdict_uuid` points at an object created via `POST /v1/sic/custom_verdicts` — `{description, label, level, stage}` where **`stage` is a hard binary enum: `false_positive` or `true_positive`**. No "suspicious" tier at this level — a real constraint, not an oversight in this design.

This is the **native, idiomatic target for `set_output`**, and it's a better mechanism than the generic comment currently planned:

1. One-time setup (Phase 6, not per-alert): `POST /custom_verdicts` twice — `VMRay: Malicious` (`stage: true_positive`) and `VMRay: Clean` (`stage: false_positive`).
2. Per-alert: `PatchAlert` — **the existing `Sekoia.io` action**, already registered as `patch-alerts/{uuid}` — with `verdict_uuid` + `verdict_analysis` (VMRay's `sample_verdict_reason_description`) + optionally `status_uuid`.

**No new Sekoia-side action needed for this.** `PatchAlert` already exists and already accepts every field this needs.

**Custom fields remain the one genuine gap.** `PATCH /alerts/{alert_uuid}/custom-fields` is a **separate endpoint**, still not exposed as a `Sekoia.io` action — confirmed: `type` enum is `text | integer | boolean | single_select | multi_select`. A `single_select` custom field (`VMRay Verdict: malicious/suspicious/clean/unknown`) covers the middle ground the binary `verdict_uuid` enum can't. This is the **one** action worth raising for contribution to `Sekoia.io` at homologation — down from the two originally flagged, since verdict-writing turned out to already be covered by an existing action.

### Observable extraction — two confirmed methods, from Sekoia's own shipped playbooks

Rather than wait on tenant data for this, `SEKOIA-IO/Community`'s `playbooks/templates/` (39 templates) was pulled directly. Three do alert-to-VirusTotal enrichment — real, Sekoia-authored, currently-shipped precedent for the exact extraction problem this module has.

**Method A — raw event JSONPath**, via `Get Events` → `Read JSON File`:

```
$..["file.hash.sha1"]        # flattened dotted-string key, literal — confirmed
$..["destination.ip"]
$..["url.domain"]
```

Alert→event query syntax, confirmed verbatim and consistent across all three templates:
```
alert_short_ids: "{{ node.X['short_id'] }}"
```

**Method B — STIX bundle JSONPath**, via `Get Alert` called with `stix: true`, then JSONPath directly against the returned bundle:

```
$.objects[?(type="observed-data")].objects[?(@.type="domain-name")].value
$.objects[?(type="observed-data")].objects[?(@.type="url")].value
```

`stix` is a plain boolean argument on the **already-registered `GetAlert` action** — this is the same `?stix=true` query param found in the `AlertDetailSchema` spec, now confirmed in production use. **This retires the `/objects`-vs-event-search open question and the "contribute `Get Alert Objects`" idea from earlier** — a shipped, working, zero-new-code path already exists. No new Sekoia-side action needed for extraction at all.

**One asymmetry, stated plainly:** none of the three templates extract a file **hash** via Method B — the one shipped hash-enrichment template uses Method A exclusively. Method B is confirmed for URL and domain, not for hash. The module's extraction node should default to Method A for hashes until Method B is verified against a real STIX `file` SCO's `hashes` object.

**On file bytes — corroborating, not conclusive.** Searched all 39 templates for any `file` / `sample_file` / `attachment` argument sourced from an alert. **Zero.** Every `file`-named argument found was `Read JSON File`'s own generic parameter, pointed at a STIX bundle or an events blob — never a malware sample. This does not prove any given tenant lacks file bytes on its alerts, but it is real signal: Sekoia's own template authors, across 39 shipped playbooks, never had one to work with either. Consistent with, not a replacement for, spike 0.2.

**One fragility in the shipped reference, worth avoiding rather than copying.** `Enrich_alerts_with_VirusTotal_Hash.json`'s "not malicious" branch indexes `node.12['output'][0]` with no length guard — a zero-match JSONPath throws there. The module's own extraction node should check for an empty result and branch to "no submittable observable found" rather than fail.

### IOC-collection policy (decided)

`POST /v2/inthreat/ioc-collections/{uuid}/indicators` writes **live**, immediately — confirmed against the spec: no content-proposal, no staging, no review gate. Just the "Manage IOC collections" permission and a direct write. That's why this needed an explicit policy rather than assuming a default caution — the IOC collection is now the module's *only* Intelligence Center write path, since the staged, reviewable `post_bundle` route was dropped.

**Decided:**

| Verdict | Action |
|---|---|
| `malicious` | Push to `VMRay Detonation IOCs`, tagged `confirmed` |
| `suspicious` | **Not pushed.** Comment only — visible to an analyst, never live |
| `clean` / `unknown` | Not pushed |

- **Collection:** default `VMRay Detonation IOCs`, discovered by name (`GET ?term=`) or created on first use (`POST /ioc-collections`). Never a customer's existing production collection — keeps the set independently auditable and revocable.
- **TTL:** `valid_for` defaults short — **14–30 days**. Sandbox-derived infrastructure (C2 domains, dropper URLs) is abandoned or reused far faster than a hash; a long TTL turns a stale detonation IOC into a slow-building false-positive source.
- **Self-correction — new action, `RevokeIndicators`.** The endpoint supports it: `DELETE /ioc-collections/{uuid}/indicators/{indicator_id}` soft-revokes, hard-deletes only after 24h. Track which `indicator_id`s came from which `sample_id` (a small piece of state, likely playbook run-data storage or a module-side cache), and revoke them if a later `reanalyze` flips the verdict away from `malicious`. Without this, a corrected VMRay verdict never reaches indicators already pushed under the old one.

### Sekoia API surface — both specs are public

Neither spec needs to be supplied privately. Both fetch unauthenticated and are committed under `spikes/specs/`:

| Spec | URL | Paths | Covers |
|---|---|---|---|
| SIC Alert API | `https://app.sekoia.io/api/v1/sic/openapi.json` | 103 | alerts, cases, comments, workflow, custom-fields, alert objects |
| Intelligence Center API | `https://app.sekoia.io/api/v2/inthreat/openapi.json` | 142 | bundles, IOC collections, observables, content proposals |

The SIC spec covers **only** alerts and cases — zero paths for inthreat, IOC collections, playbooks or intakes. That is why the second one matters: both of the module's output sinks live in it.

**`GET /v1/sic/alerts/{uuid}/objects` response shape** (`ObjectsSchema`), which decides the observable-extraction contract:

```json
{"items": [{"id": "...", "type": "...", "display_name": "...",
            "pattern": "...", "description": "...",
            "embedded_relationships": {"<rel>": ["<id>", ...]}}],
 "total": 0}
```

Typed `type` plus a `display_name` value, with `pattern` for indicators. That is exactly what observable extraction needs, and confirms this beats digging raw event fields — **pending spike 0.1 showing the endpoint is actually populated on real alerts.**

#### The IOC-collection question is now mostly answerable

The open item was "which collection, at what TTL, pre-created by whom". The spec removes the hard part:

| Need | Endpoint |
|---|---|
| **Find** a collection by name | `GET /v2/inthreat/ioc-collections?term=<name>&with_indicators_count=true` |
| **Create** one | `POST /v2/inthreat/ioc-collections` → `{id, name, description, community_uuid, available_for_sub_communities}` |
| **Add** indicators | `POST /v2/inthreat/ioc-collections/{uuid}/indicators` → `{indicators: [...], default_fields: {...}}` |

So `ioc_collection_id` need not be a hand-copied UUID in the playbook. A collection can be **discovered by name** — e.g. a documented convention of `VMRay Detonation IOCs` — and created on first use if absent. That turns a per-customer configuration chore into a documented default, and is a much better onboarding story.

`default_fields` is where the TTL lives; the `Sekoia.io` module surfaces it as `valid_for` in days.

**What the spec does not settle:** whether VMRay false positives entering a live collection is acceptable remains a **policy** decision per customer, not a technical one. Recommendation stands — ship the wiring, default the collection to a VMRay-specific one so its contents are trivially auditable and revocable, and never write into a customer's existing production collection.

#### Two caveats on `POST /v2/inthreat/bundles`

1. **It returns `202`, not `200`.** Content-proposal creation is asynchronous. The `Sekoia.io` action already handles this, but any error handling we write around it must not treat 202 as unexpected.
2. **The spec does not declare a STIX version.** Its request body is loosely typed (`auto_merge`, `name`, `enrich`, `assigned_to` only — the bundle itself rides in `data`). Sekoia Intelligence is documented elsewhere as STIX 2.1, but **the spec does not confirm it**, and VMRay's own STIX endpoint emits 2.0 only. *(Historical — moot for v1: the feature that would have used this endpoint was dropped, 2026-09-17. Left on record for if it's reconsidered.)*

### HTTP client contract (spikes 0.4 / 0.5 closed by decision)

Settled rather than measured:

| Setting | Value | Notes |
|---|---|---|
| Detonation wait | **30 min, configurable** | `timeout` argument, default `1800`. Replaces the 180 s borrowed from Glimps. |
| Poll interval | `pull_time`, default 10 s | 180 polls over a full 30 min window. |
| Fan-out | **Concurrent** | The four sample sub-resource calls issue in parallel. |
| Concurrency cap | 4 | One per fan-out call. No reason to go wider. |

#### 429 handling

VMRay throttles with a standard envelope and an authoritative `Retry-After`:

```http
HTTP/2 429
retry-after: 1
server: nginx

{"error_msg": "Request was throttled. Expected available in 1 seconds.", "result": "error"}
```

Rules:

1. **Honour `Retry-After` exactly.** It is in seconds and VMRay states the real availability time. Never substitute an exponential backoff curve for it.
2. Add a small random jitter (0–250 ms) on top, so four concurrent calls throttled together do not retry in lockstep.
3. Retry budget per call: 5 attempts, then surface the section into the `errors` map rather than failing the whole action — the partial-failure rule already established.
4. A 429 during the **submission poll** is not a failure. Sleep and continue; it does not consume the retry budget.

#### Error detection is three-layered

The spec documents only `200`, `400` and `404` — **429 is not in it at all**, and is known only from observed traffic. So the client cannot trust status codes alone:

1. **HTTP status** — `400` / `404` / undocumented `429`
2. **Body envelope** — `ErrorResponse {error_msg, result: "error"}`. Check `result` even on a 200.
3. **Submit-specific** — `POST /sample/submit` returns 200 with an `errors[]` array of `SampleSubmissionError {submission_filename, error_msg}`. A 200 here does **not** mean the sample was accepted.

All three are checked before a response is treated as success.

#### ⚠️ One risk this creates, to verify in spike 0.6

A 30-minute blocking action is **3.75× the longest shipped precedent** in `automation-library` (VirusTotal's `scan_file` backoff loop tops out near 8 minutes; Glimps waits 180 s). Sekoia's own guidance targets 60 s per playbook, and no documentation states an enforced kill — but nothing demonstrates a 30-minute action surviving either.

This is an assumption, not a verified fact. Spike 0.6 (import a stub module on the tenant) must include a deliberately long-running action to confirm the platform does not reap the container. If it does reap, the cron-fallback playbook stops being optional and becomes the primary design for URL detonation.

### Actions

The payload above argues against pushing the fan-out into the playbook. Split as follows:

| Action | `docker_parameters` | Purpose |
|---|---|---|
| **Submit and wait for result** | `SubmitAndWait` | Primary. Submits URL or file (hash stays SearchSample's job — no submission), polls submission status until done. Returns **identifiers and verdict only** — `submission_id`, `sample_id`, `sample_verdict`, `sample_vti_score`, `sample_webif_url`, `timed_out`. `analysis_id` dropped from the original sketch: obtaining it needs `GET /analysis/submission/{id}`, unconfirmed and unbuilt, and nothing downstream keys off it (`GetAnalysisDetails` takes `sample_id`). Cheap and fast. Args: `timeout` (default **1800**, i.e. 30 min), `pull_time` (default 10), `push_timeout` (default 30). |
| **Get analysis details** | `GetAnalysisDetails` | The aggregator. Takes `sample_id`, fans out to `GET /sample/{id}` + `/vtis` + `/iocs` + `/mitre_attack`, returns one assembled object. Toggles: `include_vtis`, `include_iocs`, `include_mitre_attack`, `include_recursive` (the `/threat_names` + `/classifications` children calls, 2026.2+). Follows continuation ids. Returns an `errors` map for sections that failed. |
| **Submit and enrich** | `SubmitAndEnrich` | Convenience composite: `SubmitAndWait` + `GetAnalysisDetails` in one node. The action most playbooks will actually use. Same toggle set. |
| Submit URL | `SubmitUrl` | `POST /sample/submit` with `sample_url`. Checks the `errors` array. |
| Submit file | `SubmitFile` | Same endpoint with `sample_file`, read from `self.data_path`. |
| **Search sample by hash** | `SearchSample` | `GET /sample/sha256\|sha1\|md5/{hash}` → the full sample object. Zero quota, sub-second, answers most of the enrichment on a cache hit. **First node in both templates.** |
| IOCs to indicator list | `IocsToIndicators` | Pure transform. Flat, typed indicator list for `add_ioc_to_ioc_collection` (its five-value `indicator_type` enum). Lossy by design — the bundle action is the lossless path. |
| Render analysis summary | `RenderSummary` | Pure transform. VTIs + classifications + threat names + ATT&CK + report deep link → one markdown string for `post-alerts/{uuid}/comments`. Keeps presentation out of the API actions. |
| Download sample | `GetSample` | `GET /sample/{id}/file` → **encrypted ZIP** (not raw bytes), written to `data_path`. Exposes `encryption_password`. |
| Download PDF report | `GetReportPdf` | `GET /sample/{id}/report` → PDF to `data_path`. Pairs with `post-reports/pdf` or a handoff node. |
| Download screenshots | `GetScreenshots` | `GET /analysis/{id}/archive/screenshots` → ZIP to `data_path`. Same handoff pattern as `GetSample`/`GetReportPdf`; keyed by `analysis_id`, not `sample_id` — a sample can carry several analysis runs. |
| ~~Check quota~~ | ~~`GetQuota`~~ | **Removed (2026-09-24)** — no playbook needed a pre-detonation quota guard. `GET /api_key/quota` remains documented in the API surface table above if it's ever wanted back. |

The two **pure transform** actions make no VMRay calls — they are cheap, deterministic, and trivially unit-testable against fixture JSON. That separation is what keeps the API actions thin.

Verdict branching uses `self.set_output(...)`, the mechanism `Virustotal` uses for its detection threshold — lets a playbook fork on malicious / suspicious / clean without an operator node.

**Latency budget.** The fan-out runs *after* detonation completes, so it adds to wall clock. Decided: **run the four calls concurrently**, so the fan-out costs roughly its slowest call rather than the sum. The SDK already ships `sekoia_automation/aio/` and `http/` helpers with rate limiting, so concurrency is supported rather than bolted on. With a 30-minute detonation budget the fan-out is noise either way; concurrency matters mainly on the `SearchSample` cache-hit path, where the whole enrichment should return in under a second.

### Results model

Pydantic model matching the manifest's `results` JSON schema exactly (SDK requirement). This is the **assembled** shape `GetAnalysisDetails` returns — the module's job is to flatten VMRay's several endpoint responses into it, so downstream transform actions and playbook Jinja expressions see one stable contract regardless of how many calls produced it:

Field names below are the real ones from the spec, not placeholders:

```
sample_id, sample_verdict, sample_verdict_reason_code, sample_verdict_reason_description
sample_score, sample_severity, sample_vti_score, sample_highest_vti_score
sample_threat_names[], sample_classifications[]
sample_sha256hash, sample_sha1hash, sample_md5hash, sample_ssdeephash
sample_filename, sample_filesize, sample_type, sample_webif_url, sample_display_url
sample_child_sample_ids[], sample_child_relations[]        # from GET /sample/{id}
sample_child_relations_truncated                           # → fall back to /sample_relation
threat_indicators[]                                        # from /vtis
iocs: {files, filenames, mutexes, registry, urls, domains,
       ips, emails, email_addresses, processes}            # from /iocs
mitre_attack_techniques[]                                  # from /mitre_attack
submission_id, analysis_id, submission_consumed_quota, submission_finished
errors: {section_name: message}   # partial-failure map; empty on a clean run
```

### Playbook — single flow

```
Trigger: Alert Created   (or Manual Trigger, for analyst-initiated detonation)
  → Sekoia.io: Get Alert                    (get-alerts/{uuid})
  → Sekoia.io: Get Events                   (get-events)
  → Operator: extract observable (hash / url)
  → VMRay: Submit and enrich                ← blocks: detonation poll, then internal fan-out
  → VMRay: Render analysis summary
  → Sekoia.io: Post comment on alert        (post-alerts/{uuid}/comments)
  → VMRay: IOCs to indicator list
  → Sekoia.io: Add IOC to IOC collection    (add_ioc_to_ioc_collection)
  → Sekoia.io: Trigger action on alert workflow / Patch alert
```

Every Sekoia-side node above is an existing registered action in `Sekoia.io/main.py` — nothing new needed on that side.

**Single output tier — the alert.** Comment + IOC collection + workflow is everything a tier-1 analyst needs in the next 30 seconds, and it's the module's entire v1 write surface. The STIX-bundle / Intelligence Center tier that would have made relations, ATT&CK and malware objects durable was scoped in, then dropped (2026-09-17) — see "Dropped: STIX bundle / CTI tier" below. That data now exists only as prose in the comment; nothing preserves it structurally.

**Fallback for analyses that outrun the wait action:** a second playbook on the **Cron trigger** running `GetResults` over submissions parked in playbook run data storage. Only build this if field data shows detonations regularly exceeding the timeout.

---

## Decisions (locked)

| # | Decision | Choice | Consequence |
|---|---|---|---|
| 1 | Architecture | Native automation module | Standalone daemon dropped. SDK + `automation-library`. |
| 2 | Entry point | **One module, two playbook templates.** Manual Trigger first, Alert Created second | Same actions behind both; only the trigger node and filter conditions differ. Considered and rejected: `VirusTotal_Enrichement.json` shows a merged single-playbook shape (both triggers feeding shared downstream via `store.uuid`) — reaffirmed two templates instead, 2026-09-17. |
| 3 | Observables | Hash (lookup) + URL (detonation) + File (detonation, **gated**) | Domain/IP reputation excluded — overlaps Sekoia Intelligence. File submission ships only if Phase 0 proves the tenant exposes bytes. |
| 4 | Outputs wired by default | Alert comment + IOC collection | Analyst value immediately, no blast radius. |
| 5 | Output built but **not** wired | verdict → `PatchAlert.verdict_uuid`/`verdict_analysis` (native alert verdict, binary TP/FP; no new Sekoia action needed) | Capability shipped, policy left to the customer. Auto-status is the one thing that can bury a true positive. STIX-bundle/CTI-tier output dropped entirely (2026-09-17) — see below. |
| 6 | Distribution | **Upstream PR + homologation** from day one | Public-repo hygiene is a build constraint, not a final step: mypy clean, pytest, semver, CHANGELOG, zero secrets. |
| 7 | PR sizing | Everything in one PR | All 12 actions, both templates, full suite. One review cycle; accept the large diff. |
| 8 | VMRay targets | **Cloud and on-prem Platform** | `base_url` customer-supplied, plus `verify_ssl`. Declare a minimum supported Platform version. Test matrix ×2. |
| 9 | Test environment | Sekoia tenant **and** VMRay instance available | Plan is build → verify → PR. Open questions become Phase 0 spikes, not assumptions. |
| 10 | Toolchain | **uv + mise + ruff + mypy** | Not poetry/black. See below. |

### Toolchain note — the repo contradicts its own docs

`docs/development_guideline.md` in `automation-library` still prescribes `poetry` and `black`. It is **stale**. The repository root carries `POETRY_TO_UV_MIGRATION_PLAN.md` (dated 2026-07-23) and a root `mise.toml`; 28 modules already ship `uv.lock` against 85 still on `poetry.lock`, and the official docs say `uv add`. New modules follow `mise.toml`:

```toml
[tools]
uv = "latest"

[tasks.test]
run = "uv run pytest tests/"

[tasks.lint]
run = ["uv run ruff check --no-fix .", "uv run ruff format --check .", "uv run mypy ."]

[tasks.format]
run = ["uv run ruff check --fix .", "uv run ruff format ."]
```

Build the VMRay module uv-native from the start. Submitting a new poetry module into an active migration would be a review comment on arrival.

---

## Dropped: STIX bundle / CTI tier (2026-09-17)

Scoped in during design, cut before build. Removed from v1 entirely:

- `AnalysisToBundle` action (pure transform, would have built a STIX bundle from VMRay's aggregated analysis)
- Wiring to `post_bundle` ("Create Content Proposal") → Sekoia Intelligence Center
- The whole "second output tier" framing — relations, ATT&CK techniques, malware SDOs surviving as durable, queryable intelligence

**What this means concretely:** VMRay's child-sample lineage, sample relations, and MITRE ATT&CK mapping now have **no durable home** in v1. They render as prose inside the alert comment (`RenderSummary`) and nothing else — not queryable, not structured, gone once the comment scrolls out of an analyst's attention. This was a known trade-off going in (the mapping table above called it out explicitly), now the accepted one rather than a mitigated one.

**Why it's still reasonably cut:** it was always the higher-effort, lower-certainty half of the design — an unconfirmed STIX version requirement, an async content-proposal review flow, a whole customer-CTI-practice assumption. Dropping it shrinks the PR, removes the STIX-2.1 open question entirely, and ships the tier-1 analyst value (comment + IOC collection + verdict) without waiting on it.

**Reversible.** Nothing else in the design depends on this tier existing. If reconsidered later, the research is preserved above (marked historical) rather than deleted — the VMRay STIX-2.0-only limitation and Sekoia's undeclared bundle version are still the first two things to resolve.

## Implementation plan

### Phase 0 — Spikes

Status as of 2026-09-17. Four of the seven are closed, three without ever touching a tenant.

| # | Spike | Status |
|---|---|---|
| 0.3 | VMRay endpoint paths and response shapes | ✅ **Closed** — resolved against the v2026.2.1 OpenAPI spec. Forced five design corrections. |
| 0.4 | Detonation wait budget | ✅ **Closed by decision** — 30 min, configurable. Measurement no longer gates the build. |
| 0.5 | Concurrent fan-out / rate limits | ✅ **Closed by decision** — concurrency allowed, 429 handled via `Retry-After`. |
| — | Sekoia alert/case attachment endpoint | ✅ **Closed** — confirmed absent across all 103 SIC paths. |
| — | Minimum VMRay Platform version | ✅ **Closed** — 2026.2. |
| — | IOC collection addressing | ✅ **Closed mechanically** — discoverable by name, creatable. Policy still open. |
| 0.1 | What observables real alerts carry, and under which field names | ⛔ **Blocked on Sekoia API key.** Probe written: `spikes/spike_01_02_alert_observables.py` |
| 0.2 | Does any alert path expose sample bytes | ⛔ **Blocked on Sekoia API key.** Same probe. Gates whether `SubmitFile` ships wired. |
| 0.6 | Tenant import loop — **plus two riders** | ⛔ **Blocked on tenant.** See below. |
| 0.7 | On-prem TLS with a self-signed appliance | ⛔ **Blocked on appliance access.** |

**Spike 0.6 now carries the one highest-risk unknown left in the design**, and must test both things:

1. Does the import → run loop work end to end? *(routine)*
2. **Does Sekoia reap a 30-minute action container?** 3.75× the longest shipped precedent. If it reaps, `SubmitAndWait` is unusable for URL detonation and the cron-fallback playbook becomes the primary architecture, not an optional extra.

Nothing in Phase 1 is blocked. The contracts are settled by spec, so scaffolding, models and the two pure-transform actions can all proceed now; 0.1 and 0.2 only affect the observable-extraction node and the `SubmitFile` wiring decision.

### Phase 1 — Scaffold and contracts

1. `uv tool install sekoia-automation-sdk`, then `sekoia-automation new-module .` → slug `vmray`, category `Threat Intelligence`.
2. Convert the scaffold to uv + mise: module `mise.toml` inheriting the root, pinning its Python version and local `.venv`.
3. `manifest.json` configuration: `base_url` (uri, required), `api_key` (required, `secrets: ["api_key"]`), `verify_ssl` (bool, default `true`).
4. `vmray/models.py` — every Pydantic argument and result model, written against the Phase 0 fixtures. **The results model is the contract**; the two pure-transform actions and all playbook Jinja depend on it.
5. `vmray/base.py` — `VMRayAction(Action)` with a `cached_property` client, mirroring `Glimps/glimps/base.py`. Client honours `verify_ssl` and sets a `User-Agent` identifying the module and version.

### Phase 2 — Pure transforms first (no network, no credentials)

Written and fully tested against Phase 0 fixtures before any API code exists. Cheapest, most testable, and they pin the results model by using it.

- `RenderSummary` — markdown for `post-alerts/{uuid}/comments`
- `IocsToIndicators` — flat typed list for `add_ioc_to_ioc_collection`'s five-value enum

### Phase 3 — API actions

Order matters: cheapest and most independently verifiable first.

1. `SearchSample` — hash lookup; also the dedup guard
2. `SubmitUrl`, `SubmitHash`, `SubmitFile` — fire-and-forget
3. `SubmitAndWait` — poll to completion, return **identifiers and verdict only**
4. `GetAnalysisDetails` — the fan-out aggregator, with the `include_*` toggles and the `errors` partial-failure map
5. `SubmitAndEnrich` — composite of 3 + 4; the action most playbooks use
6. `GetSample`, `GetReportPdf` — write to `data_path`, return relative paths


Two items originally sketched here are cut, not built: **`GetChildSamples`** — redundant, `sample_child_sample_ids`/`sample_child_relations` already ride on the base `GET /sample/{id}` object per spike 0.3's findings. **`RevokeIndicators`** — wrong module entirely; `DELETE /v2/inthreat/ioc-collections/{uuid}/indicators/{id}` is a Sekoia endpoint, not VMRay's, and this module's config carries no Sekoia credentials. Moved to the `Sekoia.io` contribution list below.

**Dedup rule, applied throughout:** `SearchSample` runs before any submission. An existing analysis is reused unless `force_reanalysis` is set. Without this, a hash appearing across twenty alerts costs twenty detonations.

### Phase 4 — Manifests, tests, quality gates

- Generate manifests with `sekoia-automation generate-files-from-code` — never hand-write the JSON schemas
- `pytest` + `requests_mock` against Phase 0 fixtures. Cover: happy path, **partial fan-out failure**, VMRay 4xx/5xx, timeout expiry, on-prem TLS
- `mise run lint` clean — `ruff check`, `ruff format --check`, `mypy`. Hard PR gate
- `manifest.json` version `1.0.0`; `CHANGELOG.md` in Keep a Changelog format
- `README.md` documenting the attachment limitation and the unwired capabilities

### Phase 5 — Playbook templates

Built against the exact shipped format confirmed in `SEKOIA-IO/Community` (`Enrich_alerts_with_VirusTotal_Hash.json` dumped in full, not summarized — node schema, `outputs` linkage, `module_uuid`/`action_uuid` pairing, Condition-operator shape all taken directly from it). Files: `playbooks/VMRay_Manual_Detonation.json` (12 nodes), `playbooks/VMRay_Automatic_Enrichment.json` (12 nodes) — both validated (valid JSON, no dangling `outputs` references, every non-trigger node reachable).

- **Template A — Manual detonation**: Manual Trigger → Get Alert → Get Events → extract hash → Condition (hash present?) → `SearchSample` → `GetAnalysisDetails` → `RenderSummary` → Comment → `IocsToIndicators` → Add IOC to collection. Miss/no-hash branches converge on one "no VMRay match" comment.
- **Template B — Automatic** *(revised 2026-09-24 — hash **and** URL)*: Alert Created → urgency ≥ threshold → Get Alert → Get Events → three `Read JSON File` extractions → hash found? → `SearchSample` → `GetAnalysisDetails`; no hash, or hash unknown to VMRay → http(s) URL found? → `SubmitAndEnrich` (URL detonation). Both branches converge on one `RenderSummary` → comment → malicious? → `IocsToIndicators` → IOC collection. 19 nodes.
  - **Field choice, measured, not guessed** — counted which fields the 252 parsers in `SEKOIA-IO/intake-formats` actually populate: `url.original` 82, `url.full` 20 (7 of them — incl. CrowdStrike Falcon and Retarus — set `url.full` *without* `url.original`, so both are needed); `file.hash.sha256` 46 / `md5` 31 / `sha1` 24, `process.hash.sha256/sha1/md5` 13/15/12. The previous template read `file.hash.sha256` only and missed md5/sha1-only parsers and process-execution hashes.
  - **URLs filtered to `^https?://`** inside the JSONPath — ECS `url.original` is path-only (`/index.php`) in web-server logs, which VMRay can't detonate. Same guard as Sekoia's own `VirusTotal_Enrichement` template (`regex_match('^http.*')`). Two separate nodes because `jsonpath_ng`'s `|` union silently drops one side when combined with filters — verified on the exact version the `Utils` module pins (1.6.1).
  - **Branch convergence** reads `node.9 if (node.9 is defined and node.9) else node.11['analysis']` — tested under Jinja's default, chainable and strict undefined modes, and with the skipped node absent *or* `None`. Still unconfirmed on a live tenant (spike 0.6).
  - **Adds the malicious-only IOC push gate** the IOC-collection policy above requires; the previous template pushed on any VMRay hit.

**Scope cut, made explicit rather than silent: v1 templates are hash-only.** `SubmitAndEnrich` takes `sample_url`/`file_name`, never a bare hash (by design — decision 3's observable scope). Converging a hash-hit path (`SearchSample`→`GetAnalysisDetails`) and a URL-fallback path (`SubmitAndEnrich`) into one graph would need one of two things this build can't confirm: either a shared downstream chain reading from *whichever* upstream node actually fired (untested whether Sekoia's Jinja can reference a node that never executed), or duplicating the render/comment/IOC chain for both paths, which pushes past 20 nodes. Neither was worth guessing at. **v1 ships the hash path only** — a miss comments "not in VMRay's history, no detonation performed" and stops. URL-triggered fresh detonation via `SubmitAndEnrich` is a documented v1.1 addition once node-convergence behaviour is confirmed on a live tenant.

**A second scope cut surfaced while wiring the IOC-push node.** `add_ioc_to_ioc_collection` takes one `indicator_type` per call, but `IocsToIndicators` returns a mixed-type list — pushing every type would need up to 5 filtered calls (`node.9['indicators'] | selectattr('type','equalto','domain') | map(attribute='value') | list`, one per type), each needing its own empty-list guard against an unconfirmed API behaviour. **v1 pushes hash only** — the one type a successful detonation always has, and the highest-confidence indicator of the five (the sample itself, not shared infrastructure). Domains/URLs/IPs still reach the analyst via `RenderSummary`'s comment; they're just not pushed live. Extending to the other four types is mechanical once empty-list handling is confirmed.

**A third gap for the `Sekoia.io` contribution list.** "Discover or create an IOC collection by name" is a real Intelligence Center *API* capability (`GET/POST /v2/inthreat/ioc-collections`) but isn't exposed as a `Sekoia.io` *playbook action* — only `add_ioc_to_ioc_collection` (add indicators to an already-known collection) is registered. Both templates take `ioc_collection_id` as a literal placeholder (`REPLACE_WITH_YOUR_VMRAY_IOC_COLLECTION_ID`) the importer fills in once — the same normal, expected edit-after-import pattern every shipped Community template already uses for its own hardcoded values (thresholds, webhook URLs). Adds a third item to the contribution list, alongside `Patch Alert Custom Fields` and `Revoke IOC Collection Indicator`.

**Two mechanisms this build leans on but never independently confirmed**, worth adding to spike 0.6's live-tenant checklist:
- Passing a whole node's result object as another action's object-typed argument (`"analysis": "{{ node.6 }}"`, `"iocs": "{{ node.6 }}"`) — standard for any playbook engine, and consistent with everything read, but no shipped example in `SEKOIA-IO/Community` does this exact thing (`{{ node.X }}` always fed strings, hashes or single field lookups in every example dumped from that repo).
- Standard Jinja2 `selectattr`/`map` filters (used in the IOC-type filtering above) — the shipped examples confirm `reject`, `join`, `regex_match`, `jsonpath` work, but never `selectattr`/`map` specifically.

Both under 15 nodes (12 each), per Sekoia's best-practice target. Contribute as JSON to `SEKOIA-IO/Community`, following `Enrich_alerts_with_VirusTotal_Hash.json`.

### Phase 6 — Validate, then submit

1. Import the real module on the test tenant; run both templates against live alerts
2. Confirm on Cloud **and** a self-signed on-prem appliance
3. PR to `SEKOIA-IO/automation-library`
4. Email **homologation-request@sekoia.io** with the PR link
5. Raise the attachment gap with Sekoia in the same thread — it limits every sandbox vendor equally, and a first-party fix is worth more than any workaround

---

## Open items

**Resolved by Phase 0:** alert observable schema (0.1), file availability (0.2), VMRay endpoint paths and shapes (0.3), detonation timing (0.4), rate limits (0.5), on-prem TLS (0.7).

**Closed without needing tenant access** (settled against the public SIC OpenAPI spec, 2026-09-17):

- ~~Undocumented alert/case attachment endpoint?~~ **No.** Confirmed absent across all 103 paths of the SIC OpenAPI spec. Screenshots and PDF stay deep-linked; the README must say so. Raise with Sekoia at homologation as a platform gap affecting every sandbox vendor.
- ~~Exact VMRay endpoint paths and response shapes~~ **Resolved** against the v2026.2.1 OpenAPI spec. See the surface table above. Spike 0.3 is closed; `spike_03_vmray_surface.py` is now only a live sanity check, not a discovery tool.
- ~~Minimum supported VMRay Platform version~~ **2026.2**, forced by recursive threat names and classifications. Gate on `system_info.version_major/minor`, degrade with a warning.

**Still requiring a decision or an external answer:**

- ~~Which IOC collection, at what `valid_for` TTL, which verdicts push~~ **Closed by decision** (2026-09-17). See "IOC-collection policy" below.
- Whether `post-reports/pdf` content proposals are an acceptable home for per-sample detonation PDFs, or a misuse of the Intelligence Center surface. Sekoia's call.
- ~~Whether to contribute a `Get Alert Objects` action~~ **Unnecessary.** `GetAlert` already accepts `stix: true` and returns typed STIX observables in one call — confirmed in three shipped Community playbook templates. **Three** genuine gaps remain worth raising for contribution to `Sekoia.io`: `Patch Alert Custom Fields`; **`Revoke IOC Collection Indicator`** (`DELETE /v2/inthreat/ioc-collections/{uuid}/indicators/{id}`) — needed to retract a pushed indicator when a VMRay `reanalyze` flips a sample away from `malicious`, found while implementing Phase 3 (originally, wrongly, drafted as a VMRay-module action — moved here since it's a Sekoia-side call); and **`Find or Create IOC Collection`** (`GET`/`POST /v2/inthreat/ioc-collections`) — found while wiring Phase 5's playbook templates, which currently take a literal placeholder `ioc_collection_id` for lack of this action.
- ~~Whether VMRay verdict has a structured home beyond a comment~~ **Resolved.** Native `verdict_uuid`/`verdict_analysis` fields exist on the alert, binary (true_positive/false_positive) only. Requires one-time setup of two `custom_verdict` objects; see above.

---

## References

**Sekoia — Platform & Product**
- [Sekoia — Agentic Cybersecurity Platform](https://www.sekoia.io/en/homepage/)
- [Sekoia Defend — XDR platform](https://www.sekoia.io/en/product/xdr/)
- [Sekoia Intelligence — CTI product](https://www.sekoia.io/en/product/cti/)
- [Integrations catalog](https://www.sekoia.com/integrations)
- [Platform best practices](https://docs.sekoia.com/getting_started/best_practices/)

**Sekoia — Official integration docs (`docs.sekoia.com/integration/`)**
- [Develop Integration — overview](https://docs.sekoia.com/integration/develop_integration/overview/)
- [Automation — overview](https://docs.sekoia.com/integration/develop_integration/automation/overview/)
- [Automation — Module](https://docs.sekoia.com/integration/develop_integration/automation/module/)
- [Automation — Action](https://docs.sekoia.com/integration/develop_integration/automation/action/)
- [Automation — Trigger](https://docs.sekoia.com/integration/develop_integration/automation/trigger/)
- [Automation — Create a Module](https://docs.sekoia.com/integration/develop_integration/automation/create_a_module/)
- [Automation — Development Guidelines](https://docs.sekoia.com/integration/develop_integration/automation/development_guideline/)

**Sekoia — Playbook docs**
- [Build playbooks](https://docs.sekoia.com/xdr/features/automate/build-playbooks/)
- [Native trigger library](https://docs.sekoia.com/xdr/features/automate/triggers/)
- [Playbooks JSON schema](https://docs.sekoia.com/xdr/features/automate/playbooks_format_json_schema/)
- [Native Sekoia.io action/trigger library](https://docs.sekoia.com/xdr/features/automate/library/sekoia-io/)
- [API Documentation](https://docs.sekoia.com/developer/api/)

**Sekoia — Source read for this design**
- [automation-library](https://github.com/SEKOIA-IO/automation-library)
  - `Glimps/` — reference implementation (submit + submit-and-wait + retrieve + export)
  - `Virustotal/` — blocking poll loop, `set_output` verdict branching
  - `Triage/`, `MWDB/` — `*_to_observables` action shape
  - `Sekoia.io/main.py` — the alert/IOC actions the playbook consumes
  - `docs/development_guideline.md`, `docs/organization.md`
- [sekoia-automation-sdk](https://github.com/SEKOIA-IO/sekoia-automation-sdk) — `action.py` (`data_path`, `json_argument`, `set_output`), `trigger.py` (no webhook server)

**VMRay — Internal knowledge base**
- `vmray-pltf-api-guide.pdf` — API Programmer Guide v2026.2.1, Ch.13 "Understanding Webhooks" (deferred, see above)
- `vmray-pltf-cloud-api-ref.pdf` — Cloud API Reference v2026.2.1, `POST /rest/sample/submit`
- `vmray-pltf-user-ref.pdf` — Console User Reference v2026.2.1, §4.6 "Using Tags"
