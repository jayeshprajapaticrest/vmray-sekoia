"""
Data models of the VMRay module.

Field names on VMRay-sourced models follow the VMRay Platform REST API
(OpenAPI spec, v2026.2.1) verbatim — see spikes/specs/vmray-openapi-2026.2.1.json
in the design repo. They are NOT renamed to snake_case-without-prefix or to
Sekoia conventions, so a field here can always be grep'd straight back to the
spec it came from.

Types are intentionally loose (plain `str` rather than a `Literal`/enum) on
any VMRay-controlled value whose full set of possibilities was not directly
confirmed against real response bodies (verdict, severity, classification
strings). A strict Literal would raise on an unseen-but-valid value VMRay adds
later; a plain str degrades gracefully instead.
"""

from typing import Any

from pydantic import BaseModel, Field, ValidationInfo, field_validator
from pydantic.json_schema import SkipJsonSchema
from sekoia_automation.module import Module


def hide_empty_defaults(schema: dict[str, Any]) -> None:
    """Sekoia's playbook editor shows an input only when it has a plain `type`: optional inputs are typed
    `X | SkipJsonSchema[None]` so the schema carries no `null` branch, and their `"default": null` is dropped
    here — empty still means "not set" in the code."""
    for prop in schema.get("properties", {}).values():
        if "default" in prop and prop["default"] is None:
            del prop["default"]


# --------------------------------------------------------------------------
# Module configuration
# --------------------------------------------------------------------------


class VMRayConfiguration(BaseModel):
    base_url: str = Field(
        ...,
        description="VMRay Platform URL, e.g. https://eu.cloud.vmray.com or an on-prem appliance URL",
        json_schema_extra={"format": "uri"},
    )
    api_key: str = Field(..., description="VMRay API key", json_schema_extra={"secret": True})
    verify_ssl: bool = Field(
        default=True,
        description="Verify the TLS certificate of the VMRay Platform. "
        "Disable only for an on-prem appliance with a self-signed certificate.",
    )


class VMRayModule(Module):
    configuration: VMRayConfiguration


# --------------------------------------------------------------------------
# Submission-time VMRay options, shared by every submitting action
# --------------------------------------------------------------------------


class SubmissionOptions(BaseModel):
    """POST /sample/submit form fields, with the descriptions, types and defaults of the
    Cortex-Analyzers VMRay analyzer's configuration (VMRay.json) — minus its archive
    settings, which only apply to submitted files. Options left empty
    are not sent, so the VMRay user's own analyzer settings apply. `net_scheme_name`
    and `analysis_timeout` are not form fields: they ride inside the `user_config`
    JSON string (as `net_scheme_name` and `timeout`)."""

    model_config = {"json_schema_extra": hide_empty_defaults}

    shareable: bool = Field(
        default=False,
        description="If set to true, the hash of the sample will be shared with VirusTotal.",
    )
    max_recursive_samples: int = Field(
        default=10,
        ge=0,
        le=10,
        description="The maximum amount of recursive samples which will be analyzed (at most 10). 0 disables "
        "recursion.",
    )
    max_jobs: int | SkipJsonSchema[None] = Field(
        default=None, description="Limits the amount of jobs that can be created by jobrules for a submission."
    )
    enable_reputation: bool | SkipJsonSchema[None] = Field(
        default=None,
        description="If set to true, reputation lookups will be performed for submitted samples and analysis "
        "artifacts (file hash and URL lookups) by the VMRay cloud reputation service and additional third party "
        "services. The user analyzer setting is used as default value for this parameter.",
    )
    enable_whois: bool | SkipJsonSchema[None] = Field(
        default=None,
        description="If set to true, domains seen during analyses are queried with external WHOIS service. The user "
        "analyzer setting is used as default value for this parameter.",
    )
    analyzer_mode: str | SkipJsonSchema[None] = Field(
        default=None,
        description="Specifies which types of analyzers will be used for analyzing this sample. Supported strings "
        "are 'reputation', 'reputation_static', 'reputation_static_dynamic', 'static_dynamic', and 'static'. The "
        "user analyzer setting is used as default value for this parameter.",
    )
    known_malicious: bool | SkipJsonSchema[None] = Field(
        default=None,
        description="If set to true, triage will be used to pre-filter known malicious samples by results of "
        "reputation lookup (if allowed) and static analysis. The user analyzer setting is used as default value "
        "for this parameter.",
    )
    known_benign: bool | SkipJsonSchema[None] = Field(
        default=None,
        description="If set to true, triage will be used to pre-filter known benign samples by results of "
        "reputation lookup (if allowed) and static analysis. The user analyzer setting is used as default value "
        "for this parameter.",
    )
    analysis_timeout: int | SkipJsonSchema[None] = Field(default=None, description="Analysis timeout in seconds.")
    net_scheme_name: str | SkipJsonSchema[None] = Field(default=None, description="Name of the network schema.")


# --------------------------------------------------------------------------
# SubmitUrlSample — submit a URL and wait for every resulting submission
# --------------------------------------------------------------------------


class Submission(BaseModel):
    """One submission object, as GET /submission/{id} returns it once finished."""

    model_config = {"extra": "allow"}

    submission_id: int
    submission_sample_id: int | None = None
    submission_finished: bool | None = None
    submission_has_errors: bool | None = None
    submission_verdict: str | None = None
    submission_score: int | None = None
    submission_original_url: str | None = None
    submission_consumed_quota: int | None = None
    submission_webif_url: str | None = None


class SubmitUrlSampleArguments(SubmissionOptions):
    sample_url: str = Field(..., min_length=1, description="URL to submit for detonation.")
    reanalyze: bool = Field(
        default=True,
        description="If set to true, known samples will be re-analyzed on submission. This is enabled by default.",
    )
    tags: list[str] = Field(default_factory=lambda: ["sekoia"], description="Tags to attach to the sample.")
    query_retry_wait: float = Field(
        default=10,
        gt=0,
        allow_inf_nan=False,
        description="The amount of seconds to wait before trying to fetch the results.",
    )
    timeout: float = Field(
        default=1800,
        ge=0,
        allow_inf_nan=False,
        description="Maximum time (seconds) to wait for every submission to finish. The analyzer waits forever; "
        "this stops and takes the timed_out branch.",
    )

    @field_validator("sample_url", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class SubmitUrlSampleResults(BaseModel):
    submissions: list[Submission] = Field(default_factory=list, description="Finished submissions.")
    submission_ids: list[int] = Field(
        default_factory=list, description="IDs of the finished submissions — input for the report."
    )
    sample_ids: list[int] = Field(
        default_factory=list, description="Distinct sample_ids of the finished submissions — input for the report."
    )
    pending_submission_ids: list[int] = Field(
        default_factory=list, description="Submissions still running when the wait timed out."
    )
    timed_out: bool = False
    failed_submission_ids: list[int] = Field(
        default_factory=list, description="Submissions that finished with an error, or could not be followed."
    )
    errors: list[dict[str, Any]] = Field(
        default_factory=list, description="Errors VMRay returned on submit, and why a submission failed."
    )


# --------------------------------------------------------------------------
# GetSamplesByHash — lookup only; building the full report is a separate action
# --------------------------------------------------------------------------


class GetSamplesByHashArguments(BaseModel):
    hashes: list[str] = Field(
        ...,
        title="File hashes",
        description="List of SHA256, SHA1 or MD5 file hashes to look up in VMRay — e.g. the hashes extracted from "
        "the alert's events. Duplicates are ignored; no quota is used.",
    )

    @field_validator("hashes", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        """A single hash is accepted as a one-item list, and empty values — what a playbook template yields for
        an event without that hash field — are dropped instead of failing the action."""
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            return [str(h) for h in value if h is not None and str(h).strip()]
        return value


class GetSamplesByHashResults(BaseModel):
    found: bool
    sample_ids: list[int] = Field(default_factory=list, description="Distinct VMRay sample_ids matched.")
    samples: list[dict[str, Any]] = Field(
        default_factory=list,
        description="The matched sample objects as VMRay returns them from the lookup (verdict, score, hashes, "
        "threat names, classifications, report link) — no VTIs/IOCs/MITRE ATT&CK, those need a separate fetch.",
    )
    not_found: list[str] = Field(default_factory=list, description="Hashes VMRay has never analysed.")
    errors: dict[str, str] = Field(
        default_factory=dict, description="Per-hash failures (invalid hash or lookup error)."
    )


# --------------------------------------------------------------------------
# BuildReport — the Cortex-Analyzers VMRay analyzer's `_build_report`
# --------------------------------------------------------------------------


class ReportSample(BaseModel):
    """One sample in a report, in the Cortex-Analyzers VMRay analyzer's shape: the full
    GET /sample/{id} object, plus the sub-resources fetched for it under the analyzer's
    keys, plus its child samples nested the same way. VMRay's own sample fields pass
    through untouched (extra: allow)."""

    model_config = {"extra": "allow"}

    sample_id: int
    sample_verdict: str | None = None
    sample_vti_score: int | None = None
    sample_webif_url: str | None = None
    sample_threat_names: list[str] = Field(default_factory=list, description="Sample + children, merged.")
    sample_classifications: list[str] = Field(default_factory=list, description="Sample + children, merged.")
    sample_analyses: list[dict[str, Any]] = Field(
        default_factory=list, description="Analyses of the latest submission (all analyses if none)."
    )
    sample_threat_indicators: dict[str, Any] = Field(default_factory=dict, description="GET /sample/{id}/vtis")
    sample_mitre_attack: dict[str, Any] = Field(default_factory=dict, description="GET /sample/{id}/mitre_attack")
    sample_iocs: dict[str, Any] = Field(default_factory=dict, description="GET /sample/{id}/iocs")
    sample_child_samples: list["ReportSample"] = Field(
        default_factory=list, description="Child samples, built the same way, down to max_recursion_depth."
    )
    has_screenshots: bool = Field(default=False, description="Any analysis in sample_analyses carries screenshots.")
    errors: dict[str, str] = Field(
        default_factory=dict, description="Sections of this sample that failed to load; the rest is still filled."
    )

    @field_validator(
        "sample_threat_names",
        "sample_classifications",
        "sample_analyses",
        "sample_threat_indicators",
        "sample_mitre_attack",
        "sample_iocs",
        "sample_child_samples",
        "errors",
        mode="before",
    )
    @classmethod
    def _null_is_empty(cls, value: Any, info: ValidationInfo) -> Any:
        """VMRay sends null for an empty list on some sample fields (e.g. the deprecated sample_threat_names)."""
        if value is None:
            return cls.model_fields[info.field_name or ""].get_default(call_default_factory=True)
        return value


class BuildReportArguments(BaseModel):
    model_config = {"json_schema_extra": hide_empty_defaults}

    sample_ids: list[int] | SkipJsonSchema[None] = Field(
        default=None, description="VMRay sample IDs — e.g. the `sample_ids` of Get samples by hash."
    )
    submission_ids: list[int] | SkipJsonSchema[None] = Field(
        default=None,
        description="VMRay submission IDs — e.g. the `submission_ids` of Submit URL sample. Each is resolved to "
        "its sample with one GET /submission/{id}. Used when `sample_ids` is empty.",
    )
    max_recursion_depth: int = Field(
        default=10,
        ge=0,
        le=10,
        description="The maximum depth of recursive samples which will be analyzed in the report (at most 10). 0 "
        "disables recursion.",
    )
    ioc_severity_filter: list[str] = Field(
        default_factory=list,
        description="Restrict which IOC severities are fetched from VMRay. Allowed values: 'malicious', "
        "'suspicious'. Add exactly one to filter server-side; leave empty (or add both) to fetch both severities.",
    )
    analysis_verdict_filter: list[str] = Field(
        default_factory=list,
        description="Analysis verdicts to include in the report. Allowed values: 'malicious', 'suspicious', "
        "'clean'. Leave empty to include all analyses, including those with an unknown verdict. Note: Adding all "
        "three allowed values is NOT the same as leaving empty — it still excludes analyses with unknown verdicts.",
    )
    include_screenshots: bool = Field(
        default=True,
        description="If set to true, the report includes the screenshots of the submitted URL or looked-up hash "
        "(the top-level samples only — never of their child samples).",
    )


class Report(BaseModel):
    """The full report, as written to the file behind BuildReport's `report_path`."""

    samples: list[ReportSample] = Field(default_factory=list)
    errors: dict[str, str] = Field(
        default_factory=dict,
        description="Samples that could not be fetched at all, keyed by sample_id — or by 'submission:<id>' when "
        "the submission itself could not be resolved to a sample.",
    )


class BuildReportResults(BaseModel):
    """Only a summary travels inline. The report itself — screenshots included — can be megabytes, far over
    Sekoia's limit on action arguments (SYM216), so it is written to data_path and passed on as a file."""

    report_path: str = Field(
        ...,
        description="Path (relative to data_path) of the full report JSON — give it to Render report and "
        "Extract IOCs as `report_path`.",
    )
    sample_ids: list[int] = Field(default_factory=list, description="Samples in the report.")
    errors: dict[str, str] = Field(
        default_factory=dict,
        description="Samples that could not be fetched at all, keyed by sample_id — or by 'submission:<id>' when "
        "the submission itself could not be resolved to a sample.",
    )


# --------------------------------------------------------------------------
# Indicators — IOCSet: the `iocs` object of GET /sample/{id}/iocs;
# Indicator: one entry for add_ioc_to_ioc_collection
# --------------------------------------------------------------------------


class IOCSet(BaseModel):
    """The `iocs` object from GET /sample/{id}/iocs. Keys per the spec's
    documented ioc_type filter values."""

    model_config = {"extra": "allow"}

    files: list[dict[str, Any]] = Field(default_factory=list)
    filenames: list[dict[str, Any]] = Field(default_factory=list)
    mutexes: list[dict[str, Any]] = Field(default_factory=list)
    registry: list[dict[str, Any]] = Field(default_factory=list)
    urls: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[dict[str, Any]] = Field(default_factory=list)
    ips: list[dict[str, Any]] = Field(default_factory=list)
    emails: list[dict[str, Any]] = Field(default_factory=list)
    email_addresses: list[dict[str, Any]] = Field(default_factory=list)
    processes: list[dict[str, Any]] = Field(default_factory=list)


class Indicator(BaseModel):
    """One entry matching add_ioc_to_ioc_collection's expected shape."""

    value: str
    type: str


# --------------------------------------------------------------------------
# NOTE: there is no RevokeIndicators action here.
#
# DELETE /v2/inthreat/ioc-collections/{uuid}/indicators/{id} is a SEKOIA
# endpoint (Intelligence Center), not a VMRay one — this module's
# configuration only carries VMRay credentials. It was originally drafted
# into this module by mistake; every module in this ecosystem is
# vendor-scoped (Glimps only calls Glimps, Sekoia.io only calls Sekoia), so
# indicator revocation belongs in the Sekoia.io module as a second
# contributed action, alongside "Patch Alert Custom Fields" — see the
# design doc's open items.
# --------------------------------------------------------------------------
