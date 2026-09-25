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

from pydantic import BaseModel, Field
from sekoia_automation.module import Module

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
    """Optional POST /sample/submit form fields. `None` means "not sent" — the
    VMRay user's own analyzer settings apply. `net_scheme_name` and
    `analysis_timeout` are not form fields: they ride inside the `user_config`
    JSON string (as `net_scheme_name` and `timeout`)."""

    enable_reputation: bool | None = Field(
        default=None,
        description="Run Reputation Analysis on the sample and its artifacts (hashes and URLs only are sent "
        "to third-party services, never the file itself).",
    )
    enable_whois: bool | None = Field(
        default=None, description="Query domains seen during analysis against an external WHOIS service."
    )
    analyzer_mode: str | None = Field(
        default=None,
        description="Analysis types to run: 'reputation', 'reputation_static', 'reputation_static_dynamic', "
        "'static_dynamic' or 'static'.",
    )
    known_malicious: bool | None = Field(
        default=None, description="Let Triage pre-filter known malicious samples (reputation + static)."
    )
    known_benign: bool | None = Field(
        default=None, description="Let Triage pre-filter known benign samples (reputation + static)."
    )
    max_jobs: int | None = Field(
        default=None, description="Cap on jobs Jobrules may create for this submission — bounds quota spend."
    )
    archive_action: str | None = Field(
        default=None,
        description="How a submitted archive is handled: 'sample', 'compound_sample' or 'separate_samples'.",
    )
    archive_password: str | None = Field(
        default=None, description="Password of a submitted password-protected archive, if not a common one."
    )
    shareable: bool = Field(
        default=False,
        description="Share the sample's hash with VirusTotal. Always sent; off unless explicitly enabled.",
    )
    net_scheme_name: str | None = Field(
        default=None, description="Network scheme for the analysis VM (e.g. 'Isolated'), sent via user_config."
    )
    analysis_timeout: int | None = Field(
        default=None, description="Analysis timeout in seconds on the VMRay side, sent via user_config."
    )
    max_recursive_samples: int | None = Field(
        default=None, description="Maximum number of recursive (child) samples VMRay may create and analyse."
    )


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
    sample_url: str = Field(..., description="URL to submit for detonation.")
    tags: list[str] = Field(
        default_factory=lambda: ["sekoia"],
        description="Tags applied to the VMRay submission, for audit trail on the VMRay side.",
    )
    reanalyze: bool = Field(default=True, description="Force a fresh analysis even if VMRay already knows the URL.")
    query_retry_wait: float = Field(default=10, description="Seconds to wait between polls of the submission status.")
    timeout: float = Field(default=1800, description="Maximum time (seconds) to wait for every submission to finish.")


class SubmitUrlSampleResults(BaseModel):
    submissions: list[Submission] = Field(default_factory=list, description="Finished submissions.")
    sample_ids: list[int] = Field(
        default_factory=list, description="Distinct sample_ids of the finished submissions — input for the report."
    )
    pending_submission_ids: list[int] = Field(
        default_factory=list, description="Submissions still running when the wait timed out."
    )
    timed_out: bool = False
    errors: list[dict[str, str]] = Field(default_factory=list, description="Errors VMRay returned on submit.")


# --------------------------------------------------------------------------
# GetSamplesByHash — lookup only; building the full report is a separate action
# --------------------------------------------------------------------------


class GetSamplesByHashArguments(BaseModel):
    hashes: list[str] = Field(
        ..., description="SHA256, SHA1 or MD5 hashes to look up. Duplicates are ignored. Costs no quota."
    )


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
    errors: dict[str, str] = Field(
        default_factory=dict, description="Sections of this sample that failed to load; the rest is still filled."
    )


class BuildReportArguments(BaseModel):
    samples: list[dict[str, Any]] | None = Field(
        default=None, description="Sample objects carrying sample_id — e.g. the `samples` of Get samples by hash."
    )
    submissions: list[dict[str, Any]] | None = Field(
        default=None,
        description="Submission objects carrying submission_sample_id — e.g. the `submissions` of Submit URL "
        "sample. Used when `samples` is empty.",
    )
    max_recursion_depth: int = Field(
        default=1,
        description="How many levels of child samples get a full report. 0 = only the given samples, "
        "1 = also their direct children. Each level multiplies the API calls.",
    )
    ioc_severity_filter: str | None = Field(
        default=None,
        description="Restrict fetched IOCs to this severity server-side ('malicious' or 'suspicious'). "
        "Empty = all severities.",
    )
    analysis_verdict_filter: list[str] = Field(
        default_factory=list,
        description="Only keep analyses whose analysis_verdict is one of these values. Empty = keep all.",
    )


class BuildReportResults(BaseModel):
    samples: list[ReportSample] = Field(default_factory=list)
    errors: dict[str, str] = Field(
        default_factory=dict, description="Samples that could not be fetched at all, keyed by sample_id."
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
