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
# Shared VMRay-shaped building blocks
# --------------------------------------------------------------------------


class ThreatIndicator(BaseModel):
    """One entry from GET /sample/{id}/vtis -> threat_indicators[]."""

    model_config = {"extra": "allow"}  # VTI rule shape is not fully pinned yet

    category: str | None = None
    operation: str | None = None
    classification: list[str] | None = None
    id: int | None = None


class MitreAttackTechnique(BaseModel):
    """One entry from GET /sample/{id}/mitre_attack -> mitre_attack_techniques[]."""

    model_config = {"extra": "allow"}

    id: str | None = None
    name: str | None = None
    tactics: list[str] | None = None


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


class SampleChildRelation(BaseModel):
    """One entry from GET /sample/{id} -> sample_child_relations[]."""

    model_config = {"extra": "allow"}

    child_sample_id: int | None = None
    relation_type: str | None = None


class AnalysisRun(BaseModel):
    """One entry from GET /analysis/sample/{id} -> a single VM-profile analysis
    run. A sample can carry several of these (different sandbox profiles/
    platforms); each has its own verdict, distinct from the aggregate
    `sample_verdict` on the base sample object."""

    model_config = {"extra": "allow"}

    analysis_id: int | None = None
    analysis_verdict: str | None = None
    analysis_severity: str | None = None
    analysis_vti_score: int | None = None
    analysis_configuration_name: str | None = None
    analysis_created: str | None = None
    analysis_job_id: int | None = None


# --------------------------------------------------------------------------
# Analysis details — the assembled shape `GetAnalysisDetails` returns.
#
# This is the module's one results contract: every pure-transform action and
# every playbook Jinja expression downstream reads THIS shape, regardless of
# how many VMRay calls actually produced it (base sample object + /vtis +
# /iocs + /mitre_attack, run concurrently — see design doc "Aggregation
# belongs in the module, not the playbook").
# --------------------------------------------------------------------------


class AnalysisDetails(BaseModel):
    # from GET /sample/{id} -- verdict, identity, lineage
    sample_id: int
    sample_verdict: str | None = None
    sample_verdict_reason_code: str | None = None
    sample_verdict_reason_description: str | None = None
    sample_score: int | None = None
    sample_severity: str | None = None
    sample_vti_score: int | None = None
    sample_highest_vti_score: int | None = None

    sample_threat_names: list[str] = Field(default_factory=list)
    sample_classifications: list[str] = Field(default_factory=list)

    sample_sha256hash: str | None = None
    sample_sha1hash: str | None = None
    sample_md5hash: str | None = None
    sample_ssdeephash: str | None = None

    sample_filename: str | None = None
    sample_filesize: int | None = None
    sample_type: str | None = None
    sample_webif_url: str | None = None
    sample_display_url: str | None = None

    sample_child_sample_ids: list[int] = Field(default_factory=list)
    sample_child_relations: list[SampleChildRelation] = Field(default_factory=list)
    sample_child_relations_truncated: bool = False

    # from GET /sample/{id}/vtis
    threat_indicators: list[ThreatIndicator] = Field(default_factory=list)

    # from GET /sample/{id}/iocs
    iocs: IOCSet = Field(default_factory=IOCSet)

    # from GET /sample/{id}/mitre_attack
    mitre_attack_techniques: list[MitreAttackTechnique] = Field(default_factory=list)

    # from GET /analysis/sample/{id} -- one entry per VM-profile analysis run
    sample_analyses: list[AnalysisRun] = Field(default_factory=list)

    # submission/analysis provenance, not sample-scoped
    submission_id: int | None = None
    analysis_id: int | None = None
    submission_consumed_quota: int | None = None
    submission_finished: bool | None = None

    # partial-failure map: {"vtis": "timed out", ...}. Empty on a clean run.
    errors: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# Submission-time VMRay options, shared by every submitting action
# --------------------------------------------------------------------------


class SubmissionOptions(BaseModel):
    """Optional POST /sample/submit form fields. `None` means "not sent" — the
    VMRay user's own analyzer settings apply. `net_scheme_name` is not a form
    field: it rides inside the `user_config` JSON string."""

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


# --------------------------------------------------------------------------
# SubmitAndWait
# --------------------------------------------------------------------------


class SubmitAndWaitArguments(SubmissionOptions):
    # Only URL and file are real detonation inputs (decided observable scope:
    # hash is a zero-cost lookup via SearchSample, never a submission here).
    # A bare sample_id "reanalyze" path was drafted early on but needs
    # POST /analysis/{analysis_id}/reanalyze, keyed by analysis_id, resolved
    # through an endpoint this module doesn't implement — dropped rather than
    # built on an unconfirmed foundation.
    sample_url: str | None = Field(default=None, description="URL to detonate. Mutually exclusive with file_name.")
    file_name: str | None = Field(
        default=None, description="Name of a file already staged under the action's data_path to submit."
    )
    reanalyze: bool = Field(default=False, description="Force a fresh detonation even if a cached result exists.")
    analysis_caching: bool = Field(
        default=True, description="Allow VMRay to return a cached result instead of a fresh detonation."
    )
    tags: list[str] = Field(default_factory=lambda: ["sekoia"])
    timeout: float = Field(default=1800, description="Maximum time (seconds) to wait for the analysis to finish.")
    pull_time: float = Field(default=10, description="Time (seconds) between polls of the submission status.")
    push_timeout: float = Field(default=30, description="Maximum time (seconds) to wait for the initial submit call.")


class SubmitAndWaitResults(BaseModel):
    submission_id: int | None = None  # None only if the submission itself failed — see `errors`
    sample_id: int | None = None
    sample_verdict: str | None = None
    sample_vti_score: int | None = None
    sample_webif_url: str | None = None
    timed_out: bool = False
    errors: list[dict[str, str]] = Field(default_factory=list)


# --------------------------------------------------------------------------
# GetAnalysisDetails
# --------------------------------------------------------------------------


class GetAnalysisDetailsArguments(BaseModel):
    sample_id: int = Field(..., description="VMRay sample_id to fetch details for.")
    include_vtis: bool = Field(default=True)
    include_iocs: bool = Field(default=True)
    include_mitre_attack: bool = Field(default=True)
    include_recursive: bool = Field(
        default=False,
        description="Also fetch recursive children's threat_names/classifications "
        "(2026.2+ only, costs two extra calls).",
    )
    include_analyses: bool = Field(
        default=False,
        description="Also fetch per-VM-profile analysis runs (GET /analysis/sample/{id}), costs one extra call.",
    )
    ioc_severity_filter: str | None = Field(
        default=None,
        description="Restrict fetched IOCs to this severity server-side (VMRay's documented values: "
        "'malicious' or 'suspicious'). Leave empty to fetch all severities.",
    )
    analysis_verdict_filter: list[str] = Field(
        default_factory=list,
        description="Only include analysis runs (requires include_analyses) whose analysis_verdict is one of "
        "these values (e.g. ['malicious', 'suspicious']). Filtered client-side, after fetch. Empty = no filtering.",
    )


# GetAnalysisDetailsResults == AnalysisDetails, reused directly.

# --------------------------------------------------------------------------
# SubmitAndEnrich — composite of SubmitAndWait + GetAnalysisDetails
# --------------------------------------------------------------------------


class SubmitAndEnrichArguments(SubmitAndWaitArguments):
    include_vtis: bool = Field(default=True)
    include_iocs: bool = Field(default=True)
    include_mitre_attack: bool = Field(default=True)
    include_recursive: bool = Field(default=False)
    include_analyses: bool = Field(default=False)
    ioc_severity_filter: str | None = Field(default=None)
    analysis_verdict_filter: list[str] = Field(default_factory=list)


class SubmitAndEnrichResults(BaseModel):
    """Not just AnalysisDetails reused directly (the original sketch) — that
    breaks on a failed submission, since AnalysisDetails.sample_id is
    required and a failed submission never gets one. Same honesty fix as
    SubmitAndWaitResults.submission_id needed. `analysis` is populated only
    once the submission actually finished."""

    submission_id: int | None = None
    sample_id: int | None = None
    timed_out: bool = False
    submission_errors: list[dict[str, str]] = Field(default_factory=list)
    analysis: AnalysisDetails | None = None


# --------------------------------------------------------------------------
# SubmitUrl / SubmitFile
# --------------------------------------------------------------------------


class SubmitUrlArguments(SubmissionOptions):
    sample_url: str = Field(..., description="URL to submit for detonation.")
    reanalyze: bool = Field(default=False)
    analysis_caching: bool = Field(default=True)
    tags: list[str] = Field(
        default_factory=lambda: ["sekoia"],
        description="Tags applied to the VMRay submission, for audit trail on the VMRay side.",
    )


class SubmitFileArguments(SubmissionOptions):
    file_name: str = Field(..., description="Name of the file, staged under the action's data_path, to submit.")
    reanalyze: bool = Field(default=False)
    analysis_caching: bool = Field(default=True)
    tags: list[str] = Field(
        default_factory=lambda: ["sekoia"],
        description="Tags applied to the VMRay submission, for audit trail on the VMRay side.",
    )


class SubmitResults(BaseModel):
    submission_id: int | None = None
    sample_id: int | None = None
    job_ids: list[int] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)


# --------------------------------------------------------------------------
# SearchSample
# --------------------------------------------------------------------------


class SearchSampleArguments(BaseModel):
    hash: str = Field(..., description="SHA256, SHA1 or MD5 of the sample to look up.")


class SearchSampleResults(BaseModel):
    found: bool
    analysis: AnalysisDetails | None = None


# --------------------------------------------------------------------------
# IocsToIndicators (pure transform)
# --------------------------------------------------------------------------


class IocsToIndicatorsArguments(BaseModel):
    iocs_path: str | None = Field(default=None, description="Path (on data_path) to an AnalysisDetails JSON file.")
    iocs: dict[str, Any] | None = Field(default=None, description="AnalysisDetails object, given inline instead.")


class Indicator(BaseModel):
    """One entry matching add_ioc_to_ioc_collection's expected shape."""

    value: str
    type: str  # one of: "IP address", "domain", "url", "email", "hash"


class IocsToIndicatorsResults(BaseModel):
    indicators: list[Indicator] = Field(default_factory=list)


# --------------------------------------------------------------------------
# RenderSummary (pure transform)
# --------------------------------------------------------------------------


class RenderSummaryArguments(BaseModel):
    analysis_path: str | None = Field(default=None, description="Path (on data_path) to an AnalysisDetails JSON file.")
    analysis: dict[str, Any] | None = Field(default=None, description="AnalysisDetails object, given inline instead.")


class RenderSummaryResults(BaseModel):
    content: str = Field(..., description="Markdown, ready for post-alerts/{uuid}/comments.")


# --------------------------------------------------------------------------
# GetSample / GetReportPdf
# --------------------------------------------------------------------------


class GetSampleArguments(BaseModel):
    sample_id: int = Field(...)
    encryption_password: str | None = Field(
        default=None, description="Password to protect the returned ZIP with. VMRay defaults if omitted."
    )


class GetSampleResults(BaseModel):
    file_path: str = Field(..., description="Path (relative to data_path) of the downloaded, encrypted ZIP.")


class GetReportPdfArguments(BaseModel):
    sample_id: int = Field(...)


class GetReportPdfResults(BaseModel):
    file_path: str = Field(..., description="Path (relative to data_path) of the downloaded PDF report.")


class GetScreenshotsArguments(BaseModel):
    analysis_id: int = Field(..., description="VMRay analysis_id (not sample_id) to fetch screenshots for.")
    encryption_password: str | None = Field(
        default=None, description="Password to protect the returned ZIP with, if the archive requires one."
    )


class GetScreenshotsResults(BaseModel):
    file_path: str = Field(..., description="Path (relative to data_path) of the downloaded screenshots ZIP.")


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
