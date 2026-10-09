"""Models for the actions that consume a BuildReport result (RenderReport,
ExtractIocs). The report itself keeps the Cortex-Analyzers VMRay analyzer's
nested shape, so it is taken here as a plain dict."""

from typing import Any

from pydantic import BaseModel, Field
from pydantic.json_schema import SkipJsonSchema

from vmray_modules.models import Indicator, hide_empty_defaults


class ReportInput(BaseModel):
    model_config = {"json_schema_extra": hide_empty_defaults}

    report_path: str | SkipJsonSchema[None] = Field(
        default=None,
        title="Report path",
        description="The report file written by Build report — its `report_path` result.",
    )
    report: dict[str, Any] | SkipJsonSchema[None] = Field(
        default=None,
        title="Report (inline)",
        description="The report itself — only used when Report path is empty. Only for small reports: a report "
        "with screenshots exceeds Sekoia's size limit on action inputs.",
    )


class RenderReportArguments(ReportInput):
    max_comment_kb: int = Field(
        default=512,
        ge=16,
        title="Max comment size (KB)",
        description="Maximum size of each screenshot comment. Screenshots are split across as many comments as "
        "needed to stay under it — Sekoia rejects larger action inputs (SYM216).",
    )


class RenderReportResults(BaseModel):
    content: str = Field(
        ..., description="The report as markdown, without screenshot images — ready for post-alerts/{uuid}/comments."
    )
    screenshot_comments: list[str] = Field(
        default_factory=list,
        description="The screenshots, split into comments of at most max_comment_kb each — post one comment per item "
        "(a Foreach over this list). Empty when the report has no screenshots.",
    )


class ExtractIocsArguments(ReportInput):
    ioc_severity_filter: list[str] = Field(
        default_factory=lambda: ["malicious"],
        title="IOC severity filter",
        description="Restrict which IOC severities are extracted. Allowed values: 'malicious', 'suspicious'. "
        "Leave empty to extract every IOC, whatever its severity. A child sample's own SHA256 is extracted when "
        "its verdict is one of these values.",
    )
    include_child_iocs: bool = Field(
        default=True,
        title="Include child IOCs",
        description="If set to true, IOCs discovered in child samples, and each child sample's own SHA256, are "
        "extracted (in addition to root-sample IOCs). Set to false to only extract IOCs from the root sample.",
    )


class IndicatorGroup(BaseModel):
    """One add_ioc_to_ioc_collection call: its indicator_type and the values to push."""

    type: str = Field(..., description="Sekoia indicator_type: IP address, domain, url, email or hash.")
    indicators: list[str] = Field(default_factory=list)


class ExtractIocsResults(BaseModel):
    indicators: list[Indicator] = Field(default_factory=list)
    indicator_groups: list[IndicatorGroup] = Field(
        default_factory=list,
        description="The same indicators grouped by type, one group per non-empty type — Add IOC to IOC Collection "
        "takes a single indicator_type per call, so a Foreach over this list pushes every type with one node.",
    )
