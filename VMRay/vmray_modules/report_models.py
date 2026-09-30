"""Models for the actions that consume a BuildReport result (RenderReport,
ReportToIndicators). The report itself keeps the Cortex-Analyzers VMRay
analyzer's nested shape, so it is taken here as a plain dict."""

from typing import Any

from pydantic import BaseModel, Field

from vmray_modules.models import Indicator


class ReportInput(BaseModel):
    report: dict[str, Any] | None = Field(
        default=None, description="A Build report result ({samples, errors}), given inline."
    )
    report_path: str | None = Field(
        default=None, description="Path (on data_path) of the report file — Build report's `report_path`."
    )


class RenderReportArguments(ReportInput):
    max_comment_kb: int = Field(
        default=256,
        description="Maximum size (KB) of each screenshot comment. Sekoia rejects playbook action arguments above "
        "an undocumented size (SYM216), so screenshots are split across comments that each stay under this.",
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


class ReportToIndicatorsArguments(ReportInput):
    verdicts: list[str] = Field(
        default_factory=lambda: ["malicious"],
        description="Only samples whose sample_verdict is one of these contribute indicators — child samples "
        "are judged on their own verdict. Empty = every sample.",
    )
    include_child_samples: bool = Field(
        default=True, description="Also take IOCs from child samples, and add each child sample's own SHA256."
    )


class ReportToIndicatorsResults(BaseModel):
    indicators: list[Indicator] = Field(default_factory=list)
