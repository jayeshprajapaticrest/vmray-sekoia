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
        default=None, description="Path (on data_path) to a Build report result saved as JSON."
    )


class RenderReportArguments(ReportInput):
    pass


class RenderReportResults(BaseModel):
    content: str = Field(..., description="Markdown, ready for post-alerts/{uuid}/comments.")


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
