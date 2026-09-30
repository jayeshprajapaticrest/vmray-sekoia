"""BuildReport — the Cortex-Analyzers VMRay analyzer's `_build_report`.

Takes samples (e.g. from GetSamplesByHash) or submissions (e.g. from
SubmitUrlSample), fetches every sample again — lookup and submit responses are
incomplete — and attaches, per sample, the same sub-resources as the analyzer's
`_build_sample_node`: analyses of the latest submission, VTIs, MITRE ATT&CK,
IOCs, classifications, threat names and screenshots, then recurses into child
samples down to `max_recursion_depth`.

Screenshots follow the analyzer's `_fetch_screenshots`: per analysis (newest
first) read `logs/summary.json` from the analysis archive, fetch each listed
screenshot, compress it to JPEG and embed it as base64 until one report-wide
size budget runs out. Sekoia has no attachment API, so embedding is the only way
a screenshot reaches the alert comment.

Deliberately left out versus the analyzer: sample-file downloads. Unlike the
analyzer, one failing call does not abort the report: it lands in that sample's
`errors` and every other section is still filled.
"""

import base64
import io
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from PIL import Image, UnidentifiedImageError
from requests import RequestException
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClient, VMRayClientError
from vmray_modules.models import BuildReportArguments, BuildReportResults

_MAX_WORKERS = 4

# Smaller than the analyzer's 1280px / quality 82: a Sekoia comment cannot zoom an
# image the way TheHive's modal does, and a smaller image fits more of them in the budget.
_SCREENSHOT_MAX_WIDTH = 800
_SCREENSHOT_QUALITY = 75


def run_concurrently(tasks: dict[str, Callable[[], Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Run each task in parallel; failures land in the errors map instead of aborting the rest."""
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_to_name = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                errors[name] = str(exc)
    return results, errors


@dataclass
class ScreenshotBudget:
    """Base64 bytes still allowed across the whole report — shared by every sample, as in the analyzer."""

    remaining: int


def _compress_screenshot(img_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    if img.width > _SCREENSHOT_MAX_WIDTH:
        ratio = _SCREENSHOT_MAX_WIDTH / img.width
        img = img.resize((_SCREENSHOT_MAX_WIDTH, int(img.height * ratio)), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=_SCREENSHOT_QUALITY, optimize=True)
    return buf.getvalue()


def _should_fetch_screenshots(mode: str, level: int) -> bool:
    if mode == "none":
        return False
    if mode == "parent_only":
        return level == 0
    return True


def fetch_screenshots(client: VMRayClient, sample: dict[str, Any], budget: ScreenshotBudget) -> None:
    """Embed each analysis's screenshots into `analysis_screenshots` ([{name, data}]), newest analysis first."""
    truncated = False
    analyses = sample.get("sample_analyses") or []
    analyses.sort(key=lambda analysis: analysis.get("analysis_created") or "", reverse=True)

    for analysis in analyses:
        analysis["analysis_screenshots"] = []
        if truncated:
            continue
        analysis_id = analysis.get("analysis_id")
        try:
            summary = json.loads(client.get_analysis_archive_file(analysis_id, "logs/summary.json"))
        except (VMRayClientError, RequestException, ValueError):
            continue  # e.g. a static analysis has no screenshots — optional, never fails the report
        for entry in summary.get("screenshots") or []:
            archive_path = entry.get("screenshot_archive_path")
            if not archive_path:
                continue
            try:
                img_bytes = _compress_screenshot(client.get_analysis_archive_file(analysis_id, archive_path))
            except (VMRayClientError, RequestException, UnidentifiedImageError, OSError):
                continue  # one unreadable screenshot must not cost the rest
            b64 = base64.b64encode(img_bytes).decode("ascii")
            if len(b64) > budget.remaining:
                truncated = True
                break
            budget.remaining -= len(b64)
            analysis["analysis_screenshots"].append({"name": archive_path.removeprefix("screenshots/"), "data": b64})

    sample["screenshots_truncated"] = truncated
    sample["has_screenshots"] = any(a.get("analysis_screenshots") for a in analyses)


def build_sample_node(
    client: VMRayClient, sample: dict[str, Any], level: int, arguments: BuildReportArguments, budget: ScreenshotBudget
) -> None:
    sample_id = sample["sample_id"]
    tasks: dict[str, Callable[[], Any]] = {
        "sample_analyses": lambda: client.get_sample_analyses(sample_id, verdicts=arguments.analysis_verdict_filter),
        "sample_threat_indicators": lambda: client.get_sample_threat_indicators(sample_id),
        "sample_mitre_attack": lambda: client.get_sample_mitre_attack(sample_id),
        "sample_iocs": lambda: client.get_sample_iocs(sample_id, severity=arguments.ioc_severity_filter),
        "sample_classifications": lambda: client.get_sample_classifications(sample_id),
        "sample_threat_names": lambda: client.get_sample_threat_names(sample_id),
    }
    # a failed classifications/threat_names call leaves the sample object's own values in place
    results, errors = run_concurrently(tasks)
    sample.update(results)

    if _should_fetch_screenshots(arguments.screenshot_mode, level):
        fetch_screenshots(client, sample, budget)

    if arguments.max_recursion_depth > level:
        children = []
        for child_id in sample.get("sample_child_sample_ids") or []:
            try:
                child = client.get_sample(child_id)
            except VMRayClientError as exc:
                errors[f"child_sample:{child_id}"] = str(exc)
                continue
            build_sample_node(client, child, level + 1, arguments, budget)
            children.append(child)
        sample["sample_child_samples"] = children

    sample["errors"] = errors


class BuildReport(VMRayAction):
    name = "Build report"
    description = (
        "Build the full VMRay report for samples or submissions: analyses, VTIs, MITRE ATT&CK, IOCs, "
        "classifications, threat names and screenshots per sample, including child samples."
    )
    results_model = BuildReportResults

    def run(self, arguments: BuildReportArguments) -> BuildReportResults:
        if arguments.samples:
            sample_ids = [s.get("sample_id") for s in arguments.samples]
        elif arguments.submissions:
            sample_ids = [s.get("submission_sample_id") for s in arguments.submissions]
        else:
            raise MissingActionArgumentError("samples or submissions")

        budget = ScreenshotBudget(remaining=arguments.screenshot_budget_kb * 1024)
        samples: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        for sample_id in dict.fromkeys(i for i in sample_ids if i is not None):
            try:
                sample = self.client.get_sample(sample_id)
            except VMRayClientError as exc:
                errors[str(sample_id)] = str(exc)
                continue
            build_sample_node(self.client, sample, 0, arguments, budget)
            samples.append(sample)

        return BuildReportResults.model_validate({"samples": samples, "errors": errors})
