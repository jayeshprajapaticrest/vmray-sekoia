"""BuildReport — the Cortex-Analyzers VMRay analyzer's `_build_report`.

Takes sample IDs (e.g. from GetSamplesByHash) or submission IDs (e.g. from
SubmitUrlSample, each resolved to its sample), fetches every sample — lookup and
submit responses are incomplete, so the analyzer refetches them too — and
attaches, per sample, the same sub-resources as the analyzer's
`_build_sample_node`: analyses of the latest submission, VTIs, MITRE ATT&CK,
IOCs, classifications, threat names and screenshots, then recurses into child
samples down to `max_recursion_depth`.

Screenshots follow the analyzer's `_fetch_screenshots`: per analysis (newest
first) read `logs/summary.json` from the analysis archive, fetch each listed
screenshot, compress it to JPEG and embed it as base64. Sekoia has no
attachment API, so embedding is the only way a screenshot reaches the alert
comment. Unlike the analyzer there is no report-wide size budget: RenderReport
splits the screenshots across as many comments as they need.

The report is written to a JSON file on data_path and only its path is returned
(`report_path`): with screenshots it easily exceeds Sekoia's size limit on action
arguments (SYM216), so the next nodes must receive it as a file, not inline.

Deliberately left out versus the analyzer: sample-file downloads. Unlike the
analyzer, one failing call does not abort the report: it lands in that sample's
`errors` and every other section is still filled.
"""

import base64
import io
import json
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import orjson
from PIL import Image, UnidentifiedImageError
from requests import RequestException
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClient, VMRayClientError
from vmray_modules.models import BuildReportArguments, BuildReportResults, Report

_MAX_WORKERS = 4

# Smaller than the analyzer's 1280px / quality 82: a Sekoia comment cannot zoom an
# image the way TheHive's modal does, and a smaller image fits more of them in a comment.
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


def fetch_screenshots(client: VMRayClient, sample: dict[str, Any]) -> None:
    """Embed each analysis's screenshots into `analysis_screenshots` ([{name, data}]), newest analysis first."""
    analyses = sample.get("sample_analyses") or []
    analyses.sort(key=lambda analysis: analysis.get("analysis_created") or "", reverse=True)

    for analysis in analyses:
        analysis["analysis_screenshots"] = []
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
            analysis["analysis_screenshots"].append({"name": archive_path.removeprefix("screenshots/"), "data": b64})

    sample["has_screenshots"] = any(a.get("analysis_screenshots") for a in analyses)


def build_sample_node(
    client: VMRayClient, sample: dict[str, Any], level: int, arguments: BuildReportArguments
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
        fetch_screenshots(client, sample)

    if arguments.max_recursion_depth > level:
        children = []
        for child_id in sample.get("sample_child_sample_ids") or []:
            try:
                child = client.get_sample(child_id)
            except VMRayClientError as exc:
                errors[f"child_sample:{child_id}"] = str(exc)
                continue
            build_sample_node(client, child, level + 1, arguments)
            children.append(child)
        sample["sample_child_samples"] = children

    sample["errors"] = errors


class BuildReport(VMRayAction):
    name = "Build report"
    description = (
        "Build the full VMRay report for sample IDs or submission IDs: analyses, VTIs, MITRE ATT&CK, IOCs, "
        "classifications, threat names and screenshots per sample, including child samples."
    )
    results_model = BuildReportResults

    def _resolve_submissions(self, submission_ids: list[int], errors: dict[str, str]) -> list[int | None]:
        sample_ids: list[int | None] = []
        for submission_id in dict.fromkeys(submission_ids):
            try:
                sample_ids.append(self.client.update_submission(submission_id).get("submission_sample_id"))
            except VMRayClientError as exc:
                errors[f"submission:{submission_id}"] = str(exc)
        return sample_ids

    def run(self, arguments: BuildReportArguments) -> BuildReportResults:
        errors: dict[str, str] = {}
        sample_ids: list[int | None]
        if arguments.sample_ids:
            sample_ids = list(arguments.sample_ids)
        elif arguments.submission_ids:
            sample_ids = self._resolve_submissions(arguments.submission_ids, errors)
        else:
            raise MissingActionArgumentError("sample_ids or submission_ids")

        samples: list[dict[str, Any]] = []
        for sample_id in dict.fromkeys(i for i in sample_ids if i is not None):
            try:
                sample = self.client.get_sample(sample_id)
            except VMRayClientError as exc:
                errors[str(sample_id)] = str(exc)
                continue
            build_sample_node(self.client, sample, 0, arguments)
            samples.append(sample)

        report = Report.model_validate({"samples": samples, "errors": errors})
        filename = f"vmray-report-{uuid.uuid4()}.json"
        self.data_path.joinpath(filename).write_bytes(orjson.dumps(report.model_dump(mode="json")))

        return BuildReportResults(
            report_path=filename, sample_ids=[s.sample_id for s in report.samples], errors=report.errors
        )
