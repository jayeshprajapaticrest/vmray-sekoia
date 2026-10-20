"""BuildReport — the full VMRay report for a set of samples.

Takes sample IDs (e.g. from GetSamplesByHash) or submission IDs (e.g. from SubmitUrlSample, each resolved to its
sample), fetches every sample — lookup and submit responses are incomplete — and attaches, per sample, its
sub-resources: analyses of the latest submission, VTIs, MITRE ATT&CK, IOCs, classifications, threat names and
screenshots, then recurses into child samples down to `max_recursion_depth`. Child samples only get their IOCs —
the rest of their sections is used nowhere. Every call is made one after another.

Screenshots: per analysis (newest first), read `logs/summary.json` from the analysis archive, fetch each listed
screenshot, compress it to JPEG and embed it as base64. Sekoia has no attachment API, so embedding is the only way a
screenshot reaches the alert comment. There is no report-wide size budget: RenderReport splits the screenshots
across as many comments as they need. A screenshot that cannot be fetched or read is named in the sample's `errors`.

The report is written to a JSON file on data_path and only its path is returned (`report_path`): with screenshots
it easily exceeds Sekoia's size limit on action arguments (SYM216), so the next nodes must receive it as a file,
not inline.

Deliberately left out: sample-file downloads. One failing call does not abort the report: it lands in that
sample's `errors` and every other section is still filled.
"""

import base64
import io
import json
import uuid
from collections.abc import Callable
from typing import Any

import orjson
from PIL import Image, UnidentifiedImageError
from pydantic import ValidationError
from requests import RequestException
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.client import BadResponseError, VMRayClient, VMRayClientError
from vmray_modules.models import BuildReportArguments, BuildReportResults, Report, ReportSample

# 800px wide so more fit in a comment; quality 85 keeps text in the screenshot from
# blurring into JPEG artifacts.
_SCREENSHOT_MAX_WIDTH = 800
_SCREENSHOT_QUALITY = 85


def run_each(tasks: dict[str, Callable[[], Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Run each task in turn; a failure lands in the errors map instead of aborting the rest."""
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, task in tasks.items():
        try:
            results[name] = task()
        except Exception as exc:
            errors[name] = _describe(exc)
    return results, errors


def _describe(exc: Exception) -> str:
    """The error as shown in the report: VMRay's own message, or the exception type when it alone says what
    went wrong (a bare `str(KeyError('x'))` is just "'x'")."""
    return str(exc) if isinstance(exc, VMRayClientError) else f"{type(exc).__name__}: {exc}"


# Calls that can fail for one sample, section or screenshot without failing the report: VMRay's own errors, the
# network giving up after its retries, and a 200 response that is not the JSON it should be.
_RECOVERABLE = (VMRayClientError, RequestException, ValueError)

# A real screenshot is a few megapixels; anything far beyond is a broken or hostile image. Checked before
# decoding, so such an image is skipped instead of being decoded into memory.
_SCREENSHOT_MAX_PIXELS = 40_000_000


def _compress_screenshot(img_bytes: bytes) -> bytes:
    opened = Image.open(io.BytesIO(img_bytes))  # reads the size only — nothing is decoded yet
    if opened.width * opened.height > _SCREENSHOT_MAX_PIXELS:
        raise ValueError(f"screenshot too large: {opened.width}x{opened.height}")
    img: Image.Image = opened.convert("RGB")
    if img.width > _SCREENSHOT_MAX_WIDTH:
        ratio = _SCREENSHOT_MAX_WIDTH / img.width
        height = max(1, int(img.height * ratio))  # a very wide, thin image must not shrink to 0 px
        img = img.resize((_SCREENSHOT_MAX_WIDTH, height), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=_SCREENSHOT_QUALITY, optimize=True)
    return buf.getvalue()


def _should_fetch_screenshots(include: bool, level: int) -> bool:
    """Only the submitted or looked-up samples (level 0) get screenshots — never their child samples."""
    return include and level == 0


def fetch_screenshots(client: VMRayClient, sample: dict[str, Any]) -> dict[str, str]:
    """Embed each analysis's screenshots into `analysis_screenshots` ([{name, data}]), newest analysis first.

    Returns what could not be embedded, for the sample's `errors`: a screenshot list that could not be read, and
    each listed screenshot that could not be fetched or read. An analysis without a screenshot list (HTTP 404, e.g.
    a static analysis) simply has no screenshots and is not an error."""
    errors: dict[str, str] = {}
    analyses = sample.get("sample_analyses") or []
    analyses.sort(key=lambda analysis: analysis.get("analysis_created") or "", reverse=True)

    for analysis in analyses:
        analysis["analysis_screenshots"] = []
        analysis_id = analysis.get("analysis_id")
        try:
            summary = json.loads(client.get_analysis_archive_file(analysis_id, "logs/summary.json"))
        except BadResponseError as exc:
            if exc.status_code != 404:
                errors[f"screenshots:{analysis_id}"] = f"screenshot list could not be read: {_describe(exc)}"
            continue
        except _RECOVERABLE as exc:
            errors[f"screenshots:{analysis_id}"] = f"screenshot list could not be read: {_describe(exc)}"
            continue
        entries = summary.get("screenshots") if isinstance(summary, dict) else None
        if not isinstance(entries, list):
            if entries is not None or not isinstance(summary, dict):
                errors[f"screenshots:{analysis_id}"] = "screenshot list could not be read: unexpected format"
            continue
        unnamed = 0
        for entry in entries:
            archive_path = entry.get("screenshot_archive_path") if isinstance(entry, dict) else None
            if not isinstance(archive_path, str) or not archive_path:
                unnamed += 1
                continue
            name = archive_path.removeprefix("screenshots/")
            try:
                img_bytes = _compress_screenshot(client.get_analysis_archive_file(analysis_id, archive_path))
            except (*_RECOVERABLE, UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
                errors[f"screenshot:{analysis_id}/{name}"] = _describe(exc)  # the rest are still embedded
                continue
            b64 = base64.b64encode(img_bytes).decode("ascii")
            analysis["analysis_screenshots"].append({"name": name, "data": b64})
        if unnamed:
            errors[f"screenshots:{analysis_id}"] = f"{unnamed} listed screenshot(s) without a path"

    sample["has_screenshots"] = any(a.get("analysis_screenshots") for a in analyses)
    return errors


_IOC_SEVERITIES = ("malicious", "suspicious")
_ANALYSIS_VERDICTS = ("malicious", "suspicious", "clean")


def ioc_severity(values: list[str]) -> str | None:
    """Exactly one valid severity filters server-side; none or both fetch everything."""
    wanted = {v.strip().lower() for v in values if v and v.strip().lower() in _IOC_SEVERITIES}
    return wanted.pop() if len(wanted) == 1 else None


def analysis_verdicts(values: list[str]) -> list[str]:
    """Values other than malicious/suspicious/clean are ignored."""
    return sorted({v.strip().lower() for v in values if v and v.strip().lower() in _ANALYSIS_VERDICTS})


def check_filter(name: str, values: list[str], allowed: tuple[str, ...]) -> None:
    """A filter whose values are all invalid (e.g. the typo "malicous") is an error, as in Extract IOCs: ignoring
    it would silently report everything. A valid value next to an invalid one still filters, and the invalid one
    is ignored."""
    given = [v for v in values if v and v.strip()]
    if given and not any(v.strip().lower() in allowed for v in given):
        raise ValueError(f"{name} has no valid value: {values!r} — use {' and/or '.join(map(repr, allowed))}")


# what each section must be; anything else VMRay sends lands in the sample's errors instead
_SECTION_TYPES: dict[str, type] = {
    "sample_analyses": list,
    "sample_threat_indicators": dict,
    "sample_mitre_attack": dict,
    "sample_iocs": dict,
    "sample_classifications": list,
    "sample_threat_names": list,
}


def build_sample_node(
    client: VMRayClient,
    sample: dict[str, Any],
    level: int,
    arguments: BuildReportArguments,
    ancestors: frozenset[int] = frozenset(),
) -> None:
    """`ancestors` are the sample ids on the path from the top-level sample: a child that is one of them (VMRay
    data can point back up the tree) is recorded as an error and not built again, so the recursion ends.

    A top-level sample (level 0) gets every section. A child sample only gets its IOCs: the comment shows a child
    as one row of the child tree (from its sample object alone), and Extract IOCs reads its IOCs — its analyses,
    VTIs, MITRE ATT&CK, classifications and threat names are used nowhere, so they are not fetched (the top-level
    sample's classifications and threat names already include its children's)."""
    sample_id = sample["sample_id"]
    verdicts = analysis_verdicts(arguments.analysis_verdict_filter)
    severity = ioc_severity(arguments.ioc_severity_filter)
    tasks: dict[str, Callable[[], Any]] = {"sample_iocs": lambda: client.get_sample_iocs(sample_id, severity=severity)}
    if level == 0:
        tasks = {
            "sample_analyses": lambda: client.get_sample_analyses(sample_id, verdicts=verdicts),
            "sample_threat_indicators": lambda: client.get_sample_threat_indicators(sample_id),
            "sample_mitre_attack": lambda: client.get_sample_mitre_attack(sample_id),
            **tasks,
            "sample_classifications": lambda: client.get_sample_classifications(sample_id),
            "sample_threat_names": lambda: client.get_sample_threat_names(sample_id),
        }
    # a failed classifications/threat_names call leaves the sample object's own values in place
    results, errors = run_each(tasks)
    for name, value in results.items():
        if isinstance(value, _SECTION_TYPES[name]):
            sample[name] = value
        else:
            errors[name] = f"unexpected response from VMRay: {type(value).__name__}"

    if _should_fetch_screenshots(arguments.include_screenshots, level):
        errors.update(fetch_screenshots(client, sample))

    if arguments.max_recursion_depth > level:
        children = []
        path = ancestors | {sample_id}
        for child_id in dict.fromkeys(sample.get("sample_child_sample_ids") or []):
            if child_id in path:
                errors[f"child_sample:{child_id}"] = "already a parent of this sample — not built again"
                continue
            try:
                child = client.get_sample(child_id)
            except _RECOVERABLE as exc:
                errors[f"child_sample:{child_id}"] = _describe(exc)
                continue
            if not isinstance(child, dict) or "sample_id" not in child:
                errors[f"child_sample:{child_id}"] = "unexpected response from VMRay"
                continue
            build_sample_node(client, child, level + 1, arguments, path)
            children.append(child)
        sample["sample_child_samples"] = children

    sample["errors"] = errors


class BuildReport(VMRayAction):
    name = "Build Report"
    description = (
        "Build the full VMRay report for sample IDs or submission IDs: analyses, VTIs, MITRE ATT&CK, IOCs, "
        "classifications, threat names and screenshots per sample, plus its child samples with their IOCs."
    )
    results_model = BuildReportResults

    def _resolve_submissions(self, submission_ids: list[int], errors: dict[str, str]) -> list[int | None]:
        sample_ids: list[int | None] = []
        for submission_id in dict.fromkeys(submission_ids):
            try:
                submission = self.client.update_submission(submission_id)
            except _RECOVERABLE as exc:
                errors[f"submission:{submission_id}"] = _describe(exc)
                continue
            sample_id = submission.get("submission_sample_id") if isinstance(submission, dict) else None
            if sample_id is None:
                errors[f"submission:{submission_id}"] = "VMRay returned no sample for this submission"
                continue
            sample_ids.append(sample_id)
        return sample_ids

    def run(self, arguments: BuildReportArguments) -> BuildReportResults:
        check_filter("ioc_severity_filter", arguments.ioc_severity_filter, _IOC_SEVERITIES)
        check_filter("analysis_verdict_filter", arguments.analysis_verdict_filter, _ANALYSIS_VERDICTS)
        errors: dict[str, str] = {}
        sample_ids: list[int | None]
        if arguments.sample_ids:
            sample_ids = list(arguments.sample_ids)
        elif arguments.submission_ids:
            sample_ids = self._resolve_submissions(arguments.submission_ids, errors)
        else:
            raise MissingActionArgumentError("sample_ids or submission_ids")

        samples: list[ReportSample] = []
        for sample_id in dict.fromkeys(i for i in sample_ids if i is not None):
            try:
                sample = self.client.get_sample(sample_id)
            except _RECOVERABLE as exc:
                errors[str(sample_id)] = _describe(exc)
                continue
            if not isinstance(sample, dict) or "sample_id" not in sample:
                errors[str(sample_id)] = "unexpected response from VMRay"
                continue
            build_sample_node(self.client, sample, 0, arguments)
            try:  # one sample VMRay describes oddly must not cost the others
                samples.append(ReportSample.model_validate(sample))
            except ValidationError as exc:
                errors[str(sample_id)] = f"unexpected sample data from VMRay: {exc.error_count()} invalid field(s)"

        report = Report(samples=samples, errors=errors)
        filename = f"vmray-report-{uuid.uuid4()}.json"
        self.data_path.joinpath(filename).write_bytes(_dump(report.model_dump(mode="json")))

        return BuildReportResults(
            report_path=filename, sample_ids=[s.sample_id for s in report.samples], errors=report.errors
        )


def _dump(data: dict[str, Any]) -> bytes:
    try:
        return orjson.dumps(data)
    except TypeError:  # orjson refuses integers beyond 64 bits; VMRay data has none, but must not fail the run
        return json.dumps(data, default=str).encode()
