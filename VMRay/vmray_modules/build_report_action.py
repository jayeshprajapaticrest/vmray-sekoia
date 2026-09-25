"""BuildReport — the Cortex-Analyzers VMRay analyzer's `_build_report`.

Takes samples (e.g. from GetSamplesByHash) or submissions (e.g. from
SubmitUrlSample), fetches every sample again — lookup and submit responses are
incomplete — and attaches, per sample, the same sub-resources as the analyzer's
`_build_sample_node`: analyses of the latest submission, VTIs, MITRE ATT&CK,
IOCs, classifications and threat names, then recurses into child samples down
to `max_recursion_depth`.

Deliberately left out versus the analyzer: screenshots (Sekoia alerts cannot
show them) and sample-file downloads. Unlike the analyzer, one failing call
does not abort the report: it lands in that sample's `errors` and every other
section is still filled.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClient, VMRayClientError
from vmray_modules.models import BuildReportArguments, BuildReportResults

_MAX_WORKERS = 4


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
        "Build the full VMRay report for samples or submissions: analyses, VTIs, MITRE ATT&CK, IOCs, "
        "classifications and threat names per sample, including child samples."
    )
    results_model = BuildReportResults

    def run(self, arguments: BuildReportArguments) -> BuildReportResults:
        if arguments.samples:
            sample_ids = [s.get("sample_id") for s in arguments.samples]
        elif arguments.submissions:
            sample_ids = [s.get("submission_sample_id") for s in arguments.submissions]
        else:
            raise MissingActionArgumentError("samples or submissions")

        samples: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        for sample_id in dict.fromkeys(i for i in sample_ids if i is not None):
            try:
                sample = self.client.get_sample(sample_id)
            except VMRayClientError as exc:
                errors[str(sample_id)] = str(exc)
                continue
            build_sample_node(self.client, sample, 0, arguments)
            samples.append(sample)

        return BuildReportResults.model_validate({"samples": samples, "errors": errors})
