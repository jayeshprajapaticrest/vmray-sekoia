"""GetAnalysisDetails — the fan-out aggregator.

GET /sample/{id} first (required — if this fails, nothing meaningful can be
built, so it's allowed to raise normally). Everything else — /vtis, /iocs,
/mitre_attack, and the two recursive-children calls — runs CONCURRENTLY
(decided: 30-minute detonation budget makes the fan-out itself noise either
way; concurrency mainly matters on the SearchSample cache-hit path) and
degrades independently: one section failing lands in `errors`, the rest of
the object still comes back populated (design doc, "partial failure is a
first-class case").

`children_threat_names`/`children_classifications` shapes ({"threat_name":
...} / {"classification_name": ...}) are production-verified against a real
shipped analyzer (Cortex-Analyzers' VMRay client), not inferred from the spec
alone — the spec confirms the endpoints exist but not their item shape.

The core logic is a free function, `fetch_analysis_details`, so
SubmitAndEnrich can reuse it without duplicating this action's body.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClient
from vmray_modules.models import (
    AnalysisDetails,
    AnalysisRun,
    GetAnalysisDetailsArguments,
    IOCSet,
    MitreAttackTechnique,
    SampleChildRelation,
    ThreatIndicator,
)

_MAX_WORKERS = 4  # one per possible fan-out call — decided concurrency cap


def _run_concurrently(tasks: dict[str, Callable[[], Any]]) -> tuple[dict[str, Any], dict[str, str]]:
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}

    if not tasks:
        return results, errors

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_to_name = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                errors[name] = str(exc)

    return results, errors


def _merge(details: AnalysisDetails, results: dict[str, Any]) -> None:
    if "vtis" in results:
        indicators = results["vtis"].get("threat_indicators", [])
        details.threat_indicators = [ThreatIndicator.model_validate(i) for i in indicators]

    if "iocs" in results:
        details.iocs = IOCSet.model_validate(results["iocs"].get("iocs", {}))

    if "mitre_attack" in results:
        techniques = results["mitre_attack"].get("mitre_attack_techniques", [])
        details.mitre_attack_techniques = [MitreAttackTechnique.model_validate(t) for t in techniques]

    if "threat_names" in results:
        children = results["threat_names"].get("children_threat_names", [])
        extra = {t["threat_name"] for t in children if t.get("threat_name")}
        details.sample_threat_names = sorted(set(details.sample_threat_names) | extra)

    if "classifications" in results:
        children = results["classifications"].get("children_classifications", [])
        extra = {c["classification_name"] for c in children if c.get("classification_name")}
        details.sample_classifications = sorted(set(details.sample_classifications) | extra)

    if "relations" in results:
        # Fallback only used when sample_child_relations_truncated was true —
        # the base object's own list is preferred and already on `details`.
        details.sample_child_relations = [SampleChildRelation.model_validate(r) for r in results["relations"]]

    if "analyses" in results:
        details.sample_analyses = [AnalysisRun.model_validate(a) for a in results["analyses"]]


def fetch_analysis_details(
    client: VMRayClient,
    sample_id: int,
    include_vtis: bool = True,
    include_iocs: bool = True,
    include_mitre_attack: bool = True,
    include_recursive: bool = False,
    include_analyses: bool = False,
    ioc_severity_filter: str | None = None,
    analysis_verdict_filter: list[str] | None = None,
) -> AnalysisDetails:
    base = client.get_sample(sample_id)
    details = AnalysisDetails.model_validate(base)

    tasks: dict[str, Callable[[], Any]] = {}
    if include_vtis:
        tasks["vtis"] = lambda: client.get_sample_vtis(sample_id)
    if include_iocs:
        tasks["iocs"] = lambda: client.get_sample_iocs(sample_id, ioc_severity=ioc_severity_filter)
    if include_mitre_attack:
        tasks["mitre_attack"] = lambda: client.get_sample_mitre_attack(sample_id)
    if include_recursive:
        tasks["threat_names"] = lambda: client.get_sample_threat_names(sample_id)
        tasks["classifications"] = lambda: client.get_sample_classifications(sample_id)
    if include_analyses:
        tasks["analyses"] = lambda: client.get_sample_analyses(sample_id)
    if details.sample_child_relations_truncated:
        tasks["relations"] = lambda: client.get_sample_relations(sample_id)

    results, errors = _run_concurrently(tasks)
    _merge(details, results)
    details.errors = errors

    if analysis_verdict_filter:
        wanted = {v.strip().lower() for v in analysis_verdict_filter if v}
        details.sample_analyses = [
            run for run in details.sample_analyses if (run.analysis_verdict or "").lower() in wanted
        ]

    return details


class GetAnalysisDetails(VMRayAction):
    name = "Get analysis details"
    description = (
        "Fetch VTIs, IOCs and MITRE ATT&CK for a VMRay sample, run concurrently, "
        "assembled into one AnalysisDetails object. Failing sections are reported "
        "in `errors` rather than aborting the whole action."
    )
    results_model = AnalysisDetails

    def run(self, arguments: GetAnalysisDetailsArguments) -> AnalysisDetails:
        return fetch_analysis_details(
            self.client,
            arguments.sample_id,
            include_vtis=arguments.include_vtis,
            include_iocs=arguments.include_iocs,
            include_mitre_attack=arguments.include_mitre_attack,
            include_recursive=arguments.include_recursive,
            include_analyses=arguments.include_analyses,
            ioc_severity_filter=arguments.ioc_severity_filter,
            analysis_verdict_filter=arguments.analysis_verdict_filter,
        )
