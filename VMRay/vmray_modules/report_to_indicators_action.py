"""ReportToIndicators — pure transform: a BuildReport result -> Sekoia's flat,
typed indicator list for add_ioc_to_ioc_collection, plus the same list grouped
by type (`indicator_groups`): that action takes one indicator_type per call, so
a playbook pushes every type with one Foreach over the groups.

Walks every sample and (by default) its child samples. Each sample is judged
on its own verdict: only samples in `verdicts` (default: malicious) contribute,
which enforces the IOC-collection policy even when one report mixes a
malicious parent with clean children. Child samples also add their own SHA256
— a dropped or downloaded payload. No VMRay or Sekoia call.
"""

from collections.abc import Iterator
from typing import Any

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.models import Indicator, IOCSet
from vmray_modules.report_models import IndicatorGroup, ReportToIndicatorsArguments, ReportToIndicatorsResults

# category -> (Sekoia indicator_type, candidate value keys, tried in order)
_CATEGORY_MAP: dict[str, tuple[str, tuple[str, ...]]] = {
    "ips": ("IP address", ("ip_address", "ip", "value")),
    "domains": ("domain", ("domain", "value")),
    "urls": ("url", ("url", "value")),
    "email_addresses": ("email", ("email_address", "email", "value")),
    "emails": ("email", ("sender", "email_address", "email", "value")),
}

# `files` gets its own handling: a file IOC carries `hashes`, a list of
# {md5_hash, sha1_hash, sha256_hash, ...} — one entry per file content seen.
# Each entry contributes its strongest hash, as the Cortex analyzer does.
_HASH_PRIORITY = ("sha256_hash", "sha1_hash", "md5_hash")


def _extract_value(item: dict[str, Any], candidate_keys: tuple[str, ...]) -> str | None:
    for key in candidate_keys:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _extract_hashes(item: dict[str, Any]) -> list[str]:
    values = []
    for entry in item.get("hashes") or []:
        if not isinstance(entry, dict):
            continue
        value = _extract_value(entry, _HASH_PRIORITY)
        if value is not None:
            values.append(value)
    return values


def iocs_to_indicators(iocs: IOCSet) -> list[Indicator]:
    seen: set[tuple[str, str]] = set()
    indicators: list[Indicator] = []

    for category, (indicator_type, candidate_keys) in _CATEGORY_MAP.items():
        for item in getattr(iocs, category):
            value = _extract_value(item, candidate_keys)
            if value is None or (indicator_type, value) in seen:
                continue
            seen.add((indicator_type, value))
            indicators.append(Indicator(value=value, type=indicator_type))

    for item in iocs.files:
        for value in _extract_hashes(item):
            if ("hash", value) in seen:
                continue
            seen.add(("hash", value))
            indicators.append(Indicator(value=value, type="hash"))

    return indicators


def _walk(samples: list[dict[str, Any]], include_children: bool, level: int = 0) -> Iterator[tuple[dict, int]]:
    for sample in samples:
        yield sample, level
        if include_children:
            yield from _walk(sample.get("sample_child_samples") or [], include_children, level + 1)


def report_to_indicators(report: dict[str, Any], verdicts: list[str], include_child_samples: bool) -> list[Indicator]:
    wanted = {v.strip().lower() for v in verdicts if v}
    seen: set[tuple[str, str]] = set()
    indicators: list[Indicator] = []

    def add(indicator: Indicator) -> None:
        key = (indicator.type, indicator.value)
        if key not in seen:
            seen.add(key)
            indicators.append(indicator)

    for sample, level in _walk(report.get("samples") or [], include_child_samples):
        if wanted and (sample.get("sample_verdict") or "").lower() not in wanted:
            continue
        for indicator in iocs_to_indicators(
            IOCSet.model_validate((sample.get("sample_iocs") or {}).get("iocs") or {})
        ):
            add(indicator)
        if level > 0 and sample.get("sample_sha256hash"):
            add(Indicator(value=sample["sample_sha256hash"], type="hash"))

    return indicators


# every indicator_type add_ioc_to_ioc_collection accepts, in push order
_SEKOIA_TYPES = ("hash", "IP address", "domain", "url", "email")


def group_indicators(indicators: list[Indicator]) -> list[IndicatorGroup]:
    """One group per non-empty type, so a Foreach never pushes an empty list."""
    groups = [
        IndicatorGroup(type=indicator_type, indicators=[i.value for i in indicators if i.type == indicator_type])
        for indicator_type in _SEKOIA_TYPES
    ]
    return [group for group in groups if group.indicators]


class ReportToIndicators(VMRayAction):
    name = "Report to indicator list"
    description = (
        "Convert a Build report result into the flat, typed indicator list Sekoia's add_ioc_to_ioc_collection "
        "expects, and the same list grouped by type — from malicious samples only by default, child samples included."
    )
    results_model = ReportToIndicatorsResults

    def run(self, arguments: ReportToIndicatorsArguments) -> ReportToIndicatorsResults:
        if arguments.report is not None:
            report = arguments.report
        elif arguments.report_path:
            report = orjson.loads(self.data_path.joinpath(arguments.report_path).read_bytes())
        else:
            raise MissingActionArgumentError("report")
        indicators = report_to_indicators(report, arguments.verdicts, arguments.include_child_samples)
        return ReportToIndicatorsResults(indicators=indicators, indicator_groups=group_indicators(indicators))
