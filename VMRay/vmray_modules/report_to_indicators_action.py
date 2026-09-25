"""ReportToIndicators — pure transform: a BuildReport result -> Sekoia's flat,
typed indicator list for add_ioc_to_ioc_collection.

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
from vmray_modules.report_models import ReportToIndicatorsArguments, ReportToIndicatorsResults

# category -> (Sekoia indicator_type, candidate value keys, tried in order)
_CATEGORY_MAP: dict[str, tuple[str, tuple[str, ...]]] = {
    "ips": ("IP address", ("ip_address", "ip", "value")),
    "domains": ("domain", ("domain", "value")),
    "urls": ("url", ("url", "value")),
    "email_addresses": ("email", ("email_address", "email", "value")),
    "emails": ("email", ("sender", "email_address", "email", "value")),
}

# `files` gets its own handling: prefer the strongest hash VMRay reports,
# whether it comes as a flat key or a nested {type, value} / {algo: hash} list.
_HASH_PRIORITY = ("sha256", "sha1", "md5")


def _extract_value(item: dict[str, Any], candidate_keys: tuple[str, ...]) -> str | None:
    for key in candidate_keys:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _extract_hash(item: dict[str, Any]) -> str | None:
    for algo in _HASH_PRIORITY:
        if isinstance(item.get(algo), str) and item[algo]:
            return item[algo]

    hashes = item.get("hashes")
    if isinstance(hashes, dict):
        for algo in _HASH_PRIORITY:
            if isinstance(hashes.get(algo), str) and hashes[algo]:
                return hashes[algo]
    elif isinstance(hashes, list):
        by_algo = {
            h.get("type", "").lower(): h.get("value")
            for h in hashes
            if isinstance(h, dict) and isinstance(h.get("value"), str)
        }
        for algo in _HASH_PRIORITY:
            if by_algo.get(algo):
                return by_algo[algo]

    return None


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
        value = _extract_hash(item)
        if value is None or ("hash", value) in seen:
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


class ReportToIndicators(VMRayAction):
    name = "Report to indicator list"
    description = (
        "Convert a Build report result into the flat, typed indicator list Sekoia's add_ioc_to_ioc_collection "
        "expects — from malicious samples only by default, child samples included."
    )
    results_model = ReportToIndicatorsResults

    def run(self, arguments: ReportToIndicatorsArguments) -> ReportToIndicatorsResults:
        if arguments.report is not None:
            report = arguments.report
        elif arguments.report_path:
            report = orjson.loads(self.data_path.joinpath(arguments.report_path).read_bytes())
        else:
            raise MissingActionArgumentError("report")
        return ReportToIndicatorsResults(
            indicators=report_to_indicators(report, arguments.verdicts, arguments.include_child_samples)
        )
