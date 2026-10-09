"""ExtractIocs — pure transform: a BuildReport result -> Sekoia's flat, typed
indicator list for add_ioc_to_ioc_collection, plus the same list grouped by type
(`indicator_groups`): that action takes one indicator_type per call, so a
playbook pushes every type with one Foreach over the groups.

Walks every sample and (by default) its child samples, like the Cortex-Analyzers
VMRay analyzer's artifacts. Each IOC is judged on its own severity: only IOCs in
`ioc_severity_filter` (default: malicious) are extracted. Child samples also add
their own SHA256 — a dropped or downloaded payload — when their verdict passes
the same filter. No VMRay or Sekoia call.
"""

import ipaddress
import re
from collections.abc import Iterator
from email.utils import parseaddr
from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.models import Indicator, IOCSet
from vmray_modules.report_models import ExtractIocsArguments, ExtractIocsResults, IndicatorGroup

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


_HEX_HASH = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
_URL = re.compile(r"[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_DOMAIN = re.compile(r"[^\s/@:]+\.[^\s/@:]+")


def normalise(indicator_type: str, value: str) -> str | None:
    """The value as Sekoia's IOC collection expects it, or None when it is not a valid indicator of that type —
    Add IOC to IOC Collection fails the whole push on one invalid IP, so every value is checked here."""
    value = value.strip()
    if not value:
        return None
    if indicator_type == "IP address":  # a plain address: no port, no CIDR range
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if indicator_type == "domain":
        value = value.lower().rstrip(".")
        return value if _DOMAIN.fullmatch(value) else None
    if indicator_type == "url":
        return value if _URL.fullmatch(value) else None
    if indicator_type == "email":  # a sender can be "Name <address>"
        address = parseaddr(value)[1]
        return address if "@" in address and " " not in address else None
    if indicator_type == "hash":
        value = value.lower()
        return value if _HEX_HASH.fullmatch(value) else None
    return None


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

    def add(indicator_type: str, raw: str | None) -> None:
        value = normalise(indicator_type, raw) if raw is not None else None
        if value is not None and (indicator_type, value) not in seen:
            seen.add((indicator_type, value))
            indicators.append(Indicator(value=value, type=indicator_type))

    for category, (indicator_type, candidate_keys) in _CATEGORY_MAP.items():
        for item in getattr(iocs, category):
            add(indicator_type, _extract_value(item, candidate_keys))

    for item in iocs.files:
        for value in _extract_hashes(item):
            add("hash", value)

    return indicators


_MAX_DEPTH = 10  # Build report's own limit on child-sample levels


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _walk(samples: Any, include_children: bool, level: int = 0) -> Iterator[tuple[dict, int]]:
    for sample in _dicts(samples):
        yield sample, level
        if include_children and level < _MAX_DEPTH:
            yield from _walk(sample.get("sample_child_samples"), include_children, level + 1)


_IOC_SEVERITIES = ("malicious", "suspicious")


def _severities(values: list[str]) -> set[str]:
    """The analyzer's rule: values other than malicious/suspicious are ignored; none left = no filter."""
    return {v.strip().lower() for v in values if v and v.strip().lower() in _IOC_SEVERITIES}


def _passes(severity: Any, wanted: set[str]) -> bool:
    return not wanted or str(severity or "").lower() in wanted


def extract_iocs(report: dict[str, Any], ioc_severity_filter: list[str], include_child_iocs: bool) -> list[Indicator]:
    wanted = _severities(ioc_severity_filter)
    if any(v and v.strip() for v in ioc_severity_filter) and not wanted:
        # a typo such as "malicous" must not turn into "no filter": that would push clean IOCs to blocklists
        raise ValueError(
            f"ioc_severity_filter has no valid value: {ioc_severity_filter!r} — use 'malicious' and/or 'suspicious'"
        )
    seen: set[tuple[str, str]] = set()
    indicators: list[Indicator] = []

    def add(indicator: Indicator) -> None:
        key = (indicator.type, indicator.value)
        if key not in seen:
            seen.add(key)
            indicators.append(indicator)

    for sample, level in _walk(report.get("samples"), include_child_iocs):
        sample_iocs = sample.get("sample_iocs")
        iocs = sample_iocs.get("iocs") if isinstance(sample_iocs, dict) else None
        kept = {
            category: [item for item in _dicts(items) if _passes(item.get("severity") or item.get("verdict"), wanted)]
            for category, items in (iocs.items() if isinstance(iocs, dict) else [])
        }
        for indicator in iocs_to_indicators(IOCSet.model_validate(kept)):
            add(indicator)
        child_hash = normalise("hash", str(sample.get("sample_sha256hash") or ""))
        if level > 0 and child_hash and _passes(sample.get("sample_verdict"), wanted):
            add(Indicator(value=child_hash, type="hash"))

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


class ExtractIocs(VMRayAction):
    name = "Extract IOCs"
    description = (
        "Extract the IOCs of a Build report as the typed indicators Add IOC to IOC Collection expects, also grouped "
        "by type — malicious IOCs only by default, child samples included."
    )
    results_model = ExtractIocsResults

    def run(self, arguments: ExtractIocsArguments) -> ExtractIocsResults:
        report = self.load_report(arguments)
        indicators = extract_iocs(report, arguments.ioc_severity_filter, arguments.include_child_iocs)
        return ExtractIocsResults(indicators=indicators, indicator_groups=group_indicators(indicators))
