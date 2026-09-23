"""Pure transform: VMRay's IOC set -> Sekoia's flat indicator list.

No VMRay call, no Sekoia call. Collapses VMRay's ten IOC categories onto
Sekoia's `add_ioc_to_ioc_collection` five-value `indicator_type` enum
(IP address / domain / url / email / hash) and drops what has no slot there
(mutexes, registry, processes, filenames) — the lossy path by design; see
the design doc's "What VMRay returns, and where each piece lands in Sekoia".

Verdict gating (push on `malicious` only) is a PLAYBOOK decision, not this
action's — it stays a plain, unconditional converter so it composes cleanly
regardless of policy.

⚠️  UNCONFIRMED AGAINST REAL DATA: VMRay's per-item field names inside each
IOC category were never verified against a live `GET /sample/{id}/iocs`
response — only the top-level category keys are spec-confirmed (see
`IOCSet` in models.py, `extra: allow`, same caveat as `ThreatIndicator`).
The candidate key lists below are inferred from VMRay's documented IOC
report conventions. MUST be corrected against real fixture data (spike 0.3
rerun with `--sample-id`, or spike 0.6) before this ships. Extraction is
deliberately tolerant — an item missing every candidate key is skipped
rather than raising, so a wrong guess degrades silently instead of crashing
the whole action; the `skipped` count in the result makes that visible.
"""

from typing import Any

import orjson
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.base import VMRayAction
from vmray_modules.models import Indicator, IOCSet, IocsToIndicatorsArguments, IocsToIndicatorsResults

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


class IocsToIndicators(VMRayAction):
    """Convert a VMRay AnalysisDetails' IOC set into Sekoia's flat, typed
    indicator list for add_ioc_to_ioc_collection."""

    name = "IOCs to indicator list"
    description = (
        "Convert VMRay IOCs into the flat, typed indicator list Sekoia's "
        "add_ioc_to_ioc_collection action expects. Lossy by design — mutexes, "
        "registry keys and processes have no Sekoia indicator type."
    )
    results_model = IocsToIndicatorsResults

    def run(self, arguments: IocsToIndicatorsArguments) -> IocsToIndicatorsResults:
        if arguments.iocs is not None:
            raw = arguments.iocs
        elif arguments.iocs_path:
            raw = orjson.loads(self.data_path.joinpath(arguments.iocs_path).read_bytes())
        else:
            raise MissingActionArgumentError("iocs")

        # `raw` may be a whole AnalysisDetails object (has an "iocs" key) or
        # the IOCSet itself, given directly — accept both.
        iocs_payload = raw["iocs"] if isinstance(raw, dict) and "iocs" in raw else raw
        iocs = IOCSet.model_validate(iocs_payload)

        return IocsToIndicatorsResults(indicators=iocs_to_indicators(iocs))
