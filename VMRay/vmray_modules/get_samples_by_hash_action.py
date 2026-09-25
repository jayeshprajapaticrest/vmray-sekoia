"""GetSamplesByHash — GET /sample/{sha256|sha1|md5}/{hash} for a list of hashes.

Mirrors the Cortex-Analyzers VMRay client's `get_samples_by_hash`: every sample
matching a hash comes back, not just the first. Runs over a list because an
alert's events usually carry several hashes and each lookup is free.

Lookup only — building the full report (VTIs, IOCs, MITRE ATT&CK) is a separate
action that takes the returned sample_ids. Zero quota. Partial failure is per
hash: a bad or failing hash lands in `errors` and the rest are still checked.
"""

from typing import Any

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClientError
from vmray_modules.models import GetSamplesByHashArguments, GetSamplesByHashResults


class GetSamplesByHash(VMRayAction):
    name = "Get samples by hash"
    description = (
        "Look up SHA256/SHA1/MD5 hashes in VMRay's existing analyses and return every matching sample — "
        "costs no quota."
    )
    results_model = GetSamplesByHashResults

    def run(self, arguments: GetSamplesByHashArguments) -> GetSamplesByHashResults:
        distinct = dict.fromkeys(h.strip().lower() for h in arguments.hashes if h and h.strip())

        samples: dict[int, dict[str, Any]] = {}
        not_found: list[str] = []
        errors: dict[str, str] = {}

        for sample_hash in distinct:
            try:
                matches = self.client.get_samples_by_hash(sample_hash)
            except VMRayClientError as exc:
                errors[sample_hash] = str(exc)
                continue
            if not matches:
                not_found.append(sample_hash)
            # md5/sha1/sha256 of one file resolve to the same sample — keep it once
            for match in matches:
                samples.setdefault(match["sample_id"], match)

        found = bool(samples)
        self.set_output("found" if found else "not_found", True)
        return GetSamplesByHashResults(
            found=found,
            sample_ids=list(samples),
            samples=list(samples.values()),
            not_found=not_found,
            errors=errors,
        )
