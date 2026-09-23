"""SearchSample — GET /sample/{sha256|sha1|md5}/{hash}.

Zero quota, sub-second. The first node in both playbook templates (design
doc): most Sekoia alerts carry a hash, and a cache hit here answers most of
an enrichment without spending a detonation. Explicit found/not-found output
via `set_output`, not a raised exception — a miss is an expected, common
outcome here, not an error.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.models import AnalysisDetails, SearchSampleArguments, SearchSampleResults


class SearchSample(VMRayAction):
    """Look up a sample by hash without spending a detonation."""

    name = "Search sample by hash"
    description = "Look up a previously analysed VMRay sample by SHA256, SHA1 or MD5 — costs no quota."
    results_model = SearchSampleResults

    def run(self, arguments: SearchSampleArguments) -> SearchSampleResults:
        matches = self.client.get_sample_by_hash(arguments.hash)

        if not matches:
            self.set_output("not_found", True)
            return SearchSampleResults(found=False)

        self.set_output("found", True)
        return SearchSampleResults(found=True, analysis=AnalysisDetails.model_validate(matches[0]))
