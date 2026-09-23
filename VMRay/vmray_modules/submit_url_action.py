"""SubmitUrl — POST /sample/submit with sample_url. Fire-and-forget."""

from vmray_modules.base import VMRayAction
from vmray_modules.models import SubmitResults, SubmitUrlArguments
from vmray_modules.submit_helpers import parse_submit_response


class SubmitUrl(VMRayAction):
    name = "Submit URL"
    description = "Submit a URL to VMRay for detonation without waiting for the result."
    results_model = SubmitResults

    def run(self, arguments: SubmitUrlArguments) -> SubmitResults:
        response = self.client.submit_url(
            sample_url=arguments.sample_url,
            tags=arguments.tags,
            reanalyze=arguments.reanalyze,
            analysis_caching=arguments.analysis_caching,
        )
        return parse_submit_response(response)
