"""SubmitFile — POST /sample/submit with sample_file, read from data_path.

Fire-and-forget, matching Glimps' convention: reads the file directly off
data_path with no defensive existence check — a missing file here means an
upstream node failed to write it, a wiring bug worth a real traceback via
Action.execute()'s generic error handling, not a quiet branch outcome.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.models import SubmitFileArguments, SubmitResults
from vmray_modules.submit_helpers import parse_submit_response, submission_params


class SubmitFile(VMRayAction):
    name = "Submit file"
    description = "Submit a file, already staged on the playbook's shared storage, to VMRay for detonation."
    results_model = SubmitResults

    def run(self, arguments: SubmitFileArguments) -> SubmitResults:
        file_path = self.data_path.joinpath(arguments.file_name)
        response = self.client.submit_file(
            file_path=str(file_path),
            file_name=arguments.file_name,
            tags=arguments.tags,
            reanalyze=arguments.reanalyze,
            analysis_caching=arguments.analysis_caching,
            **submission_params(arguments),
        )
        return parse_submit_response(response)
