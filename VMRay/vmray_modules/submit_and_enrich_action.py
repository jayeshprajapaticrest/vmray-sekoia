"""SubmitAndEnrich — SubmitAndWait + GetAnalysisDetails composed in one node.

The action most playbooks will actually use (design doc). Reuses both
stages' extracted core functions rather than duplicating their logic; see
submit_helpers.submit_and_wait and get_analysis_details_action.fetch_analysis_details.

Same three structural outputs as SubmitAndWait — `completed`, `timed_out`,
`submission_failed` — GetAnalysisDetails' own partial failures land in
`analysis.errors`, not a fourth top-level output, matching the "partial
failure is a first-class case" rule: a comment with 4 of 6 sections beats
nothing, but the submission itself either happened or it didn't.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.get_analysis_details_action import fetch_analysis_details
from vmray_modules.models import SubmitAndEnrichArguments, SubmitAndEnrichResults
from vmray_modules.submit_helpers import submit_and_wait


class SubmitAndEnrich(VMRayAction):
    name = "Submit and enrich"
    description = "Submit a URL or file, wait for the result, and fetch VTIs/IOCs/MITRE ATT&CK in one node."
    results_model = SubmitAndEnrichResults

    def run(self, arguments: SubmitAndEnrichArguments) -> SubmitAndEnrichResults:
        submitted = submit_and_wait(self.client, self.data_path, arguments)

        if submitted.submission_id is None:
            self.set_output("submission_failed", True)
            return SubmitAndEnrichResults(submission_errors=submitted.errors)

        if submitted.timed_out:
            self.set_output("timed_out", True)
            return SubmitAndEnrichResults(
                submission_id=submitted.submission_id,
                sample_id=submitted.sample_id,
                timed_out=True,
                submission_errors=submitted.errors,
            )

        if submitted.sample_id is None:
            # Submission finished but VMRay's response never carried a sample_id
            # (empty `samples[]`) — nothing to enrich. Distinct from
            # submission_failed: the detonation itself succeeded.
            self.set_output("sample_id_missing", True)
            return SubmitAndEnrichResults(
                submission_id=submitted.submission_id,
                submission_errors=submitted.errors,
            )

        details = fetch_analysis_details(
            self.client,
            submitted.sample_id,
            include_vtis=arguments.include_vtis,
            include_iocs=arguments.include_iocs,
            include_mitre_attack=arguments.include_mitre_attack,
            include_recursive=arguments.include_recursive,
            include_analyses=arguments.include_analyses,
            ioc_severity_filter=arguments.ioc_severity_filter,
            analysis_verdict_filter=arguments.analysis_verdict_filter,
        )
        self.set_output("completed", True)

        return SubmitAndEnrichResults(
            submission_id=submitted.submission_id,
            sample_id=submitted.sample_id,
            submission_errors=submitted.errors,
            analysis=details,
        )
