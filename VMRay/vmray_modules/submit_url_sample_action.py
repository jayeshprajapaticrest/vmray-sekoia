"""SubmitUrlSample — POST /sample/submit with a URL, then poll every resulting
submission until it finishes.

Follows the Cortex-Analyzers VMRay analyzer: `submit_url_sample`, then
`_wait_for_results`, which polls ALL submissions in the submit response through
`update_submission` until each reports `submission_finished`, sleeping
`query_retry_wait` between rounds. One difference: the reference waits forever;
this stops at `timeout` and reports what is still pending.

Returns the finished submissions and their sample_ids. Building the full report
(VTIs, IOCs, MITRE ATT&CK) is a separate action that takes those sample_ids.
"""

import time

from vmray_modules.base import VMRayAction
from vmray_modules.models import Submission, SubmitUrlSampleArguments, SubmitUrlSampleResults
from vmray_modules.submit_helpers import submission_params


class SubmitUrlSample(VMRayAction):
    name = "Submit URL sample"
    description = "Submit a URL to VMRay, wait until every resulting submission has finished, and return them."
    results_model = SubmitUrlSampleResults

    def run(self, arguments: SubmitUrlSampleArguments) -> SubmitUrlSampleResults:
        response = self.client.submit_url_sample(
            sample_url=arguments.sample_url,
            tags=arguments.tags,
            reanalyze=arguments.reanalyze,
            **submission_params(arguments),
        )
        errors = response.get("errors") or []
        pending = [s["submission_id"] for s in response.get("submissions") or []]

        if not pending:
            # a 200 with no submission means VMRay rejected it — the reason is in `errors`
            self.set_output("submission_failed", True)
            return SubmitUrlSampleResults(errors=errors)

        finished: list[Submission] = []
        deadline = time.monotonic() + arguments.timeout
        while pending:
            still_pending = []
            for submission_id in pending:
                updated = self.client.update_submission(submission_id)
                if updated.get("submission_finished"):
                    finished.append(Submission.model_validate(updated))
                else:
                    still_pending.append(submission_id)
            pending = still_pending

            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                break
            time.sleep(min(arguments.query_retry_wait, remaining))

        sample_ids = list(
            dict.fromkeys(s.submission_sample_id for s in finished if s.submission_sample_id is not None)
        )
        timed_out = bool(pending)
        self.set_output("timed_out" if timed_out else "completed", True)
        return SubmitUrlSampleResults(
            submissions=finished,
            sample_ids=sample_ids,
            pending_submission_ids=pending,
            timed_out=timed_out,
            errors=errors,
        )
