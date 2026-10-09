"""SubmitUrlSample — POST /sample/submit with a URL, then poll every resulting
submission until it finishes.

Follows the Cortex-Analyzers VMRay analyzer: `submit_url_sample`, then
`_wait_for_results`, which polls ALL submissions in the submit response through
`update_submission` until each reports `submission_finished`, sleeping
`query_retry_wait` between rounds. One difference: the reference waits forever;
this stops at `timeout` and reports what is still pending.

Returns the finished submissions, their submission_ids and sample_ids. Building
the full report (VTIs, IOCs, MITRE ATT&CK) is a separate action that takes
either list of IDs.
"""

import time
from typing import Any

from pydantic import ValidationError

from vmray_modules.base import VMRayAction
from vmray_modules.client import VMRayClientError
from vmray_modules.models import Submission, SubmitUrlSampleArguments, SubmitUrlSampleResults
from vmray_modules.submit_helpers import submission_params

_MAX_POLL_FAILURES = 3  # consecutive failed polls of one submission before it is given up


class SubmitUrlSample(VMRayAction):
    name = "Submit URL sample"
    description = "Submit a URL to VMRay, wait until every resulting submission has finished, and return them."
    results_model = SubmitUrlSampleResults

    def run(self, arguments: SubmitUrlSampleArguments) -> SubmitUrlSampleResults:
        try:
            response = self.client.submit_url_sample(
                sample_url=arguments.sample_url,
                tags=arguments.tags,
                reanalyze=arguments.reanalyze,
                **submission_params(arguments),
            )
        except VMRayClientError as exc:  # e.g. an invalid URL or no quota left, refused with an HTTP error
            self.set_output("submission_failed", True)
            return SubmitUrlSampleResults(errors=[{"error_msg": str(exc)}])

        errors: list[dict[str, Any]] = [e for e in response.get("errors") or [] if isinstance(e, dict)]
        pending = list(
            dict.fromkeys(
                s["submission_id"]
                for s in response.get("submissions") or []
                if isinstance(s, dict) and s.get("submission_id") is not None
            )
        )

        if not pending:
            # a 200 with no submission means VMRay rejected it — the reason is in `errors`
            self.set_output("submission_failed", True)
            return SubmitUrlSampleResults(errors=errors)

        finished: list[Submission] = []
        failed: list[int] = []
        poll_failures: dict[int, int] = {}
        deadline = time.monotonic() + arguments.timeout
        while pending:
            still_pending = []
            for submission_id in pending:
                try:
                    updated = Submission.model_validate(self.client.update_submission(submission_id))
                except (VMRayClientError, ValidationError) as exc:
                    # one failed poll in a wait of up to 30 minutes must not lose the run — retry a few times
                    poll_failures[submission_id] = poll_failures.get(submission_id, 0) + 1
                    if poll_failures[submission_id] < _MAX_POLL_FAILURES:
                        still_pending.append(submission_id)
                    else:
                        failed.append(submission_id)
                        errors.append({"submission_id": submission_id, "error_msg": f"could not be followed: {exc}"})
                    continue
                poll_failures.pop(submission_id, None)
                if not updated.submission_finished:
                    still_pending.append(submission_id)
                elif updated.submission_has_errors:
                    failed.append(submission_id)
                    errors.append({"submission_id": submission_id, "error_msg": "VMRay finished it with an error"})
                else:
                    finished.append(updated)
            pending = still_pending

            remaining = deadline - time.monotonic()
            if not pending or remaining <= 0:
                break
            time.sleep(max(0.0, min(arguments.query_retry_wait, remaining)))

        sample_ids = list(
            dict.fromkeys(s.submission_sample_id for s in finished if s.submission_sample_id is not None)
        )
        timed_out = bool(pending)
        if timed_out:
            self.set_output("timed_out", True)
        elif finished:
            self.set_output("completed", True)
        else:  # every submission finished with an error
            self.set_output("submission_failed", True)
        return SubmitUrlSampleResults(
            submissions=finished,
            submission_ids=[s.submission_id for s in finished],
            sample_ids=sample_ids,
            pending_submission_ids=pending,
            failed_submission_ids=failed,
            timed_out=timed_out,
            errors=errors,
        )
