"""SubmitAndWait — submit (URL or file), poll until finished, return
identifiers + verdict only. The blocking primitive everything else composes
from (design doc, correction 2: a single submit-and-wait action replaces the
originally-drafted two-playbook split).

Verdict-level branching (malicious/suspicious/clean) is deliberately NOT this
action's job — decision #5 routes that through Sekoia's native
`PatchAlert.verdict_uuid`, driven by a playbook Condition node reading
`sample_verdict` directly, matching how the shipped VirusTotal template
branches on `node.X.positives` rather than an action-level verdict output.
This action only sets three STRUCTURAL, mutually exclusive outputs:
`completed`, `timed_out`, `submission_failed` — the same explicit-both-branches
convention `virustotal_detection_outputs` uses (`detected` / `not detected`),
not an implicit default edge.

The actual submit/poll logic lives in submit_helpers.submit_and_wait() so
SubmitAndEnrich can reuse it without duplicating this action's body.
"""

from vmray_modules.base import VMRayAction
from vmray_modules.models import SubmitAndWaitArguments, SubmitAndWaitResults
from vmray_modules.submit_helpers import submit_and_wait


class SubmitAndWait(VMRayAction):
    name = "Submit and wait for result"
    description = "Submit a URL or file to VMRay and block until the analysis finishes, returning verdict only."
    results_model = SubmitAndWaitResults

    def run(self, arguments: SubmitAndWaitArguments) -> SubmitAndWaitResults:
        result = submit_and_wait(self.client, self.data_path, arguments)

        if result.submission_id is None:
            self.set_output("submission_failed", True)
        elif result.timed_out:
            self.set_output("timed_out", True)
        else:
            self.set_output("completed", True)

        return result
