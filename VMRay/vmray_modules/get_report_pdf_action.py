"""GetReportPdf — GET /sample/{id}/report.

Written to data_path, ready for a handoff node — e.g. Sekoia.io's
post-reports/pdf, or a downstream TheHive/email/object-storage action.
See the design doc's attachment-gap discussion: there is no way to attach
this directly to a Sekoia alert or case.
"""

import uuid

from vmray_modules.base import VMRayAction
from vmray_modules.models import GetReportPdfArguments, GetReportPdfResults


class GetReportPdf(VMRayAction):
    name = "Download PDF report"
    description = "Download the VMRay PDF report for a sample and write it to the playbook's shared storage."
    results_model = GetReportPdfResults

    def run(self, arguments: GetReportPdfArguments) -> GetReportPdfResults:
        content = self.client.get_sample_report(arguments.sample_id)

        filename = f"vmray-report-{arguments.sample_id}-{uuid.uuid4()}.pdf"
        self.data_path.joinpath(filename).write_bytes(content)

        return GetReportPdfResults(file_path=filename)
