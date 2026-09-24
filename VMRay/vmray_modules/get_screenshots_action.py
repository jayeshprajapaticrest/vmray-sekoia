"""GetScreenshots — GET /analysis/{id}/archive/screenshots.

Written to data_path, same handoff pattern as GetSample/GetReportPdf: no
alert/case attachment API exists on Sekoia's side (see the design doc's
attachment-gap discussion), so a downstream node (TheHive's upload_logs,
email, object storage) takes custody of the ZIP.

Screenshots are scoped to one analysis_id, not sample_id — a sample can carry
several analysis runs (different VM profiles), each with its own screenshots.
"""

import uuid

from vmray_modules.base import VMRayAction
from vmray_modules.models import GetScreenshotsArguments, GetScreenshotsResults


class GetScreenshots(VMRayAction):
    name = "Download screenshots"
    description = (
        "Download the screenshots captured during a VMRay analysis run as a ZIP "
        "and write it to the playbook's shared storage."
    )
    results_model = GetScreenshotsResults

    def run(self, arguments: GetScreenshotsArguments) -> GetScreenshotsResults:
        content = self.client.get_analysis_archive(arguments.analysis_id, "screenshots", arguments.encryption_password)

        filename = f"vmray-screenshots-{arguments.analysis_id}-{uuid.uuid4()}.zip"
        self.data_path.joinpath(filename).write_bytes(content)

        return GetScreenshotsResults(file_path=filename)
