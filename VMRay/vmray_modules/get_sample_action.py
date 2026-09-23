"""GetSample — GET /sample/{id}/file.

Returns an ENCRYPTED ZIP, never raw bytes — VMRay's own default password is
"infected" (client.DEFAULT_SAMPLE_FILE_PASSWORD) unless encryption_password
overrides it. Written to data_path so a downstream node (extraction, another
AV engine, TheHive) can pick it up by its relative path.
"""

import uuid

from vmray_modules.base import VMRayAction
from vmray_modules.models import GetSampleArguments, GetSampleResults


class GetSample(VMRayAction):
    name = "Download sample"
    description = (
        "Download a VMRay sample as an encrypted ZIP (default password 'infected' unless overridden) "
        "and write it to the playbook's shared storage."
    )
    results_model = GetSampleResults

    def run(self, arguments: GetSampleArguments) -> GetSampleResults:
        content = self.client.get_sample_file(arguments.sample_id, arguments.encryption_password)

        filename = f"vmray-sample-{arguments.sample_id}-{uuid.uuid4()}.zip"
        self.data_path.joinpath(filename).write_bytes(content)

        return GetSampleResults(file_path=filename)
