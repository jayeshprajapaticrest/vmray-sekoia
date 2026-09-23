"""GetQuota — GET /api_key/quota. Lets a playbook guard before detonating."""

from vmray_modules.base import VMRayAction
from vmray_modules.models import GetQuotaArguments, GetQuotaResults


class GetQuota(VMRayAction):
    name = "Check quota"
    description = "Get this API key's VMRay quota limit and current usage."
    results_model = GetQuotaResults

    def run(self, arguments: GetQuotaArguments) -> GetQuotaResults:  # noqa: ARG002
        quota = self.client.quota()
        return GetQuotaResults(quota_limit=quota["quota_limit"], used_quota=quota["used_quota"])
