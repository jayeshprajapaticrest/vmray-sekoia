from functools import cached_property
from typing import Any

import orjson
from sekoia_automation.action import Action
from sekoia_automation.exceptions import MissingActionArgumentError

from vmray_modules.client import VMRayClient
from vmray_modules.models import VMRayModule
from vmray_modules.report_models import ReportInput


class VMRayAction(Action):
    """Shared base for every VMRay action. Mirrors Glimps/glimps/base.py's
    shape: one cached client, built once per action run from the module
    configuration."""

    module: VMRayModule

    @cached_property
    def client(self) -> VMRayClient:
        config = self.module.configuration
        version = self.module.manifest.get("version", "0.0.0")
        return VMRayClient(
            base_url=config.base_url,
            api_key=config.api_key,
            verify_ssl=config.verify_ssl,
            user_agent_suffix=f"Sekoia/{version}",
        )

    def load_report(self, arguments: ReportInput) -> dict[str, Any]:
        """The Build report result: the file at `report_path`, else the inline `report`. An empty `report` counts
        as not given — Sekoia's playbook editor sends `{}` for an object input left blank, and taking that over
        `report_path` would render and extract an empty report."""
        if arguments.report_path:
            return orjson.loads(self.data_path.joinpath(arguments.report_path).read_bytes())
        if arguments.report:
            return arguments.report
        raise MissingActionArgumentError("report_path")
